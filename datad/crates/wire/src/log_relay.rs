//! A bounded single-producer/single-consumer ring of *rendered console lines*,
//! handed from the domain that can read every log ring to the domain that can
//! write the medium.
//!
//! Faces the byzantine neighbour protection domain from both sides, exactly as
//! [`LogRecords`](crate::LogRecords) does. The console domain owns
//! [`LogRelay`] and the recorder domain owns [`LogRelayConsume`], each reads
//! the other's, and neither may assume the other wrote anything a correct
//! implementation would. Nothing here judges a line: a line is bytes, every bit
//! pattern of a byte is a byte, and what a *reader* of the recording may do
//! with those bytes is that reader's rule and not this region's.
//!
//! # Why this region exists at all
//!
//! The recorder is the only domain that can write the recording medium and it
//! maps no log ring but its own — widening that would delete the property those
//! eleven pairs of grants exist for. The console domain is the opposite: it maps
//! all eleven read-only, and it already decodes and renders every record. So the
//! transcript travels the way the authority already runs. The console publishes
//! each line it has just printed, and the domain that may write the medium
//! copies it out. One pair of pages replaces eleven read grants on the domain
//! holding a block device and a DMA-capable controller.
//!
//! # Two regions, because a region is the unit of grant
//!
//! [`LogRelay`] holds the slots, the producer cursor and the console's drop
//! count; [`LogRelayConsume`] holds the consumer cursor alone. The split is
//! [`crate::LogRecords`]'s and for its reasons: a recorder mapping one region
//! read-only could not publish how far it had read, which is the console's only
//! flow control, and a recorder mapping it read-write could store into any slot
//! — forging a transcript line that no domain ever printed, into the one
//! recording a management server believes.
//!
//! # A full relay refuses the newest line, and never the console
//!
//! **The console must never be stalled by this region.** It is the appliance's
//! only diagnostic surface, and a console that waits on the recorder is a
//! console that goes quiet exactly when the recorder is the thing that is
//! wrong. So [`LogRelayWriter::publish`] is total and non-blocking: a relay the
//! recorder is not draining costs a counted drop and the console's own write
//! goes to the serial line regardless.
//!
//! Refusing the *newest* rather than the oldest is [`crate::LogRecords`]'s rule
//! and its argument holds here too — dropping the oldest would have the writer
//! advance the reader's cursor, which the split has made impossible, and would
//! let a line be assembled out of two writes.
//!
//! # Why a line and not the record it was rendered from
//!
//! The record is a 264-byte structured value and the grammar that turns one into
//! a line is a large closed vocabulary of this build's. A management server
//! handed records would need a second copy of that grammar in another language,
//! and the two would part without either failing. Handed lines it needs none:
//! the text it stores is the text an operator read on the console, so the two
//! surfaces agree by construction rather than by a comparison nobody runs.
//!
//! # What a torn line is, and what it is not
//!
//! A slot's text is published one word at a time, as [`crate::LogSlot`]'s fields
//! are, so a read concurrent with a write can yield a line whose halves come
//! from two different publishes. The guarantee is exactly this and no more:
//! every byte is always a byte and never undefined behaviour, and the length is
//! always inside the slot. A spliced line is a line no domain printed — the same
//! accepted residue a per-field record publish has, against the same
//! alternative of a sequence word per slot on the path of every line.
//!
//! It is not, however, a residue the *reader* of a recording has to absorb.
//! Every byte a console line may contain is printable ASCII, and a slot the
//! console has not reached is zero, so a reader that insists on that alphabet
//! turns a torn or unwritten line into a refusal it names rather than a string
//! it stores.

use core::{
    mem::size_of,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use crate::MAPPING_ALIGN;
use crate::log_record::LOG_DOMAIN_COUNT;

/// The longest line a slot carries, and so the longest one that crosses.
///
/// Equal to `lfw_log::MAX_LINE_LEN` by construction — the log crate asserts the
/// two agree — because a relay that could not carry the widest line the console
/// grammar renders would drop exactly the refusal lines a recording is read for.
pub const RELAY_LINE_BYTES: usize = 256;

/// Words of text one slot holds. Text is published a word at a time, so the
/// slot is an array of words and not of bytes.
const RELAY_LINE_WORDS: usize = RELAY_LINE_BYTES / size_of::<u64>();

/// Bytes of the region ahead of the first slot: the producer cursor and the
/// writer's drop count.
const RELAY_RING_HEADER_BYTES: usize = 8;

/// Slots one relay region holds, of which [`LogRelay::capacity`] are usable.
///
/// Derived rather than chosen: the region is one page — a page being the
/// smallest grant a mapping can be, and a second page of authority on the domain
/// holding the block device being the thing this whole region exists to avoid —
/// and this is every slot that fits behind the header in it.
///
/// It does not need to be a power of two. A cursor is brought into range with a
/// remainder rather than a mask, which is total for every `u32` there is at the
/// cost of a division on a path that carries a handful of lines a second, and
/// buys every slot the page has room for instead of rounding down to eight.
pub const LOG_RELAY_SLOTS: u32 =
    ((MAPPING_ALIGN - RELAY_RING_HEADER_BYTES) / size_of::<LineSlot>()) as u32;

/// One line in the region: what it is about, when it was said, how long it is,
/// and its bytes.
///
/// Every field is an atomic because both sides of it are separate protection
/// domains running concurrently, and every field is private because the
/// discipline is a property of this type rather than a convention its two
/// domains are asked to keep.
#[repr(C, align(8))]
struct LineSlot {
    /// `origin | flags << 8 | len << 16`, published as one store so those three
    /// cannot come from three different publishes. Reserved bits are zero.
    meta: AtomicU64,
    /// The instant the record was emitted, in nanoseconds since the Unix epoch,
    /// meaningful only where [`FLAG_STAMPED`] is set in `meta`. Zero elsewhere —
    /// and *not* a sentinel for the absence of one, which is what the flag is
    /// for: zero nanoseconds is 1970, an instant a reader would take for a
    /// reading, and the lines emitted before this node establishes a time are
    /// most of a boot transcript.
    unix_nanos: AtomicU64,
    text: [AtomicU64; RELAY_LINE_WORDS],
}

impl LineSlot {
    const fn zero() -> Self {
        Self {
            meta: AtomicU64::new(0),
            unix_nanos: AtomicU64::new(0),
            text: [const { AtomicU64::new(0) }; RELAY_LINE_WORDS],
        }
    }

    /// Store one line. The caller has already bounded `line` to the slot; a
    /// longer one is written as far as the slot reaches and stated as that
    /// length, so no reader is told about bytes that are not there.
    fn store(&self, origin: u8, flags: u8, unix_nanos: u64, line: &[u8]) {
        // The bound and the length are one operation, so the two cannot drift:
        // what is written is exactly what is stated.
        let text = line.get(..RELAY_LINE_BYTES).unwrap_or(line);
        self.unix_nanos.store(unix_nanos, Ordering::Relaxed);
        // Every word is stored, not only the ones the line reaches: a shorter
        // line must never leave a longer one's tail behind for a reader to
        // attribute to it, and the stated length alone would not prevent that,
        // a torn `meta` being able to state the older, longer one.
        let mut at = 0usize;
        for word in &self.text {
            let mut bytes = [0u8; size_of::<u64>()];
            let end = at.saturating_add(bytes.len());
            if let Some(window) = text.get(at..end) {
                bytes.copy_from_slice(window);
            } else if let Some(window) = text.get(at..) {
                // The final, partial word. `window` is shorter than `bytes` by
                // construction, so the copy is bounded by it and the rest of the
                // word stays zero.
                if let Some(head) = bytes.get_mut(..window.len()) {
                    head.copy_from_slice(window);
                }
            }
            word.store(u64::from_le_bytes(bytes), Ordering::Relaxed);
            at = end;
        }
        self.meta.store(
            u64::from(origin) | (u64::from(flags) << 8) | ((text.len() as u64) << 16),
            Ordering::Release,
        );
    }

    /// Load one line into `into`, answering what was read.
    ///
    /// Every field is brought into range here rather than trusted: `meta` is
    /// peer-written, so its length may name bytes past the slot and its origin
    /// may name no protection domain.
    fn load(&self, into: &mut [u8; RELAY_LINE_BYTES]) -> RelayLine {
        let meta = self.meta.load(Ordering::Acquire);
        let mut at = 0usize;
        for word in &self.text {
            let bytes = word.load(Ordering::Relaxed).to_le_bytes();
            if let Some(window) = into.get_mut(at..at.saturating_add(bytes.len())) {
                window.copy_from_slice(&bytes);
            }
            at = at.saturating_add(bytes.len());
        }
        let stated = ((meta >> 16) & 0xffff) as usize;
        RelayLine {
            origin: (meta & 0xff) as u8,
            flags: ((meta >> 8) & 0xff) as u8,
            unix_nanos: self.unix_nanos.load(Ordering::Relaxed),
            len: if stated < RELAY_LINE_BYTES {
                stated
            } else {
                RELAY_LINE_BYTES
            },
        }
    }
}

/// The one flag bit a line carries: its instant is a real one.
///
/// Clear means the emitting domain had no clock, which is a fact a reader
/// carries onward rather than one it repairs — the emitting domain is the only
/// party that knows whether time was established.
pub const FLAG_STAMPED: u8 = 1;

/// Bits of a line's flags this build defines. A reader refuses a line carrying
/// any other, on [`crate::LogRecord::check`]'s terms: the field is peer-written,
/// so an undecodable value is input to reject rather than one to coerce.
pub const RELAY_FLAG_BITS: u8 = FLAG_STAMPED;

/// What one slot held, without its text: the text goes into storage the caller
/// owns, because a slot's worth of it on a `no_std` stack per read is the one
/// copy worth avoiding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayLine {
    /// Which protection domain's ring the line was drained from, as
    /// `lfw_log::Domain`'s discriminant. Bounded by nothing here: it is the
    /// console's own claim, which the recorder passes on and a reader of the
    /// recording bounds against its own vocabulary.
    pub origin: u8,
    /// [`RELAY_FLAG_BITS`] and whatever else a byzantine writer set.
    pub flags: u8,
    /// Nanoseconds since the Unix epoch, meaningful only where [`FLAG_STAMPED`]
    /// is set in `flags`.
    pub unix_nanos: u64,
    /// Bytes of the caller's storage that hold the line, always at most
    /// [`RELAY_LINE_BYTES`].
    pub len: usize,
}

impl RelayLine {
    /// The instant this line was emitted at, or `None` where the emitting domain
    /// had no clock.
    ///
    /// The two facts are one question and a caller should not have to know which
    /// bit answers it, which is what keeps [`FLAG_STAMPED`] out of every reader.
    #[must_use]
    pub const fn stamp(&self) -> Option<u64> {
        if self.flags & FLAG_STAMPED == 0 {
            None
        } else {
            Some(self.unix_nanos)
        }
    }
}

/// The lines half of the relay: the slots, the cursor that publishes them and
/// the console's count of what it refused. The console domain maps this
/// read-write and the recorder domain read-only.
#[repr(C)]
pub struct LogRelay {
    tail: AtomicU32,
    dropped: AtomicU32,
    slots: [LineSlot; LOG_RELAY_SLOTS as usize],
}

impl LogRelay {
    /// A zeroed region, which is what the kernel hands a domain that maps one:
    /// both cursors at zero, which every reader reads as empty.
    ///
    /// A function rather than a `const`, on [`crate::LogRecords::zero`]'s terms:
    /// a `const` holding an atomic is copied at each mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            tail: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            slots: [const { LineSlot::zero() }; LOG_RELAY_SLOTS as usize],
        }
    }

    /// How many lines the relay holds at once. One slot is always left unused,
    /// which tells a full relay from an empty one without a flag.
    #[must_use]
    pub const fn capacity(&self) -> u32 {
        LOG_RELAY_SLOTS - 1
    }

    /// Take the publishing side's handle: this region to write, the recorder's
    /// cursor to read.
    ///
    /// Take it **once** and keep it, on [`crate::LogRecords::writer`]'s terms: a
    /// second restarts at slot zero and overwrites lines the first published.
    #[must_use]
    pub const fn writer<'ring>(
        &'ring self,
        consume: &'ring LogRelayConsume,
    ) -> LogRelayWriter<'ring> {
        LogRelayWriter {
            relay: self,
            consume: PeerRelayConsume::new(consume),
            tail: 0,
            dropped: 0,
        }
    }

    /// The slot a cursor names. Total by construction: the remainder of any
    /// `u32` by [`LOG_RELAY_SLOTS`] is an index of the array, and the assertion
    /// block below holds that count above zero.
    fn slot(&self, at: u32) -> Option<&LineSlot> {
        self.slots.get((at % LOG_RELAY_SLOTS) as usize)
    }
}

impl Default for LogRelay {
    fn default() -> Self {
        Self::zero()
    }
}

/// The consume half of the relay: how far the recorder has read, and nothing
/// else. The recorder domain maps this read-write and the console domain
/// read-only.
///
/// Its own region for [`crate::LogConsume`]'s reason, read the other way round:
/// it is what denies the console the one write that would matter — forging the
/// cursor that says which of its slots it may reuse, and so overwriting a line
/// the recorder has not framed while counting no drop for it.
#[repr(C)]
pub struct LogRelayConsume {
    head: AtomicU32,
}

impl LogRelayConsume {
    /// As [`LogRelay::zero`].
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            head: AtomicU32::new(0),
        }
    }

    /// Take the draining side's handle: this region to write, the console's
    /// lines to read. On [`LogRelay::writer`]'s terms.
    #[must_use]
    pub const fn reader<'ring>(&'ring self, relay: &'ring LogRelay) -> LogRelayReader<'ring> {
        LogRelayReader {
            consume: self,
            relay: PeerRelay::new(relay),
            head: 0,
        }
    }
}

impl Default for LogRelayConsume {
    fn default() -> Self {
        Self::zero()
    }
}

/// Each side's view of the region it reads and may not write, on
/// [`crate::log_ring`]'s terms: the borrow each wraps is private to it, so
/// "neither side writes the other's region" is a fact about the types and not
/// about care taken at each call site.
mod peer {
    use core::sync::atomic::Ordering;

    use super::{
        LOG_RELAY_SLOTS, LineSlot, LogRelay, LogRelayConsume, RELAY_LINE_BYTES, RelayLine,
    };

    /// The lines region as the recorder holds it: loads only.
    pub(super) struct PeerRelay<'ring>(&'ring LogRelay);

    impl<'ring> PeerRelay<'ring> {
        pub(super) const fn new(relay: &'ring LogRelay) -> Self {
            Self(relay)
        }

        /// Brought into range because it is attacker-controlled. Acquire so the
        /// writer's slot stores are visible before this side reads them.
        pub(super) fn tail(&self) -> u32 {
            self.0.tail.load(Ordering::Acquire) % LOG_RELAY_SLOTS
        }

        pub(super) fn dropped(&self) -> u32 {
            self.0.dropped.load(Ordering::Acquire)
        }

        pub(super) fn line(&self, at: u32, into: &mut [u8; RELAY_LINE_BYTES]) -> Option<RelayLine> {
            self.0.slot(at).map(|slot: &LineSlot| slot.load(into))
        }
    }

    /// The consume region as the console holds it, on [`PeerRelay`]'s terms.
    pub(super) struct PeerRelayConsume<'ring>(&'ring LogRelayConsume);

    impl<'ring> PeerRelayConsume<'ring> {
        pub(super) const fn new(consume: &'ring LogRelayConsume) -> Self {
            Self(consume)
        }

        pub(super) fn head(&self) -> u32 {
            self.0.head.load(Ordering::Acquire) % LOG_RELAY_SLOTS
        }
    }
}

use peer::{PeerRelay, PeerRelayConsume};

/// The publishing side, holding the console's position and its own drop count in
/// private memory. Re-reading either out of the shared region would hand the
/// recorder a rewound cursor to overwrite an unframed line with, and a drop
/// count it could walk backwards.
pub struct LogRelayWriter<'ring> {
    relay: &'ring LogRelay,
    consume: PeerRelayConsume<'ring>,
    tail: u32,
    dropped: u32,
}

impl LogRelayWriter<'_> {
    #[must_use]
    pub const fn capacity(&self) -> u32 {
        LOG_RELAY_SLOTS - 1
    }

    /// Publish one line, and answer whether it was taken.
    ///
    /// **Total and non-blocking, which is the whole contract**: it waits on
    /// nothing, it cannot fail in any way a caller must handle, and a relay the
    /// recorder is not draining costs the counted drop below and nothing else.
    /// The console's own write to the serial line does not depend on the answer.
    ///
    /// `line` longer than [`RELAY_LINE_BYTES`] is published as far as the slot
    /// reaches and stated as that length. It is unreachable from first-party
    /// code — the console renders into a buffer of exactly that width — and a
    /// refusal a caller cannot produce would be a branch nothing exercises.
    pub fn publish(&mut self, origin: u8, unix_nanos: Option<u64>, line: &[u8]) -> bool {
        let next = (self.tail.wrapping_add(1)) % LOG_RELAY_SLOTS;
        if next == self.consume.head() {
            self.dropped = self.dropped.saturating_add(1);
            self.relay.dropped.store(self.dropped, Ordering::Release);
            return false;
        }
        let (flags, nanos) = match unix_nanos {
            Some(nanos) => (FLAG_STAMPED, nanos),
            None => (0, 0),
        };
        let Some(slot) = self.relay.slot(self.tail) else {
            // Unreachable: `slot` takes a remainder by the array's own length.
            // A value rather than an assertion, because nothing about a
            // transcript line may fault the domain that renders the transcript.
            return false;
        };
        slot.store(origin, flags, nanos, line);
        self.tail = next;
        self.relay.tail.store(next, Ordering::Release);
        true
    }

    /// Lines this writer has refused for want of a slot, saturating at
    /// [`u32::MAX`] rather than wrapping: a wrap would turn a sustained flood
    /// back into a small number.
    #[must_use]
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }
}

/// The draining side, holding the recorder's position in private memory.
pub struct LogRelayReader<'ring> {
    consume: &'ring LogRelayConsume,
    relay: PeerRelay<'ring>,
    head: u32,
}

impl LogRelayReader<'_> {
    #[must_use]
    pub const fn capacity(&self) -> u32 {
        LOG_RELAY_SLOTS - 1
    }

    /// How many lines are queued *at this instant*, judged against the console's
    /// published cursor.
    ///
    /// That cursor is the console's to forge either way, so this is a number to
    /// bound a batch by and never one to trust: it is at most
    /// [`capacity`](Self::capacity) by construction, and a forged cursor
    /// presents slots that were never published — stale or zero, in bounds,
    /// never out of it. The alphabet check a reader of the recording applies is
    /// what keeps those out of stored text.
    #[must_use]
    pub fn queued(&self) -> u32 {
        (self
            .relay
            .tail()
            .wrapping_add(LOG_RELAY_SLOTS)
            .wrapping_sub(self.head))
            % LOG_RELAY_SLOTS
    }

    /// Read the line `at` places past this reader's position into `into`,
    /// **without consuming it**.
    ///
    /// This is the half of the protocol that lets a batch be composed and then
    /// abandoned. The domain that frames these lines into a recording cannot
    /// know whether a block will be placed until it offers it, and a reader that
    /// consumed first would lose every line of a batch the recording deferred.
    /// So it peeks a batch, offers it, and calls [`consume`](Self::consume) only
    /// once the bytes are placed.
    ///
    /// `None` past what is queued, which is the answer for a caller iterating by
    /// index rather than a fault.
    pub fn peek(&self, at: u32, into: &mut [u8; RELAY_LINE_BYTES]) -> Option<RelayLine> {
        if at >= self.queued() {
            return None;
        }
        self.relay
            .line(self.head.wrapping_add(at) % LOG_RELAY_SLOTS, into)
    }

    /// Release `count` lines, publishing the new position to the console, and
    /// answer how many were released.
    ///
    /// Bounded by what is queued, so a caller that lost count releases slots it
    /// has read and never slots the console has yet to fill.
    pub fn consume(&mut self, count: u32) -> u32 {
        let taken = count.min(self.queued());
        self.head = self.head.wrapping_add(taken) % LOG_RELAY_SLOTS;
        self.consume.head.store(self.head, Ordering::Release);
        taken
    }

    /// Read one line into `into` and consume it, or answer `None` holding none.
    ///
    /// [`peek`](Self::peek) and [`consume`](Self::consume) in one call, for a
    /// caller with nothing to abandon.
    pub fn read(&mut self, into: &mut [u8; RELAY_LINE_BYTES]) -> Option<RelayLine> {
        let line = self.peek(0, into)?;
        self.consume(1);
        Some(line)
    }

    /// What the console says it refused for want of a slot. The console's claim
    /// about itself, so it is a number to pass on and never one to decide under.
    #[must_use]
    pub fn dropped_by_writer(&self) -> u32 {
        self.relay.dropped()
    }
}

/// Bytes the system description reserves for the lines region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const LOG_RELAY_REGION_SIZE: usize = size_of::<LogRelay>().next_multiple_of(MAPPING_ALIGN);

/// As [`LOG_RELAY_REGION_SIZE`]. A page for one word is what a region costs when
/// a region is the unit of grant, and `log_*_consume` spends one for that reason.
pub const LOG_RELAY_CONSUME_REGION_SIZE: usize =
    size_of::<LogRelayConsume>().next_multiple_of(MAPPING_ALIGN);

// Two cross-PD shared-memory ABIs: pin both layouts so a field reorder or a size
// change is a compile error rather than a silently corrupted mapping. One domain
// maps each region read-write and the other read-only, and neither can see the
// other's view of it.
const _: () = {
    use core::mem::{align_of, offset_of};

    assert!(LOG_RELAY_SLOTS >= 2, "a relay of one slot holds nothing");

    assert!(RELAY_LINE_BYTES.is_multiple_of(size_of::<u64>()));
    assert!(size_of::<LineSlot>() == 16 + RELAY_LINE_BYTES);
    assert!(align_of::<LineSlot>() == align_of::<AtomicU64>());
    assert!(offset_of!(LineSlot, meta) == 0);
    assert!(offset_of!(LineSlot, unix_nanos) == 8);
    assert!(offset_of!(LineSlot, text) == 16);

    assert!(offset_of!(LogRelay, tail) == 0);
    assert!(offset_of!(LogRelay, dropped) == 4);
    assert!(offset_of!(LogRelay, slots) == RELAY_RING_HEADER_BYTES);
    assert!(align_of::<LogRelay>() == align_of::<AtomicU64>());
    assert!(
        size_of::<LogRelay>()
            == RELAY_RING_HEADER_BYTES + LOG_RELAY_SLOTS as usize * size_of::<LineSlot>()
    );

    assert!(offset_of!(LogRelayConsume, head) == 0);
    assert!(align_of::<LogRelayConsume>() == align_of::<AtomicU32>());
    assert!(size_of::<LogRelayConsume>() == 4);

    // The lines region is one page and no more: a second page of authority on
    // the domain holding the block device is what this whole region avoids.
    assert!(LOG_RELAY_REGION_SIZE == MAPPING_ALIGN);
    assert!(LOG_RELAY_CONSUME_REGION_SIZE == MAPPING_ALIGN);
    assert!(size_of::<LogRelay>() <= MAPPING_ALIGN);

    // A line's origin is a protection domain's discriminant and it crosses in one
    // byte, so every domain must have a value inside one.
    assert!(LOG_DOMAIN_COUNT < u8::MAX);
};

#[cfg(test)]
mod tests;
