//! A batch of console transcript lines as the bytes a recording carries them
//! in, and the reader that takes one apart again.
//!
//! # Adversary
//!
//! The **byzantine neighbour protection domain** on the writing side — every
//! line encoded here came out of a region the console domain owns, and every
//! line *that* domain published came out of a region a writing domain owns, so
//! what is framed is a peer's claim two indirections away — and, on the reading
//! side, whoever holds a recording. [`decode`] is therefore total over arbitrary
//! bytes: any input is a typed refusal or a batch of lines, and no input panics,
//! indexes out of range or loops on a length it was handed.
//!
//! # Why the first byte is never zero
//!
//! These batches share a block type and an enterprise number with the padding
//! the recorder writes behind the last record of a sector, and that padding is
//! all zeroes. So the discriminator is the first byte of the data: **empty data,
//! or a leading zero byte, is padding**, and every other value names a kind.
//! Every recording ever written decodes correctly under that rule, padding
//! having no other byte to offer.
//!
//! # Why the alphabet is checked here and not left to whoever stores a line
//!
//! A line is a string that leaves this appliance and is stored, displayed and
//! queried elsewhere, and it arrived in a region a peer domain writes. Two
//! things follow. A slot the console never reached is zeroes, and a slot read
//! while it was being written is two lines spliced, so an unchecked reader would
//! store text no domain ever printed — including embedded NULs, which a
//! downstream string column may not even be able to hold. And the console
//! grammar renders one closed alphabet: printable ASCII and nothing else. So
//! this reader refuses a line outside that alphabet by name, which turns both
//! failures into a counted refusal instead of a stored lie.
//!
//! # Why the count is stated rather than walked to the end
//!
//! A Custom Block's data is padded to a four-byte boundary by whoever wrote the
//! block, and an entry is as long as its line. A reader walking to the end of
//! the data would take that padding for a fifth field of a fourth entry. The
//! count says where the entries stop, and the walk is bounded by it *and* by the
//! bytes that remain — whichever runs out first ends it.

use core::mem::size_of;

/// The kind byte of a transcript batch. Never zero, which is what tells one from
/// the padding block it shares a type and an enterprise number with.
pub const TRANSCRIPT_KIND: u8 = 2;

/// The layout version of a batch's body. Bumped when the fields below move.
pub const TRANSCRIPT_VERSION: u8 = 1;

/// Bytes ahead of the first entry: the kind, the version, two reserved bytes,
/// the entry count and two more reserved bytes.
pub const TRANSCRIPT_HEADER_BYTES: usize = 8;

/// Bytes of one entry ahead of its line: the origin, the flags, the line's
/// length, and the instant.
pub const TRANSCRIPT_ENTRY_HEADER_BYTES: usize = 12;

/// The longest line an entry carries, matching the relay slot it was copied out
/// of, so the two ABIs cannot part on what fits.
pub const TRANSCRIPT_LINE_BYTES: usize = crate::RELAY_LINE_BYTES;

/// The most entries one batch carries: every slot the relay can hold at once.
///
/// Derived rather than chosen, and it is what makes [`BATCH_BYTES`] a build
/// constant — which is in turn what lets the domain that writes one assert at
/// compile time that a batch always fits the recording it goes into.
pub const TRANSCRIPT_MAX_ENTRIES: usize = crate::LOG_RELAY_SLOTS as usize;

/// Bytes the longest batch occupies.
pub const BATCH_BYTES: usize = TRANSCRIPT_HEADER_BYTES
    + TRANSCRIPT_MAX_ENTRIES * (TRANSCRIPT_ENTRY_HEADER_BYTES + TRANSCRIPT_LINE_BYTES);

/// The lowest and highest byte a console line may carry: printable ASCII, space
/// through tilde. The grammar renders nothing else — no tab, no control byte, no
/// byte above 127 — and the line ending is added by the console driver rather
/// than being part of a line.
const PRINTABLE: core::ops::RangeInclusive<u8> = 0x20..=0x7e;

/// Why a batch was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output is shorter than the batch. Nothing partial is written: a batch
    /// cut short is one a reader parses happily and takes lines out of.
    OutOfSpace { needed: usize, capacity: usize },
}

/// Why a batch could not be read back.
///
/// One variant per distinct cause, because these are what a server reports when
/// a recording will not decode and a variant covering three causes names none of
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Empty data, or a leading zero byte: the padding block this shares a type
    /// and an enterprise number with. Not a fault — a reader steps over it.
    Padding,
    /// A kind byte naming something this build does not read.
    UnknownKind { kind: u8 },
    /// A body version this build does not read.
    UnknownVersion { version: u8 },
    /// A reserved byte that is not zero, which is a writer this build does not
    /// share a layout with.
    ReservedSet,
    /// Fewer bytes than the header needs.
    TooShort { len: usize, needed: usize },
    /// A batch claiming more entries than a relay can hold, which no correct
    /// writer produces.
    TooManyEntries { stated: usize, held: usize },
    /// The entry at `at` does not fit the bytes that follow it.
    Truncated {
        at: usize,
        needed: usize,
        left: usize,
    },
    /// The entry at `at` carries a flag bit this build does not define.
    UnknownFlags { at: usize, flags: u8 },
    /// The entry at `at` carries a byte no console line can, so the text is not
    /// a line this appliance printed. `byte` is the first such byte.
    Unprintable { at: usize, byte: u8 },
}

/// One line out of a batch, as a reader gets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptLine<'data> {
    /// Which protection domain's ring the line was drained from, as
    /// `lfw_log::Domain`'s discriminant. Not bounded here — this crate holds no
    /// vocabulary — so a reader maps it through its own and reports one it cannot
    /// name.
    pub origin: u8,
    /// Nanoseconds since the Unix epoch, or `None` where the emitting domain had
    /// no clock. A sum type rather than a reserved value, on
    /// [`crate::LogStampKind`]'s terms.
    pub unix_nanos: Option<u64>,
    /// The line the console printed, without its ending, in the alphabet the
    /// header names.
    pub line: &'data [u8],
}

/// One line as a writer offers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'data> {
    pub origin: u8,
    pub unix_nanos: Option<u64>,
    pub line: &'data [u8],
}

/// Write one batch of `entries` into `out`, answering its length.
///
/// Entries past [`TRANSCRIPT_MAX_ENTRIES`], and a line past
/// [`TRANSCRIPT_LINE_BYTES`], are truncated to what the ABI carries rather than
/// refused: both are unreachable from first-party code — the writer drains a
/// relay whose slots are exactly these widths — and a bound that cannot be
/// violated is better spent on the assertion below than on an error nobody can
/// produce.
///
/// # Errors
/// [`EncodeError::OutOfSpace`] when `out` cannot hold the batch.
pub fn encode(out: &mut [u8], entries: &[Entry<'_>]) -> Result<usize, EncodeError> {
    let taken = entries.get(..TRANSCRIPT_MAX_ENTRIES).unwrap_or(entries);
    let mut needed = TRANSCRIPT_HEADER_BYTES;
    for entry in taken {
        let text = entry
            .line
            .get(..TRANSCRIPT_LINE_BYTES)
            .unwrap_or(entry.line);
        needed = needed
            .saturating_add(TRANSCRIPT_ENTRY_HEADER_BYTES)
            .saturating_add(text.len());
    }
    let capacity = out.len();
    if needed > capacity {
        return Err(EncodeError::OutOfSpace { needed, capacity });
    }
    let mut batch = Batch::new(out);
    for entry in taken {
        if !batch.push(entry) {
            // Unreachable: the length was measured above against this very
            // buffer. A value rather than an assertion, because this encoder is
            // reached from a protection domain and no transcript line may fault
            // one.
            break;
        }
    }
    Ok(batch.finish())
}

/// A batch being composed one entry at a time.
///
/// The domain that writes these blocks copies each line out of a shared region
/// into one buffer it reuses, so it holds exactly one line at a time and cannot
/// present the array of borrows [`encode`] takes. This is the same encoder with
/// the entries arriving one by one, and [`encode`] is written on top of it so
/// there is one implementation of the layout and not two.
pub struct Batch<'out> {
    body: &'out mut [u8],
    at: usize,
    count: u16,
}

impl<'out> Batch<'out> {
    /// Begin a batch in `out`, writing its header.
    ///
    /// Storage too short for a header yields a batch that takes no entry and
    /// finishes at zero, which is what a caller offering nothing gets anyway.
    #[must_use]
    pub fn new(out: &'out mut [u8]) -> Self {
        out.fill(0);
        let mut batch = Self {
            body: out,
            at: 0,
            count: 0,
        };
        let mut writer = Writer {
            body: batch.body,
            at: 0,
        };
        writer.byte(TRANSCRIPT_KIND);
        writer.byte(TRANSCRIPT_VERSION);
        writer.byte(0);
        writer.byte(0);
        writer.half(0);
        writer.half(0);
        batch.at = TRANSCRIPT_HEADER_BYTES;
        batch
    }

    /// Append one entry, answering whether it was taken.
    ///
    /// `false` for storage with no room for it, and for a batch already holding
    /// [`TRANSCRIPT_MAX_ENTRIES`]. Nothing partial is written either way: an
    /// entry half in the batch is one a reader parses as a whole entry with a
    /// borrowed tail.
    pub fn push(&mut self, entry: &Entry<'_>) -> bool {
        if self.count as usize >= TRANSCRIPT_MAX_ENTRIES {
            return false;
        }
        let text = entry
            .line
            .get(..TRANSCRIPT_LINE_BYTES)
            .unwrap_or(entry.line);
        let end = self
            .at
            .saturating_add(TRANSCRIPT_ENTRY_HEADER_BYTES)
            .saturating_add(text.len());
        if end > self.body.len() || self.at < TRANSCRIPT_HEADER_BYTES {
            return false;
        }
        let mut writer = Writer {
            body: self.body,
            at: self.at,
        };
        writer.byte(entry.origin);
        match entry.unix_nanos {
            Some(_) => writer.byte(crate::FLAG_STAMPED),
            None => writer.byte(0),
        }
        writer.half(text.len() as u16);
        writer.long(entry.unix_nanos.unwrap_or(0));
        writer.bytes(text);
        self.at = end;
        self.count = self.count.saturating_add(1);
        true
    }

    /// Close the batch, writing the entry count it turned out to hold, and answer
    /// its length.
    #[must_use]
    pub fn finish(self) -> usize {
        if let Some(slot) = self.body.get_mut(4..6) {
            slot.copy_from_slice(&self.count.to_le_bytes());
        }
        // Storage that could not hold a header holds no batch at all, and
        // saying it holds a header's worth would offer a reader bytes that were
        // never written.
        if self.body.len() < TRANSCRIPT_HEADER_BYTES {
            return 0;
        }
        self.at
    }

    /// How many entries the batch holds so far.
    #[must_use]
    pub const fn entries(&self) -> u16 {
        self.count
    }
}

/// Take one Custom Block's data apart as a batch of transcript lines, calling
/// `each` with every line in the order they were printed.
///
/// Total over arbitrary bytes: every input is a run of calls followed by `Ok`, or
/// a named refusal. [`DecodeError::Padding`] is the one refusal that is not a
/// fault — it is the block the recorder writes to fill a sector, which shares
/// this block type and enterprise number and is told apart by its leading zero.
///
/// A refusal *stops* the walk, and the lines already handed over stand: a batch
/// whose fourth entry is malformed still carried three lines the console
/// printed, and discarding them would lose transcript to punish its neighbour.
/// The caller counts the refusal and keeps what it was given, which is what
/// every other reader of a peer's region does.
///
/// # Errors
/// As [`DecodeError`], one variant per distinct cause.
pub fn decode(data: &[u8], mut each: impl FnMut(TranscriptLine<'_>)) -> Result<usize, DecodeError> {
    let Some(&kind) = data.first() else {
        return Err(DecodeError::Padding);
    };
    if kind == 0 {
        return Err(DecodeError::Padding);
    }
    if kind != TRANSCRIPT_KIND {
        return Err(DecodeError::UnknownKind { kind });
    }
    let Some(header) = data.get(..TRANSCRIPT_HEADER_BYTES) else {
        return Err(DecodeError::TooShort {
            len: data.len(),
            needed: TRANSCRIPT_HEADER_BYTES,
        });
    };
    let mut reader = Reader {
        body: header,
        at: 1,
    };
    let version = reader.byte();
    if version != TRANSCRIPT_VERSION {
        return Err(DecodeError::UnknownVersion { version });
    }
    if reader.byte() != 0 || reader.byte() != 0 {
        return Err(DecodeError::ReservedSet);
    }
    let stated = reader.half() as usize;
    if reader.half() != 0 {
        return Err(DecodeError::ReservedSet);
    }
    if stated > TRANSCRIPT_MAX_ENTRIES {
        return Err(DecodeError::TooManyEntries {
            stated,
            held: TRANSCRIPT_MAX_ENTRIES,
        });
    }
    // Bounded by the stated count, which is itself bounded above by a build
    // constant, so the loop runs a known number of times whatever the input
    // said; every step is additionally bounded by the bytes that remain.
    let mut at = TRANSCRIPT_HEADER_BYTES;
    for index in 0..stated {
        let left = data.len().saturating_sub(at);
        let Some(entry) = data.get(at..at.saturating_add(TRANSCRIPT_ENTRY_HEADER_BYTES)) else {
            return Err(DecodeError::Truncated {
                at: index,
                needed: TRANSCRIPT_ENTRY_HEADER_BYTES,
                left,
            });
        };
        let mut fields = Reader { body: entry, at: 0 };
        let origin = fields.byte();
        let flags = fields.byte();
        if flags & !crate::RELAY_FLAG_BITS != 0 {
            return Err(DecodeError::UnknownFlags { at: index, flags });
        }
        let len = fields.half() as usize;
        let unix_nanos = fields.long();
        let from = at.saturating_add(TRANSCRIPT_ENTRY_HEADER_BYTES);
        let Some(line) = data.get(from..from.saturating_add(len)) else {
            return Err(DecodeError::Truncated {
                at: index,
                needed: TRANSCRIPT_ENTRY_HEADER_BYTES.saturating_add(len),
                left,
            });
        };
        if let Some(&byte) = line.iter().find(|byte| !PRINTABLE.contains(byte)) {
            return Err(DecodeError::Unprintable { at: index, byte });
        }
        each(TranscriptLine {
            origin,
            unix_nanos: if flags & crate::FLAG_STAMPED == 0 {
                None
            } else {
                Some(unix_nanos)
            },
            line,
        });
        at = from.saturating_add(len);
    }
    Ok(stated)
}

/// A little-endian writer over storage already proven long enough, so no store
/// here can be short and none needs an error of its own.
struct Writer<'out> {
    body: &'out mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn byte(&mut self, value: u8) {
        if let Some(slot) = self.body.get_mut(self.at) {
            *slot = value;
        }
        self.at = self.at.saturating_add(1);
    }

    fn half(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    fn long(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        if let Some(slot) = self
            .body
            .get_mut(self.at..self.at.saturating_add(value.len()))
        {
            slot.copy_from_slice(value);
        }
        self.at = self.at.saturating_add(value.len());
    }
}

/// A little-endian reader over storage the caller has already proven whole: a
/// field past it reads as zero rather than as a fault, and the checks above are
/// what turn that into a refusal.
struct Reader<'body> {
    body: &'body [u8],
    at: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> u8 {
        let value = self.body.get(self.at).copied().unwrap_or(0);
        self.at = self.at.saturating_add(1);
        value
    }

    fn half(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }

    fn long(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let at = self.at;
        self.at = self.at.saturating_add(N);
        self.body
            .get(at..at.saturating_add(N))
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or([0; N])
    }
}

// The two ends of one ABI, fixed at build time: one domain writes these bytes
// into a recording and a management server reads them out of it, so a header that
// moved must be a compile error here rather than a server attributing one
// domain's line to another.
const _: () = {
    assert!(TRANSCRIPT_KIND != 0);
    assert!(TRANSCRIPT_KIND != 1, "1 is the metric reading's kind");
    assert!(TRANSCRIPT_HEADER_BYTES == 8);
    assert!(TRANSCRIPT_ENTRY_HEADER_BYTES == 4 + size_of::<u64>());
    // A line's length crosses in two bytes, so the slot it is copied out of must
    // fit that field.
    assert!(TRANSCRIPT_LINE_BYTES <= u16::MAX as usize);
    // As must the entry count.
    assert!(TRANSCRIPT_MAX_ENTRIES <= u16::MAX as usize);
    assert!(
        BATCH_BYTES
            == TRANSCRIPT_HEADER_BYTES
                + TRANSCRIPT_MAX_ENTRIES * (TRANSCRIPT_ENTRY_HEADER_BYTES + TRANSCRIPT_LINE_BYTES)
    );
};

#[cfg(test)]
mod tests;
