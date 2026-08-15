//! One whole metric reading as the bytes a recording carries it in, and the
//! reader that takes one apart again.
//!
//! # Adversary
//!
//! The **byzantine neighbour protection domain** on the writing side — every
//! number encoded here came out of a region another domain owns — and, on the
//! reading side, whoever holds a recording. [`decode`] is therefore total over
//! arbitrary bytes: any input is a typed refusal or a reading, and no input
//! panics, indexes out of range or loops on a length it was handed.
//!
//! # Why the block says what catalogue it was written against
//!
//! A slot here means whatever the series table at that position means, and that
//! table is a build-time fact of one image. A reader holding a recording written
//! by another build must not map slot 300 through its own table and answer a
//! plausible number for the wrong series — a wrong number being worse than a
//! missing one on a surface an operator acts on. So every reading carries
//! [`CATALOGUE_FINGERPRINT`], which is derived from every name, label and shard
//! the table holds, and a reader whose own fingerprint differs refuses the whole
//! reading rather than mapping any of it.
//!
//! # Why the first byte is never zero
//!
//! These readings share a block type and an enterprise number with the padding
//! the recorder writes behind the last record of a sector, and that padding is
//! all zeroes. So the discriminator is the first byte of the data: **empty data,
//! or a leading zero byte, is padding**, and every other value names a kind.
//! Every recording ever written decodes correctly under that rule, padding
//! having no other byte to offer.
//!
//! # The dynamic series are not here
//!
//! Two families — the per-interface information and the per-rule hit counts —
//! have no fixed slot: which ones exist comes from the committed configuration
//! rather than from the catalogue, so no reading carries them. A reading is
//! exactly the closed table, which is what lets both ends hold one fingerprint
//! over it.

use core::mem::size_of;

use crate::catalog::{SHARD_COUNT, SHARDS, Series};
use crate::{STATS_SLOTS, StatsShard};

/// The kind byte of a metric reading. Never zero, which is what tells one from
/// the padding block it shares a type and an enterprise number with.
pub const SNAPSHOT_KIND: u8 = 1;

/// The layout version of a reading's body. Bumped when the fields below move;
/// the fingerprint covers what the *slots* mean and this covers the frame
/// around them.
pub const SNAPSHOT_VERSION: u8 = 1;

/// Bytes ahead of the first value: the kind, the version, two reserved bytes,
/// the catalogue fingerprint, the instant, and the slot count.
pub const SNAPSHOT_HEADER_BYTES: usize = 20;

/// How many slots a reading carries: every series the catalogue names, across
/// every shard, in shard order.
pub const SNAPSHOT_SLOTS: usize = snapshot_slots();

const fn snapshot_slots() -> usize {
    let mut total = 0;
    let mut shard = 0;
    while shard < SHARD_COUNT {
        total += SHARDS[shard].series.len();
        shard += 1;
    }
    total
}

/// Bytes one reading occupies, header and slots together.
pub const SNAPSHOT_BYTES: usize = SNAPSHOT_HEADER_BYTES + SNAPSHOT_SLOTS * size_of::<u64>();

/// One reading of every shard, taken whole before anything is composed from it.
///
/// Taken whole so a reading is one pass over one set of numbers rather than a
/// re-read per family: a walk that read the shards again each time would let a
/// counter appear to move backwards *within* one reading, which is the one shape
/// of inconsistency a reader cannot explain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    values: [[u64; STATS_SLOTS]; SHARD_COUNT],
}

impl Snapshot {
    /// A snapshot of stated values, for a test or a fuzz harness that has no
    /// shared region.
    #[must_use]
    pub const fn new(values: [[u64; STATS_SLOTS]; SHARD_COUNT]) -> Self {
        Self { values }
    }

    /// Read every shard once, in [`SHARDS`] order.
    #[must_use]
    pub fn read(shards: [&StatsShard; SHARD_COUNT]) -> Self {
        let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
        for (target, shard) in values.iter_mut().zip(shards) {
            *target = shard.sample();
        }
        Self { values }
    }

    /// The catalogue's slots laid end to end, in shard order, for the reading
    /// this node hands to the domain that writes the medium — so a slot's
    /// position here **is** its position in [`SHARDS`].
    #[must_use]
    pub fn relay_values(&self) -> [u64; SNAPSHOT_SLOTS] {
        let mut out = [0u64; SNAPSHOT_SLOTS];
        let mut at = 0;
        for (spec, values) in SHARDS.iter().zip(&self.values) {
            for slot in 0..spec.series.len() {
                if let Some(target) = out.get_mut(at) {
                    *target = values.get(slot).copied().unwrap_or(0);
                }
                at = at.saturating_add(1);
            }
        }
        out
    }
}

/// What the slots of a reading mean, as one number over the whole table.
///
/// FNV-1a over every shard's domain and every series' family name, label names
/// and label values, in the order a reading lays them out. Derived rather than
/// chosen, so a series renamed, relabelled, inserted or reordered changes it
/// without anybody remembering to — which is the only way a version number over
/// a four-hundred-entry table stays true.
pub const CATALOGUE_FINGERPRINT: u32 = fingerprint();

const FNV_OFFSET: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;

const fn fnv(mut hash: u32, bytes: &[u8]) -> u32 {
    let mut at = 0;
    while at < bytes.len() {
        hash ^= bytes[at] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
        at += 1;
    }
    hash
}

/// A separator no name, label or domain can contain, so two tables that differ
/// only in where one string ends and the next begins hash differently.
const fn fnv_field(hash: u32, bytes: &[u8]) -> u32 {
    fnv(fnv(hash, bytes), &[0x1f])
}

const fn fingerprint() -> u32 {
    let mut hash = FNV_OFFSET;
    let mut shard = 0;
    while shard < SHARD_COUNT {
        let spec = &SHARDS[shard];
        hash = fnv_field(hash, spec.domain.as_bytes());
        let mut index = 0;
        while index < spec.series.len() {
            let series: &Series = &spec.series[index];
            hash = fnv_field(hash, series.metric.name.as_bytes());
            let mut label = 0;
            while label < series.labels.len() {
                hash = fnv_field(hash, series.labels[label].name.as_bytes());
                hash = fnv_field(hash, series.labels[label].value.as_bytes());
                label += 1;
            }
            hash = fnv_field(hash, b"");
            index += 1;
        }
        shard += 1;
    }
    hash
}

/// Why a reading was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output is shorter than a whole reading. Nothing partial is written:
    /// a reading cut short is one a reader parses happily and takes short values
    /// from.
    OutOfSpace { needed: usize, capacity: usize },
}

/// Why a reading could not be read back.
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
    /// A catalogue this build cannot map. The slots are real numbers about real
    /// series and this build cannot say which, so none of them is reported.
    ForeignCatalogue { stated: u32, held: u32 },
    /// A slot count the catalogue does not have.
    SlotCountMismatch { stated: usize, held: usize },
    /// The stated slot count does not fit the bytes that follow it.
    Truncated { len: usize, needed: usize },
}

/// One reading, taken apart: when it was measured and what every slot held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricSnapshot {
    /// Nanoseconds since the Unix epoch, as the writing domain had it. Zero
    /// where that domain had no clock — a fact a reader reports rather than
    /// repairs.
    pub unix_nanos: u64,
    pub values: [u64; SNAPSHOT_SLOTS],
}

impl MetricSnapshot {
    /// A reading of stated values, for a test or a caller with no region.
    #[must_use]
    pub const fn new(unix_nanos: u64, values: [u64; SNAPSHOT_SLOTS]) -> Self {
        Self { unix_nanos, values }
    }

    /// What one slot held, and the series it belongs to.
    ///
    /// `None` past the table, which is the answer for a caller iterating by
    /// index rather than a fault: a slot outside the catalogue names nothing.
    #[must_use]
    pub fn series(slot: usize) -> Option<(&'static str, &'static Series)> {
        let mut base = 0;
        for spec in &SHARDS {
            if let Some(series) = spec.series.get(slot.wrapping_sub(base)) {
                return Some((spec.domain, series));
            }
            base = base.saturating_add(spec.series.len());
        }
        None
    }
}

/// Write one reading into `out`, answering its length.
///
/// `values` shorter than the catalogue leaves the slots it does not reach at
/// zero; longer is written as far as the catalogue reaches. Both are unreachable
/// from first-party code — the publisher reads the same tables — and neither is
/// worth an error a caller cannot produce.
///
/// # Errors
/// [`EncodeError::OutOfSpace`] when `out` is shorter than [`SNAPSHOT_BYTES`].
pub fn encode(out: &mut [u8], unix_nanos: u64, values: &[u64]) -> Result<usize, EncodeError> {
    let capacity = out.len();
    let Some(body) = out.get_mut(..SNAPSHOT_BYTES) else {
        return Err(EncodeError::OutOfSpace {
            needed: SNAPSHOT_BYTES,
            capacity,
        });
    };
    body.fill(0);
    let mut writer = Writer { body, at: 0 };
    writer.byte(SNAPSHOT_KIND);
    writer.byte(SNAPSHOT_VERSION);
    writer.byte(0);
    writer.byte(0);
    writer.word(CATALOGUE_FINGERPRINT);
    writer.long(unix_nanos);
    writer.word(SNAPSHOT_SLOTS as u32);
    for value in values.iter().take(SNAPSHOT_SLOTS) {
        writer.long(*value);
    }
    Ok(SNAPSHOT_BYTES)
}

/// Take one Custom Block's data apart.
///
/// Total over arbitrary bytes: every input is a reading or a named refusal.
/// [`DecodeError::Padding`] is the one refusal that is not a fault — it is the
/// block the recorder writes to fill a sector, which shares this block type and
/// enterprise number and is told apart by its leading zero.
///
/// # Errors
/// As [`DecodeError`], one variant per distinct cause.
pub fn decode(data: &[u8]) -> Result<MetricSnapshot, DecodeError> {
    let Some(&kind) = data.first() else {
        return Err(DecodeError::Padding);
    };
    if kind == 0 {
        return Err(DecodeError::Padding);
    }
    if kind != SNAPSHOT_KIND {
        return Err(DecodeError::UnknownKind { kind });
    }
    let Some(header) = data.get(..SNAPSHOT_HEADER_BYTES) else {
        return Err(DecodeError::TooShort {
            len: data.len(),
            needed: SNAPSHOT_HEADER_BYTES,
        });
    };
    let mut reader = Reader {
        body: header,
        at: 1,
    };
    let version = reader.byte();
    if version != SNAPSHOT_VERSION {
        return Err(DecodeError::UnknownVersion { version });
    }
    if reader.byte() != 0 || reader.byte() != 0 {
        return Err(DecodeError::ReservedSet);
    }
    let stated = reader.word();
    if stated != CATALOGUE_FINGERPRINT {
        return Err(DecodeError::ForeignCatalogue {
            stated,
            held: CATALOGUE_FINGERPRINT,
        });
    }
    let unix_nanos = reader.long();
    let slots = reader.word() as usize;
    if slots != SNAPSHOT_SLOTS {
        return Err(DecodeError::SlotCountMismatch {
            stated: slots,
            held: SNAPSHOT_SLOTS,
        });
    }
    if data.len() < SNAPSHOT_BYTES {
        return Err(DecodeError::Truncated {
            len: data.len(),
            needed: SNAPSHOT_BYTES,
        });
    }
    let mut snapshot = MetricSnapshot {
        unix_nanos,
        values: [0; SNAPSHOT_SLOTS],
    };
    // Bounded by the catalogue rather than by anything the input stated: the
    // count above is checked equal to it, so this walks a fixed number of
    // eight-byte windows inside a slice already proven long enough.
    for (slot, value) in snapshot.values.iter_mut().enumerate() {
        let at = SNAPSHOT_HEADER_BYTES + slot * size_of::<u64>();
        let bytes = data.get(at..at + size_of::<u64>()).unwrap_or(&[0; 8]);
        *value = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
    }
    Ok(snapshot)
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

    fn word(&mut self, value: u32) {
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

/// A little-endian reader over the header, which the caller has already proven
/// whole: a field past it reads as zero rather than as a fault, and the checks
/// above are what turn that into a refusal.
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

    fn word(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
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
// into a recording and a management server reads them out of it, so a header
// that moved must be a compile error here rather than a server attributing one
// series' number to another.
const _: () = {
    assert!(SNAPSHOT_KIND != 0);
    assert!(SNAPSHOT_HEADER_BYTES == 20);
    assert!(SNAPSHOT_BYTES == SNAPSHOT_HEADER_BYTES + SNAPSHOT_SLOTS * 8);
    // The reading has to fit the region the publisher hands it over in, and that
    // region is one page. A catalogue that outgrew it is a build error here
    // rather than a reading silently cut short.
    assert!(SNAPSHOT_SLOTS <= wire::RELAY_SLOTS);
};

#[cfg(test)]
mod tests;
