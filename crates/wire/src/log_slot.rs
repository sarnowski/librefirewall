//! The shared-memory image of a [`LogRecord`]: the same bytes, reachable
//! through the shared reference a mapped region is the only kind of reference
//! to.
//!
//! Faces the byzantine peer protection domain (CONCEPT §7.1). A peer can write
//! any slot at any moment, and a non-atomic access racing with that write is
//! undefined behaviour — which would let the compiler assume the memory cannot
//! change underneath it. Atomic accesses cannot race by definition, so the
//! worst a byzantine writer achieves is an unexpected *value*. That is what
//! lets this crate hold its `unsafe` count at zero while two domains write the
//! same region.
//!
//! One atomic per byte for the byte arrays rather than a packed word, for the
//! reason [`crate::ConfigImage`]'s image gives: packing text into words would
//! place a field inside a word and make the byte order of the region a thing
//! this crate chooses rather than a thing it mirrors.
//!
//! Nothing here is public. A caller that could reach a field could choose its
//! own `Ordering`, and which ordering each word carries is a property of the
//! transport rather than a convention its users are asked to keep (DOC-9) —
//! so the region is reached through [`crate::LogRecords`]'s handles alone.
//!
//! Accesses are `Relaxed`: all the ordering a record needs is the
//! release/acquire pair on the cursor that publishes it.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::log_record::{
    CauseImage, IdentifierImage, LOG_CAUSE_BYTES, LOG_IDENTIFIER_BYTES, LogRecord, TextImage,
    ValueImage,
};
use crate::{load_bytes, store_bytes};

/// The image of a [`TextImage`].
#[repr(C)]
pub(crate) struct TextSlot<const N: usize> {
    bytes: [AtomicU8; N],
    len: AtomicU8,
    _pad: [AtomicU8; 3],
}

impl<const N: usize> TextSlot<N> {
    /// A `const fn` rather than an associated constant: a constant holding
    /// atomics is copied at each use, so publishing through one would store
    /// into a temporary and be read back by nobody.
    pub(crate) const fn zero() -> Self {
        Self {
            bytes: [const { AtomicU8::new(0) }; N],
            len: AtomicU8::new(0),
            _pad: [const { AtomicU8::new(0) }; 3],
        }
    }

    /// Carries the padding too: this moves an image, and which bytes mean
    /// something is [`LogRecord::check`]'s question rather than this one's.
    fn store(&self, image: &TextImage<N>) {
        store_bytes(&self.bytes, image.bytes);
        self.len.store(image.len, Ordering::Relaxed);
        store_bytes(&self._pad, image._pad);
    }

    fn load(&self) -> TextImage<N> {
        TextImage {
            bytes: load_bytes(&self.bytes),
            len: self.len.load(Ordering::Relaxed),
            _pad: load_bytes(&self._pad),
        }
    }
}

/// The image of a [`ValueImage`].
#[repr(C)]
pub(crate) struct ValueSlot {
    number: AtomicU32,
    kind: AtomicU8,
    octets: [AtomicU8; 6],
    _pad: AtomicU8,
    id: TextSlot<LOG_IDENTIFIER_BYTES>,
}

impl ValueSlot {
    pub(crate) const fn zero() -> Self {
        Self {
            number: AtomicU32::new(0),
            kind: AtomicU8::new(0),
            octets: [const { AtomicU8::new(0) }; 6],
            _pad: AtomicU8::new(0),
            id: TextSlot::zero(),
        }
    }

    fn store(&self, image: &ValueImage) {
        self.number.store(image.number, Ordering::Relaxed);
        self.kind.store(image.kind, Ordering::Relaxed);
        store_bytes(&self.octets, image.octets);
        self._pad.store(image._pad, Ordering::Relaxed);
        self.id.store(&image.id);
    }

    fn load(&self) -> ValueImage {
        ValueImage {
            number: self.number.load(Ordering::Relaxed),
            kind: self.kind.load(Ordering::Relaxed),
            octets: load_bytes(&self.octets),
            _pad: self._pad.load(Ordering::Relaxed),
            id: self.id.load(),
        }
    }
}

/// The image of a [`LogRecord`], byte-identical to it.
#[repr(C)]
pub(crate) struct LogSlot {
    features: AtomicU64,
    operands: [AtomicU64; 2],
    tsc_hz: AtomicU64,
    unix_nanos: AtomicU64,
    kind: AtomicU32,
    generation: AtomicU32,
    sequence: AtomicU32,
    changes: AtomicU32,
    reject_offset: AtomicU32,
    receive_posted: AtomicU32,
    domain: AtomicU8,
    state: AtomicU8,
    detail: AtomicU8,
    operand_count: AtomicU8,
    signalled: AtomicU8,
    change: AtomicU8,
    object: AtomicU8,
    field: AtomicU8,
    outcome: AtomicU8,
    reason: AtomicU8,
    _pad: [AtomicU8; 6],
    cause: TextSlot<LOG_CAUSE_BYTES>,
    key: TextSlot<LOG_IDENTIFIER_BYTES>,
    from: ValueSlot,
    to: ValueSlot,
}

impl LogSlot {
    pub(crate) const fn zero() -> Self {
        Self {
            features: AtomicU64::new(0),
            operands: [const { AtomicU64::new(0) }; 2],
            tsc_hz: AtomicU64::new(0),
            unix_nanos: AtomicU64::new(0),
            kind: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            sequence: AtomicU32::new(0),
            changes: AtomicU32::new(0),
            reject_offset: AtomicU32::new(0),
            receive_posted: AtomicU32::new(0),
            domain: AtomicU8::new(0),
            state: AtomicU8::new(0),
            detail: AtomicU8::new(0),
            operand_count: AtomicU8::new(0),
            signalled: AtomicU8::new(0),
            change: AtomicU8::new(0),
            object: AtomicU8::new(0),
            field: AtomicU8::new(0),
            outcome: AtomicU8::new(0),
            reason: AtomicU8::new(0),
            _pad: [const { AtomicU8::new(0) }; 6],
            cause: TextSlot::zero(),
            key: TextSlot::zero(),
            from: ValueSlot::zero(),
            to: ValueSlot::zero(),
        }
    }

    pub(crate) fn store(&self, record: &LogRecord) {
        self.features.store(record.features, Ordering::Relaxed);
        for (cell, value) in self.operands.iter().zip(record.operands) {
            cell.store(value, Ordering::Relaxed);
        }
        self.tsc_hz.store(record.tsc_hz, Ordering::Relaxed);
        self.unix_nanos.store(record.unix_nanos, Ordering::Relaxed);
        self.kind.store(record.kind, Ordering::Relaxed);
        self.generation.store(record.generation, Ordering::Relaxed);
        self.sequence.store(record.sequence, Ordering::Relaxed);
        self.changes.store(record.changes, Ordering::Relaxed);
        self.reject_offset
            .store(record.reject_offset, Ordering::Relaxed);
        self.receive_posted
            .store(record.receive_posted, Ordering::Relaxed);
        self.domain.store(record.domain, Ordering::Relaxed);
        self.state.store(record.state, Ordering::Relaxed);
        self.detail.store(record.detail, Ordering::Relaxed);
        self.operand_count
            .store(record.operand_count, Ordering::Relaxed);
        self.signalled.store(record.signalled, Ordering::Relaxed);
        self.change.store(record.change, Ordering::Relaxed);
        self.object.store(record.object, Ordering::Relaxed);
        self.field.store(record.field, Ordering::Relaxed);
        self.outcome.store(record.outcome, Ordering::Relaxed);
        self.reason.store(record.reason, Ordering::Relaxed);
        store_bytes(&self._pad, record._pad);
        self.cause.store(&record.cause);
        self.key.store(&record.key);
        self.from.store(&record.from);
        self.to.store(&record.to);
    }

    pub(crate) fn load(&self) -> LogRecord {
        let mut operands = [0; 2];
        for (value, cell) in operands.iter_mut().zip(&self.operands) {
            *value = cell.load(Ordering::Relaxed);
        }
        LogRecord {
            features: self.features.load(Ordering::Relaxed),
            operands,
            tsc_hz: self.tsc_hz.load(Ordering::Relaxed),
            unix_nanos: self.unix_nanos.load(Ordering::Relaxed),
            kind: self.kind.load(Ordering::Relaxed),
            generation: self.generation.load(Ordering::Relaxed),
            sequence: self.sequence.load(Ordering::Relaxed),
            changes: self.changes.load(Ordering::Relaxed),
            reject_offset: self.reject_offset.load(Ordering::Relaxed),
            receive_posted: self.receive_posted.load(Ordering::Relaxed),
            domain: self.domain.load(Ordering::Relaxed),
            state: self.state.load(Ordering::Relaxed),
            detail: self.detail.load(Ordering::Relaxed),
            operand_count: self.operand_count.load(Ordering::Relaxed),
            signalled: self.signalled.load(Ordering::Relaxed),
            change: self.change.load(Ordering::Relaxed),
            object: self.object.load(Ordering::Relaxed),
            field: self.field.load(Ordering::Relaxed),
            outcome: self.outcome.load(Ordering::Relaxed),
            reason: self.reason.load(Ordering::Relaxed),
            _pad: load_bytes(&self._pad),
            cause: self.cause.load(),
            key: self.key.load(),
            from: self.from.load(),
            to: self.to.load(),
        }
    }
}

// Expressing the record as atomics must leave the region the console domain
// maps byte-identical to a plain `LogRecord`: same size, same alignment, every
// field at the offset the plain image puts it at. A mismatch here is a silent
// corruption of every record that crosses, so it is a compile error.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<TextSlot<LOG_IDENTIFIER_BYTES>>() == size_of::<IdentifierImage>());
    assert!(align_of::<TextSlot<LOG_IDENTIFIER_BYTES>>() == align_of::<IdentifierImage>());
    assert!(
        offset_of!(TextSlot<LOG_IDENTIFIER_BYTES>, bytes) == offset_of!(IdentifierImage, bytes)
    );
    assert!(offset_of!(TextSlot<LOG_IDENTIFIER_BYTES>, len) == offset_of!(IdentifierImage, len));
    assert!(offset_of!(TextSlot<LOG_IDENTIFIER_BYTES>, _pad) == offset_of!(IdentifierImage, _pad));

    assert!(size_of::<TextSlot<LOG_CAUSE_BYTES>>() == size_of::<CauseImage>());
    assert!(align_of::<TextSlot<LOG_CAUSE_BYTES>>() == align_of::<CauseImage>());
    assert!(offset_of!(TextSlot<LOG_CAUSE_BYTES>, bytes) == offset_of!(CauseImage, bytes));
    assert!(offset_of!(TextSlot<LOG_CAUSE_BYTES>, len) == offset_of!(CauseImage, len));
    assert!(offset_of!(TextSlot<LOG_CAUSE_BYTES>, _pad) == offset_of!(CauseImage, _pad));

    assert!(size_of::<ValueSlot>() == size_of::<ValueImage>());
    assert!(align_of::<ValueSlot>() == align_of::<ValueImage>());
    assert!(offset_of!(ValueSlot, number) == offset_of!(ValueImage, number));
    assert!(offset_of!(ValueSlot, kind) == offset_of!(ValueImage, kind));
    assert!(offset_of!(ValueSlot, octets) == offset_of!(ValueImage, octets));
    assert!(offset_of!(ValueSlot, _pad) == offset_of!(ValueImage, _pad));
    assert!(offset_of!(ValueSlot, id) == offset_of!(ValueImage, id));

    assert!(size_of::<LogSlot>() == size_of::<LogRecord>());
    assert!(align_of::<LogSlot>() == align_of::<LogRecord>());
    assert!(offset_of!(LogSlot, features) == offset_of!(LogRecord, features));
    assert!(offset_of!(LogSlot, operands) == offset_of!(LogRecord, operands));
    assert!(offset_of!(LogSlot, tsc_hz) == offset_of!(LogRecord, tsc_hz));
    assert!(offset_of!(LogSlot, unix_nanos) == offset_of!(LogRecord, unix_nanos));
    assert!(offset_of!(LogSlot, kind) == offset_of!(LogRecord, kind));
    assert!(offset_of!(LogSlot, generation) == offset_of!(LogRecord, generation));
    assert!(offset_of!(LogSlot, sequence) == offset_of!(LogRecord, sequence));
    assert!(offset_of!(LogSlot, changes) == offset_of!(LogRecord, changes));
    assert!(offset_of!(LogSlot, reject_offset) == offset_of!(LogRecord, reject_offset));
    assert!(offset_of!(LogSlot, receive_posted) == offset_of!(LogRecord, receive_posted));
    assert!(offset_of!(LogSlot, domain) == offset_of!(LogRecord, domain));
    assert!(offset_of!(LogSlot, state) == offset_of!(LogRecord, state));
    assert!(offset_of!(LogSlot, detail) == offset_of!(LogRecord, detail));
    assert!(offset_of!(LogSlot, operand_count) == offset_of!(LogRecord, operand_count));
    assert!(offset_of!(LogSlot, signalled) == offset_of!(LogRecord, signalled));
    assert!(offset_of!(LogSlot, change) == offset_of!(LogRecord, change));
    assert!(offset_of!(LogSlot, object) == offset_of!(LogRecord, object));
    assert!(offset_of!(LogSlot, field) == offset_of!(LogRecord, field));
    assert!(offset_of!(LogSlot, outcome) == offset_of!(LogRecord, outcome));
    assert!(offset_of!(LogSlot, reason) == offset_of!(LogRecord, reason));
    assert!(offset_of!(LogSlot, _pad) == offset_of!(LogRecord, _pad));
    assert!(offset_of!(LogSlot, cause) == offset_of!(LogRecord, cause));
    assert!(offset_of!(LogSlot, key) == offset_of!(LogRecord, key));
    assert!(offset_of!(LogSlot, from) == offset_of!(LogRecord, from));
    assert!(offset_of!(LogSlot, to) == offset_of!(LogRecord, to));
};

#[cfg(test)]
mod tests;
