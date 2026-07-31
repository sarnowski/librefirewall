use super::*;
use core::mem::{align_of, offset_of, size_of};
use proptest::prelude::*;

const RECORD_BYTES: usize = size_of::<LogRecord>();

/// See the record module's tests for why every bit pattern is a valid record.
fn record_from_bytes(bytes: [u8; RECORD_BYTES]) -> LogRecord {
    // SAFETY: `LogRecord` is `#[repr(C)]`, `Copy`, and asserted in
    // `log_record.rs` to be exactly the sum of its fields' sizes, so it has no
    // padding and every byte belongs to an integer field that admits any bit
    // pattern.
    unsafe { core::mem::transmute(bytes) }
}

/// The compile-time assertions above prove the same equalities, but only for
/// the build that compiles them away; this is the one a failure names.
#[test]
fn the_atomic_image_occupies_exactly_the_bytes_the_plain_one_does() {
    assert_eq!(size_of::<LogSlot>(), size_of::<LogRecord>());
    assert_eq!(size_of::<LogSlot>(), 232);
    assert_eq!(align_of::<LogSlot>(), align_of::<LogRecord>());
    assert_eq!(align_of::<LogSlot>(), 8);
    assert_eq!(
        [
            offset_of!(LogSlot, features),
            offset_of!(LogSlot, operands),
            offset_of!(LogSlot, tsc_hz),
            offset_of!(LogSlot, unix_nanos),
            offset_of!(LogSlot, stamp_nanos),
            offset_of!(LogSlot, kind),
            offset_of!(LogSlot, generation),
            offset_of!(LogSlot, sequence),
            offset_of!(LogSlot, changes),
            offset_of!(LogSlot, reject_offset),
            offset_of!(LogSlot, receive_posted),
            offset_of!(LogSlot, domain),
            offset_of!(LogSlot, state),
            offset_of!(LogSlot, detail),
            offset_of!(LogSlot, operand_count),
            offset_of!(LogSlot, signalled),
            offset_of!(LogSlot, change),
            offset_of!(LogSlot, object),
            offset_of!(LogSlot, field),
            offset_of!(LogSlot, outcome),
            offset_of!(LogSlot, reason),
            offset_of!(LogSlot, stamp_kind),
            offset_of!(LogSlot, _pad),
            offset_of!(LogSlot, cause),
            offset_of!(LogSlot, key),
            offset_of!(LogSlot, from),
            offset_of!(LogSlot, to),
        ],
        [
            offset_of!(LogRecord, features),
            offset_of!(LogRecord, operands),
            offset_of!(LogRecord, tsc_hz),
            offset_of!(LogRecord, unix_nanos),
            offset_of!(LogRecord, stamp_nanos),
            offset_of!(LogRecord, kind),
            offset_of!(LogRecord, generation),
            offset_of!(LogRecord, sequence),
            offset_of!(LogRecord, changes),
            offset_of!(LogRecord, reject_offset),
            offset_of!(LogRecord, receive_posted),
            offset_of!(LogRecord, domain),
            offset_of!(LogRecord, state),
            offset_of!(LogRecord, detail),
            offset_of!(LogRecord, operand_count),
            offset_of!(LogRecord, signalled),
            offset_of!(LogRecord, change),
            offset_of!(LogRecord, object),
            offset_of!(LogRecord, field),
            offset_of!(LogRecord, outcome),
            offset_of!(LogRecord, reason),
            offset_of!(LogRecord, stamp_kind),
            offset_of!(LogRecord, _pad),
            offset_of!(LogRecord, cause),
            offset_of!(LogRecord, key),
            offset_of!(LogRecord, from),
            offset_of!(LogRecord, to),
        ]
    );

    assert_eq!(
        size_of::<TextSlot<LOG_IDENTIFIER_BYTES>>(),
        size_of::<IdentifierImage>()
    );
    assert_eq!(
        size_of::<TextSlot<LOG_CAUSE_BYTES>>(),
        size_of::<CauseImage>()
    );
    assert_eq!(size_of::<ValueSlot>(), size_of::<ValueImage>());
    assert_eq!(align_of::<ValueSlot>(), align_of::<ValueImage>());
    assert_eq!(
        [
            offset_of!(ValueSlot, number),
            offset_of!(ValueSlot, kind),
            offset_of!(ValueSlot, octets),
            offset_of!(ValueSlot, _pad),
            offset_of!(ValueSlot, id),
        ],
        [
            offset_of!(ValueImage, number),
            offset_of!(ValueImage, kind),
            offset_of!(ValueImage, octets),
            offset_of!(ValueImage, _pad),
            offset_of!(ValueImage, id),
        ]
    );
}

/// A zeroed region reads back as the zeroed record, which is what lets the
/// console domain come up against one before anything has been written.
#[test]
fn an_untouched_slot_holds_the_zero_record() {
    assert_eq!(LogSlot::zero().load(), LogRecord::ZERO);
    assert_eq!(
        ValueSlot::zero().load(),
        crate::log_record::ValueImage::ZERO
    );
    assert_eq!(
        TextSlot::<LOG_IDENTIFIER_BYTES>::zero().load(),
        IdentifierImage::ZERO
    );
    assert_eq!(TextSlot::<LOG_CAUSE_BYTES>::zero().load(), CauseImage::ZERO);
}

proptest! {
    /// Every byte of an arbitrary record survives the region unchanged, padding
    /// included: the atomic image moves a record and rules on none of it, so a
    /// writer's bytes are the console's bytes whatever they say.
    #[test]
    fn an_arbitrary_record_round_trips_through_the_region(
        written in proptest::collection::vec(any::<u8>(), RECORD_BYTES),
        second in proptest::collection::vec(any::<u8>(), RECORD_BYTES),
    ) {
        let mut image = [0u8; RECORD_BYTES];
        image.copy_from_slice(&written);
        let record = record_from_bytes(image);

        let slot = LogSlot::zero();
        slot.store(&record);
        prop_assert_eq!(slot.load(), record);
        // The padding the writer chose crossed too, byte for byte.
        prop_assert_eq!(slot.load()._pad, record._pad);
        prop_assert_eq!(slot.load().key._pad, record.key._pad);
        prop_assert_eq!(slot.load().cause._pad, record.cause._pad);
        prop_assert_eq!(slot.load().from._pad, record.from._pad);
        prop_assert_eq!(slot.load().to.id._pad, record.to.id._pad);

        // And again over an already-written slot, so no field is left holding
        // what the previous record put there.
        slot.store(&LogRecord::ZERO);
        prop_assert_eq!(slot.load(), LogRecord::ZERO);
        slot.store(&record);
        prop_assert_eq!(slot.load(), record);

        let mut other = [0u8; RECORD_BYTES];
        other.copy_from_slice(&second);
        let next = record_from_bytes(other);
        slot.store(&next);
        prop_assert_eq!(slot.load(), next);
    }
}
