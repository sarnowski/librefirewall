use proptest::prelude::*;

use super::{
    BIT_STRING, DerError, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, Writer, context,
    context_primitive,
};

/// The encoding of a value, for comparison against what the standard says it
/// is. Every expected byte string below was written from the encoding rules
/// rather than from this writer's output.
fn encoded(room: usize, body: impl FnOnce(&mut Writer<'_>) -> Result<(), DerError>) -> Vec<u8> {
    let mut buffer = vec![0_u8; room];
    let mut writer = Writer::new(&mut buffer);
    body(&mut writer).expect("the buffer is wide enough");
    let len = writer.len();
    buffer.truncate(len);
    buffer
}

#[test]
fn a_short_element_takes_the_one_byte_length_form() {
    assert_eq!(
        encoded(16, |w| w.primitive(OCTET_STRING, &[1, 2, 3])),
        vec![0x04, 0x03, 1, 2, 3]
    );
    assert_eq!(
        encoded(16, |w| w.primitive(OCTET_STRING, &[])),
        vec![0x04, 0x00]
    );
}

#[test]
fn the_length_form_widens_exactly_at_the_boundaries_the_encoding_names() {
    // 127 content bytes is the last short form; 128 is the first long one, and
    // 256 and 65536 are where the long form widens again.
    for (content, header) in [
        (127_usize, vec![0x04, 0x7f]),
        (128, vec![0x04, 0x81, 0x80]),
        (255, vec![0x04, 0x81, 0xff]),
        (256, vec![0x04, 0x82, 0x01, 0x00]),
        (65_535, vec![0x04, 0x82, 0xff, 0xff]),
        (65_536, vec![0x04, 0x83, 0x01, 0x00, 0x00]),
    ] {
        let body = vec![0_u8; content];
        let out = encoded(content + 8, |w| w.primitive(OCTET_STRING, &body));
        assert_eq!(out.get(..header.len()), Some(&header[..]), "{content}");
        assert_eq!(out.len(), header.len() + content);
    }
}

#[test]
fn a_constructed_element_carries_its_children_and_its_own_length() {
    assert_eq!(
        encoded(32, |w| w.constructed(SEQUENCE, |inner| {
            inner.primitive(OBJECT_IDENTIFIER, &[0x55, 0x04, 0x03])?;
            inner.primitive(OCTET_STRING, &[0xaa])
        })),
        vec![0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x04, 0x01, 0xaa]
    );
    // An empty constructed element is a header and nothing else, which is what
    // an end-entity certificate's basic constraints are.
    assert_eq!(
        encoded(8, |w| w.constructed(SEQUENCE, |_| Ok(()))),
        vec![0x30, 0x00]
    );
}

#[test]
fn a_constructed_element_whose_children_widen_its_length_still_encodes() {
    // The header is reserved at its widest and the content moves back over it,
    // so a child set that pushes the length into the long form must still come
    // out contiguous.
    let body = vec![0_u8; 300];
    let out = encoded(512, |w| {
        w.constructed(SEQUENCE, |inner| inner.primitive(OCTET_STRING, &body))
    });
    assert_eq!(out.get(..4), Some(&[0x30, 0x82, 0x01, 0x30][..]));
    assert_eq!(out.get(4..8), Some(&[0x04, 0x82, 0x01, 0x2c][..]));
    assert_eq!(out.len(), 4 + 4 + 300);
}

#[test]
fn nesting_holds_at_depth() {
    let out = encoded(64, |w| {
        w.constructed(SEQUENCE, |a| {
            a.constructed(context(3), |b| {
                b.constructed(SEQUENCE, |c| c.primitive(OCTET_STRING, &[7]))
            })
        })
    });
    assert_eq!(
        out,
        vec![0x30, 0x07, 0xa3, 0x05, 0x30, 0x03, 0x04, 0x01, 0x07]
    );
}

#[test]
fn a_bit_string_says_it_has_no_unused_bits() {
    assert_eq!(
        encoded(16, |w| w.bit_string(&[0xde, 0xad])),
        vec![0x03, 0x03, 0x00, 0xde, 0xad]
    );
    assert_eq!(encoded(8, |w| w.bit_string(&[])), vec![0x03, 0x01, 0x00]);
}

#[test]
fn an_integer_drops_leading_zeroes_and_stays_positive() {
    for (magnitude, expected) in [
        (&[0x00_u8][..], vec![0x02, 0x01, 0x00]),
        (&[][..], vec![0x02, 0x01, 0x00]),
        (&[0x00, 0x00, 0x01][..], vec![0x02, 0x01, 0x01]),
        (&[0x7f][..], vec![0x02, 0x01, 0x7f]),
        (&[0x80][..], vec![0x02, 0x02, 0x00, 0x80]),
        (&[0x00, 0xff, 0x01][..], vec![0x02, 0x03, 0x00, 0xff, 0x01]),
    ] {
        assert_eq!(
            encoded(16, |w| w.unsigned_integer(magnitude)),
            expected,
            "{magnitude:?}"
        );
    }
}

#[test]
fn a_context_tag_is_constructed_or_primitive_as_the_structure_asks() {
    assert_eq!(context(0), 0xa0);
    assert_eq!(context(3), 0xa3);
    assert_eq!(context_primitive(7), 0x87);
    assert_eq!(
        encoded(16, |w| w.primitive(context_primitive(7), &[10, 0, 0, 1])),
        vec![0x87, 0x04, 10, 0, 0, 1]
    );
}

#[test]
fn a_buffer_that_is_too_small_refuses_at_every_step_and_never_indexes() {
    for room in 0_usize..12 {
        let mut buffer = vec![0_u8; room];
        let mut writer = Writer::new(&mut buffer);
        let outcome = writer.constructed(SEQUENCE, |inner| {
            inner.primitive(OCTET_STRING, &[1, 2, 3, 4, 5])
        });
        if room < 12 {
            assert!(
                matches!(outcome, Err(DerError::OutOfSpace { .. })),
                "{room}"
            );
        }
    }
    let mut buffer = [0_u8; 12];
    let mut writer = Writer::new(&mut buffer);
    assert!(
        writer
            .constructed(SEQUENCE, |inner| inner
                .primitive(OCTET_STRING, &[1, 2, 3, 4, 5]))
            .is_ok()
    );
    assert_eq!(writer.len(), 9);
}

#[test]
fn an_empty_writer_says_so_and_a_written_one_does_not() {
    let mut buffer = [0_u8; 8];
    let mut writer = Writer::new(&mut buffer);
    assert!(writer.is_empty());
    writer.primitive(INTEGER, &[1]).expect("room");
    assert!(!writer.is_empty());
    assert_eq!(writer.len(), 3);
}

#[test]
fn a_length_past_what_this_writer_encodes_is_refused_rather_than_truncated() {
    // The writer's long form reaches three length bytes, so a value at 2^24 is
    // the first it will not carry. Reached through the header path rather than
    // by building such a value, which no caller has the memory for.
    let mut buffer = [0_u8; 8];
    let mut writer = Writer::new(&mut buffer);
    let huge = 1_usize << 24;
    assert_eq!(
        writer.bytes(&[0; 4]).and_then(|()| {
            // A primitive whose content slice claims that length cannot be
            // built, so the refusal is provoked through the same encoder the
            // real path uses.
            super::encode_header(SEQUENCE, huge, &mut [0; 5]).map(|_| ())
        }),
        Err(DerError::TooLong { bytes: huge })
    );
}

proptest! {
    /// Arbitrary content, arbitrary room: either it encodes and the bytes are
    /// a well-formed element, or it refuses. Never a panic and never a write
    /// past the buffer.
    #[test]
    fn arbitrary_content_encodes_or_refuses(
        content in proptest::collection::vec(any::<u8>(), 0..600),
        room in 0_usize..700,
    ) {
        let mut buffer = vec![0_u8; room];
        let mut writer = Writer::new(&mut buffer);
        match writer.constructed(SEQUENCE, |inner| inner.primitive(OCTET_STRING, &content)) {
            Ok(()) => {
                let len = writer.len();
                prop_assert!(len <= room);
                prop_assert_eq!(buffer.first(), Some(&SEQUENCE));
            }
            Err(DerError::OutOfSpace { needed }) => prop_assert!(needed > 0),
            Err(other) => prop_assert!(false, "{other:?}"),
        }
    }

    /// Every magnitude encodes to a positive integer whose content never
    /// begins with a byte that would make it negative, and never carries a
    /// redundant leading zero.
    #[test]
    fn every_integer_is_canonical(magnitude in proptest::collection::vec(any::<u8>(), 0..40)) {
        let out = encoded(64, |w| w.unsigned_integer(&magnitude));
        prop_assert_eq!(out.first(), Some(&INTEGER));
        let content = &out[2..];
        prop_assert!(!content.is_empty());
        prop_assert!(content[0] & 0x80 == 0);
        if content.len() > 1 {
            prop_assert!(content[0] != 0 || content[1] & 0x80 != 0);
        }
    }

    /// A bit string's first content byte is always the unused-bit count, which
    /// is always zero here.
    #[test]
    fn every_bit_string_declares_no_unused_bits(
        content in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let out = encoded(128, |w| w.bit_string(&content));
        prop_assert_eq!(out.first(), Some(&BIT_STRING));
        prop_assert_eq!(out.get(2), if content.is_empty() { None } else { Some(&content[0]) }
            .map(|_| &0_u8).or(Some(&0_u8)));
    }
}
