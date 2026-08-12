use super::*;
use std::vec::Vec;

fn entry(origin: u8, nanos: Option<u64>, line: &str) -> Entry<'_> {
    Entry {
        origin,
        unix_nanos: nanos,
        line: line.as_bytes(),
    }
}

/// Everything a batch was worth, as a test reads it.
fn read(data: &[u8]) -> Result<Vec<(u8, Option<u64>, String)>, DecodeError> {
    let mut lines = Vec::new();
    decode(data, |line| {
        lines.push((
            line.origin,
            line.unix_nanos,
            String::from_utf8_lossy(line.line).into_owned(),
        ))
    })?;
    Ok(lines)
}

#[test]
fn a_batch_round_trips() {
    let entries = [
        entry(
            0,
            Some(7),
            "LFW-PD time=1970-01-01T00:00:00.000000007Z domain=forwarder",
        ),
        entry(
            3,
            None,
            "LFW-CFG time=unsynchronized generation=1 outcome=applied changes=16",
        ),
        entry(9, Some(u64::MAX), "LFW-PD domain=store state=refused"),
    ];
    let mut out = [0u8; BATCH_BYTES];
    let written = encode(&mut out, &entries).expect("room for three lines");
    let read = read(&out[..written]).expect("a batch this build wrote");
    assert_eq!(read.len(), 3);
    for (offered, taken) in entries.iter().zip(&read) {
        assert_eq!(offered.origin, taken.0);
        assert_eq!(offered.unix_nanos, taken.1);
        assert_eq!(core::str::from_utf8(offered.line).unwrap(), taken.2);
    }
}

#[test]
fn an_empty_batch_carries_no_lines_and_is_not_padding() {
    let mut out = [0u8; BATCH_BYTES];
    let written = encode(&mut out, &[]).expect("room for a header");
    assert_eq!(written, TRANSCRIPT_HEADER_BYTES);
    assert_eq!(read(&out[..written]).expect("a header"), Vec::new());
}

/// The discriminator every recording ever written already satisfies.
#[test]
fn padding_is_told_apart_by_its_leading_byte() {
    assert_eq!(read(&[]), Err(DecodeError::Padding));
    assert_eq!(read(&[0]), Err(DecodeError::Padding));
    assert_eq!(read(&[0; 512]), Err(DecodeError::Padding));
}

#[test]
fn a_metric_reading_is_not_a_transcript_batch() {
    assert_eq!(
        read(&[1, 1, 0, 0]),
        Err(DecodeError::UnknownKind { kind: 1 })
    );
}

#[test]
fn a_body_version_this_build_does_not_read_is_refused_by_name() {
    let mut out = [0u8; BATCH_BYTES];
    let written = encode(&mut out, &[entry(0, None, "line")]).unwrap();
    out[1] = TRANSCRIPT_VERSION + 1;
    assert_eq!(
        read(&out[..written]),
        Err(DecodeError::UnknownVersion {
            version: TRANSCRIPT_VERSION + 1
        })
    );
}

#[test]
fn a_reserved_byte_that_is_not_zero_is_a_writer_this_build_does_not_share_a_layout_with() {
    for at in [2usize, 3, 6, 7] {
        let mut out = [0u8; BATCH_BYTES];
        let written = encode(&mut out, &[entry(0, None, "line")]).unwrap();
        out[at] = 1;
        assert_eq!(
            read(&out[..written]),
            Err(DecodeError::ReservedSet),
            "byte {at}"
        );
    }
}

#[test]
fn a_header_cut_short_is_refused_rather_than_read_past() {
    for len in 1..TRANSCRIPT_HEADER_BYTES {
        let mut data = [0u8; TRANSCRIPT_HEADER_BYTES];
        data[0] = TRANSCRIPT_KIND;
        assert_eq!(
            read(&data[..len]),
            Err(DecodeError::TooShort {
                len,
                needed: TRANSCRIPT_HEADER_BYTES
            })
        );
    }
}

#[test]
fn a_batch_claiming_more_entries_than_a_relay_holds_is_refused() {
    let mut data = [0u8; TRANSCRIPT_HEADER_BYTES];
    data[0] = TRANSCRIPT_KIND;
    data[1] = TRANSCRIPT_VERSION;
    let stated = (TRANSCRIPT_MAX_ENTRIES + 1) as u16;
    data[4..6].copy_from_slice(&stated.to_le_bytes());
    assert_eq!(
        read(&data),
        Err(DecodeError::TooManyEntries {
            stated: stated as usize,
            held: TRANSCRIPT_MAX_ENTRIES
        })
    );
}

/// The lines already handed over stand: a batch whose last entry is malformed
/// still carried the ones before it, and discarding them would lose transcript
/// to punish its neighbour.
#[test]
fn a_truncated_batch_keeps_the_lines_that_were_whole() {
    let mut out = [0u8; BATCH_BYTES];
    let written = encode(
        &mut out,
        &[entry(0, None, "first"), entry(1, None, "second")],
    )
    .unwrap();
    let mut lines = Vec::new();
    let refusal = decode(&out[..written - 3], |line| {
        lines.push(String::from_utf8_lossy(line.line).into_owned())
    })
    .expect_err("the second entry does not fit");
    assert!(matches!(refusal, DecodeError::Truncated { at: 1, .. }));
    assert_eq!(lines, ["first"]);
}

#[test]
fn a_flag_bit_this_build_does_not_define_is_refused_by_name() {
    let mut out = [0u8; BATCH_BYTES];
    let written = encode(&mut out, &[entry(0, None, "line")]).unwrap();
    out[TRANSCRIPT_HEADER_BYTES + 1] = 0x80;
    assert_eq!(
        read(&out[..written]),
        Err(DecodeError::UnknownFlags { at: 0, flags: 0x80 })
    );
}

/// A slot the console never reached is zeroes and a slot read mid-write is two
/// lines spliced. Both leave the alphabet, and that is what keeps text no domain
/// printed out of whatever stores it.
#[test]
fn a_line_outside_the_console_alphabet_is_refused_by_name() {
    for byte in [0u8, 0x09, 0x0a, 0x0d, 0x1f, 0x7f, 0x80, 0xff] {
        let mut out = [0u8; BATCH_BYTES];
        let written = encode(&mut out, &[entry(0, None, "line")]).unwrap();
        out[TRANSCRIPT_HEADER_BYTES + TRANSCRIPT_ENTRY_HEADER_BYTES] = byte;
        assert_eq!(
            read(&out[..written]),
            Err(DecodeError::Unprintable { at: 0, byte }),
            "byte {byte:#04x}"
        );
    }
}

#[test]
fn every_printable_byte_crosses() {
    let alphabet: Vec<u8> = (0x20u8..=0x7e).collect();
    let mut out = [0u8; BATCH_BYTES];
    let written = encode(
        &mut out,
        &[Entry {
            origin: 0,
            unix_nanos: None,
            line: &alphabet,
        }],
    )
    .unwrap();
    let read = read(&out[..written]).expect("the whole alphabet");
    assert_eq!(read[0].2.as_bytes(), &alphabet[..]);
}

#[test]
fn a_batch_that_does_not_fit_is_refused_whole() {
    let entries = [entry(0, None, "line")];
    let mut out = [0u8; TRANSCRIPT_HEADER_BYTES];
    let error = encode(&mut out, &entries).expect_err("no room for the entry");
    assert!(matches!(error, EncodeError::OutOfSpace { .. }));
    assert!(
        out.iter().all(|byte| *byte == 0),
        "a refused batch wrote something"
    );
}

/// The batch a full relay hands over is the largest one there is, and it fits
/// the storage the writer sizes from the same constant.
#[test]
fn the_largest_batch_fits_its_own_bound() {
    let widest: Vec<u8> = core::iter::repeat_n(b'~', TRANSCRIPT_LINE_BYTES).collect();
    let entries: Vec<Entry<'_>> = (0..TRANSCRIPT_MAX_ENTRIES)
        .map(|index| Entry {
            origin: (index % 10) as u8,
            unix_nanos: Some(index as u64),
            line: &widest,
        })
        .collect();
    let mut out = [0u8; BATCH_BYTES];
    let written = encode(&mut out, &entries).expect("the bound is this batch");
    assert_eq!(written, BATCH_BYTES);
    assert_eq!(
        read(&out[..written]).expect("the largest batch").len(),
        TRANSCRIPT_MAX_ENTRIES
    );
}

/// Total over arbitrary bytes, which is what a reader of a recording needs: no
/// input panics, indexes out of range or loops on a length it was handed.
#[test]
fn arbitrary_bytes_are_a_refusal_or_a_batch() {
    let mut state = 0x1234_5678u32;
    for _ in 0..4_000 {
        let mut data = [0u8; 96];
        for byte in &mut data {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *byte = (state >> 16) as u8;
        }
        let _ = read(&data);
        data[0] = TRANSCRIPT_KIND;
        data[1] = TRANSCRIPT_VERSION;
        let _ = read(&data);
    }
}
