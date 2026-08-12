//! `lfw_metrics`' metric-reading codec, against arbitrary bytes out of a
//! recording and against arbitrary readings out of a peer's region.
//!
//! # Adversary
//!
//! Two, one per direction. On the **decode** side, whoever holds a recording:
//! these bytes reach a management server that ingests them into a time-series
//! store, and a recording is a file that leaves a customer's premises. On the
//! **encode** side, a **byzantine neighbour protection domain**, every counter
//! in a reading having been stored by another domain and handed across the relay
//! page.
//!
//! # What is asserted, beyond not crashing
//!
//! * **Totality.** Every byte string is a reading or a *named* refusal; no
//!   input faults, indexes out of range or reads past what arrived.
//! * **Padding is never a reading.** The padding block a recording is filled out
//!   with shares this block type and this enterprise number, and its data is
//!   zeroes or nothing at all. Every such input must decode as padding — the
//!   property every recording ever written rests on, since a padding block read
//!   as a reading would put four hundred fabricated numbers into a store.
//! * **A foreign catalogue is refused whole.** A reading whose fingerprint is
//!   not this build's yields no values at all, rather than values mapped through
//!   the wrong table: a wrong number on an operator's dashboard is worse than a
//!   missing one, and nothing downstream can tell the two apart.
//! * **Round-trip.** Any reading this build encodes decodes back to exactly what
//!   went in, for arbitrary counter values including `u64::MAX`.
//! * **Refusal, never truncation.** An output under the declared length either
//!   holds a whole reading or is refused with nothing written, and the refusal
//!   names what was needed against what was offered.
//! * **Containment.** Nothing is written past the caller's slice, checked with
//!   guard bytes rather than trusted.

use arbitrary::Unstructured;
use lfw_metrics::{
    MetricSnapshot, SNAPSHOT_BYTES, SNAPSHOT_HEADER_BYTES, SNAPSHOT_KIND, SNAPSHOT_SLOTS,
    SnapshotDecodeError, SnapshotEncodeError, decode_snapshot, encode_snapshot,
};

use crate::{any_u32, next_op};

/// A guard run past the caller's slice, so an overrun is caught by inspection
/// rather than by whatever it happened to corrupt.
const GUARD: usize = 64;

pub fn metric_snapshot_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);

    decode_arbitrary_bytes(data);
    decode_a_derived_reading(&mut unstructured, data);
    round_trip_arbitrary_values(&mut unstructured);
    encode_into_arbitrary_storage(&mut unstructured);
}

/// The input as it stands, which is what a block in a recording is: bytes
/// somebody else chose, of whatever length they chose.
fn decode_arbitrary_bytes(data: &[u8]) {
    let answer = decode_snapshot(data);
    assert_eq!(
        answer,
        decode_snapshot(data),
        "decoding one input twice gave two answers"
    );
    match answer {
        Ok(reading) => {
            assert!(
                data.len() >= SNAPSHOT_BYTES,
                "a reading came out of {} bytes",
                data.len()
            );
            assert_eq!(data.first().copied(), Some(SNAPSHOT_KIND));
            // Every slot is exactly the eight bytes at its own offset: a reading
            // that shifted one slot would report one series' number under
            // another's name, which no consumer could notice.
            for (slot, value) in reading.values.iter().enumerate() {
                let at = SNAPSHOT_HEADER_BYTES + slot * 8;
                let bytes: [u8; 8] = data[at..at + 8].try_into().expect("inside the reading");
                assert_eq!(*value, u64::from_le_bytes(bytes), "slot {slot}");
            }
        }
        Err(SnapshotDecodeError::Padding) => assert_eq!(
            data.first().copied().unwrap_or(0),
            0,
            "a non-zero leading byte was read as padding"
        ),
        Err(_named) => {}
    }

    // The padding a recording actually holds, at every length one can take.
    // `write_padding_block` can emit a block with no data at all, which is why
    // the empty case is here and not only the zero-filled ones.
    for len in [0, 1, 4, SNAPSHOT_HEADER_BYTES, SNAPSHOT_BYTES, 4096] {
        assert_eq!(
            decode_snapshot(&vec![0u8; len]),
            Err(SnapshotDecodeError::Padding),
            "{len} zero bytes were not read as padding"
        );
    }
}

/// A reading this build wrote, with the input's own bytes laid over its header —
/// which is what reaches the *interesting* refusals. A uniform blob is `Padding`
/// or `UnknownKind` for all but a vanishing fraction of inputs, so the
/// fingerprint, version and count checks would never be driven by chance.
fn decode_a_derived_reading(unstructured: &mut Unstructured<'_>, data: &[u8]) {
    let mut body = [0u8; SNAPSHOT_BYTES];
    encode_snapshot(&mut body, 0, &[]).expect("its own length");
    let held = decode_snapshot(&body).expect("this build's own reading");

    for (slot, byte) in data.iter().take(SNAPSHOT_HEADER_BYTES).enumerate() {
        // One byte of the header at a time, so each refusal is reached by the
        // shortest input that can reach it.
        let mut derived = body;
        derived[slot] = *byte;
        match decode_snapshot(&derived) {
            Ok(reading) => assert_eq!(
                reading.values, held.values,
                "a header byte changed what the slots read"
            ),
            Err(SnapshotDecodeError::ForeignCatalogue { stated, held: mine }) => {
                assert_ne!(stated, mine, "a matching fingerprint was called foreign");
            }
            Err(_named) => {}
        }
    }

    // And a wholly arbitrary header over a real body, which is where two fields
    // disagreeing at once is reached.
    let mut derived = body;
    for slot in 0..SNAPSHOT_HEADER_BYTES {
        let Some(byte) = next_op(unstructured) else {
            break;
        };
        derived[slot] = byte;
    }
    let _ = decode_snapshot(&derived);
    // Truncation at every boundary that matters, which must never read a slot
    // the bytes do not carry.
    for len in [
        0,
        1,
        SNAPSHOT_HEADER_BYTES - 1,
        SNAPSHOT_HEADER_BYTES,
        SNAPSHOT_BYTES - 1,
    ] {
        match decode_snapshot(&body[..len]) {
            Ok(_reading) => panic!("a reading came out of {len} bytes"),
            Err(_named) => {}
        }
    }
}

/// Every bit pattern of every slot is a number a domain may have counted, so a
/// reading of arbitrary values must come back exactly.
fn round_trip_arbitrary_values(unstructured: &mut Unstructured<'_>) {
    let mut values = [0u64; SNAPSHOT_SLOTS];
    'fill: for slot in values.iter_mut() {
        if next_op(unstructured).is_none() {
            break 'fill;
        }
        // Two `u32`s rather than a `u64`, so a short input still reaches the top
        // of the range through the high half.
        *slot = (u64::from(any_u32(unstructured)) << 32) | u64::from(any_u32(unstructured));
    }
    let unix_nanos = (u64::from(any_u32(unstructured)) << 32) | u64::from(any_u32(unstructured));

    let mut out = [0u8; SNAPSHOT_BYTES];
    let written = encode_snapshot(&mut out, unix_nanos, &values).expect("its own length");
    assert_eq!(written, SNAPSHOT_BYTES);
    assert_ne!(out[0], 0, "a reading that reads as padding");

    let decoded = decode_snapshot(&out).expect("this build's own reading");
    assert_eq!(decoded.unix_nanos, unix_nanos);
    assert_eq!(decoded.values, values);

    // Every slot names a series, and one past the table names none: a reader
    // walking by index must never be handed a name for a slot that has none.
    for slot in 0..SNAPSHOT_SLOTS {
        assert!(MetricSnapshot::series(slot).is_some(), "slot {slot}");
    }
    assert!(MetricSnapshot::series(SNAPSHOT_SLOTS).is_none());

    // A catalogue this build cannot map yields nothing rather than the wrong
    // numbers under the right names.
    let mut foreign = out;
    foreign[4] ^= 0xff;
    match decode_snapshot(&foreign) {
        Err(SnapshotDecodeError::ForeignCatalogue { .. }) => {}
        Ok(_reading) => panic!("a foreign catalogue was mapped through this build's table"),
        Err(other) => panic!("a foreign catalogue was refused as {other:?}"),
    }
}

/// The output is the caller's storage and its length is not this codec's to
/// choose, so a refusal must be total and must write nothing a caller could send.
fn encode_into_arbitrary_storage(unstructured: &mut Unstructured<'_>) {
    let capacity = (any_u32(unstructured) as usize) % (SNAPSHOT_BYTES + 32);
    let mut storage = vec![0xA5u8; capacity + GUARD];
    let (out, guard) = storage.split_at_mut(capacity);

    match encode_snapshot(out, 7, &[1, 2, 3]) {
        Ok(written) => {
            assert_eq!(written, SNAPSHOT_BYTES);
            assert!(capacity >= SNAPSHOT_BYTES);
            let reading = decode_snapshot(out).expect("this build's own reading");
            assert_eq!(reading.unix_nanos, 7);
            assert_eq!(reading.values.get(..3), Some(&[1u64, 2, 3][..]));
            assert!(
                reading.values.iter().skip(3).all(|value| *value == 0),
                "slots the reading did not reach carry something"
            );
            // Bytes past the reading are the caller's and stay untouched.
            assert!(out[SNAPSHOT_BYTES..].iter().all(|byte| *byte == 0xA5));
        }
        Err(SnapshotEncodeError::OutOfSpace {
            needed,
            capacity: offered,
        }) => {
            assert_eq!(needed, SNAPSHOT_BYTES);
            assert_eq!(offered, capacity);
            assert!(
                out.iter().all(|byte| *byte == 0xA5),
                "a refused encode wrote a partial reading"
            );
        }
    }
    assert!(
        guard.iter().all(|byte| *byte == 0xA5),
        "the encoder wrote past the storage it was given"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const TARGET: &str = "metric_snapshot";

    /// The shapes a cold fuzz run starts from, each named for what it
    /// demonstrates. Built from this build's own encoder rather than written out
    /// as bytes, so a change to the reading's layout — or to the catalogue behind
    /// its fingerprint — moves them rather than leaving four files quietly
    /// meaning something else.
    fn demonstrations() -> Vec<(&'static str, Vec<u8>)> {
        let mut reading = [0u8; SNAPSHOT_BYTES];
        let values: Vec<u64> = (0..SNAPSHOT_SLOTS as u64)
            .map(|slot| slot * 7 + 1)
            .collect();
        encode_snapshot(&mut reading, 1_785_443_220_000_000_000, &values).expect("its own length");

        let mut saturated = [0u8; SNAPSHOT_BYTES];
        encode_snapshot(&mut saturated, u64::MAX, &[u64::MAX; 16]).expect("its own length");

        let mut foreign = reading;
        foreign[4] ^= 0xff;

        let mut wrong_version = reading;
        wrong_version[1] = 0xff;

        vec![
            // A whole reading this build wrote: the accept path, and the input
            // every header mutation below is derived from.
            ("reading", reading.to_vec()),
            // Counters at the top of their range, which is what a byzantine
            // neighbour can store and what a `Float64` consumer must reckon with.
            ("saturated", saturated.to_vec()),
            // A recording from another build: refused whole rather than mapped.
            ("foreign-catalogue", foreign.to_vec()),
            ("unknown-version", wrong_version.to_vec()),
            // The padding a recording is filled out with, at the two lengths that
            // matter: a block with no data at all, and one whose data is zeroes.
            ("padding-empty", vec![0u8; 1]),
            ("padding-zeroes", vec![0u8; SNAPSHOT_BYTES]),
            // A reading the bytes do not reach, at the header boundary.
            ("truncated", reading[..SNAPSHOT_HEADER_BYTES].to_vec()),
        ]
    }

    /// Rewrite every committed seed from the demonstration of the same name.
    ///
    /// Ignored by default and run by hand — `cargo test --manifest-path
    /// fuzz/Cargo.toml -- --ignored rewrite_the_committed_seeds` — after a
    /// deliberate change to the reading's layout or to the catalogue behind its
    /// fingerprint, either of which shifts every seed's byte image. The test
    /// below holds the corpus to the demonstrations afterwards, so this is a
    /// regeneration step and never a substitute for it.
    #[test]
    #[ignore = "regenerates the committed corpus; run by hand after a layout change"]
    fn rewrite_the_committed_seeds() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET);
        fs::create_dir_all(&dir).expect("the corpus directory");
        for (name, built) in demonstrations() {
            fs::write(dir.join(name), &built).expect("write the seed");
        }
    }

    #[test]
    fn every_demonstration_is_the_committed_seed_of_its_name() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET);
        for (name, built) in demonstrations() {
            let committed = fs::read(dir.join(name))
                .unwrap_or_else(|_| panic!("seed {name} is committed for {TARGET}"));
            assert_eq!(
                committed, built,
                "seed {name} is not what this build encodes"
            );
        }
    }

    /// The one property the whole discriminator rests on, asserted over the two
    /// shapes a padding block actually takes.
    #[test]
    fn every_committed_padding_seed_decodes_as_padding() {
        for (name, built) in demonstrations() {
            if name.starts_with("padding") {
                assert_eq!(decode_snapshot(&built), Err(SnapshotDecodeError::Padding));
            }
        }
    }
}
