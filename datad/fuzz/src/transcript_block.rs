//! `wire`'s two new console-transcript ABIs, driven end to end: the relay region
//! the console publishes a printed line into, and the Custom Block a recording
//! carries a batch of them in.
//!
//! # Adversary
//!
//! Two, one per surface. The **byzantine neighbour protection domain** owns both
//! ends of the relay: the console writes the slots, their lengths, their origin
//! bytes and the producer cursor, while the recorder writes the consume cursor,
//! and neither may assume the other wrote anything a correct implementation
//! would. And on the block, **whoever holds a recording** — these bytes reach a
//! management server that stores them as an appliance's log, and a recording is
//! a file that leaves a customer's premises.
//!
//! # What is asserted, beyond not crashing
//!
//! * **Totality.** Every byte string is a batch of lines or a *named* refusal;
//!   no input faults, indexes out of range or loops on a length it was handed.
//! * **Padding is never a transcript, and neither is a reading.** Both share this
//!   block type and this enterprise number, so a reader that took either for a
//!   batch would store lines no domain printed.
//! * **The alphabet holds.** Every line handed to a caller is printable ASCII.
//!   That is what keeps a relay slot the console never reached — zeroes — and one
//!   read mid-write — two lines spliced — out of a store, and it is asserted on
//!   the way out rather than trusted from the way in.
//! * **A full relay never blocks and always counts.** Publishing answers, and
//!   every refusal moves the drop count by exactly one: the console must never
//!   wait on the domain that writes the medium, and a silent drop would be a gap
//!   in a transcript with nothing saying so.
//! * **Peeking releases nothing.** A batch composed and abandoned leaves the
//!   relay exactly as it was, which is what lets a recorder offer a block and
//!   lose no line when the recording defers it.
//! * **Round-trip.** Any batch this build encodes decodes back to the origins,
//!   instants and lines that went in.
//! * **Containment.** Nothing is written past the caller's slice, checked with
//!   guard bytes rather than trusted.

use arbitrary::Unstructured;
use wire::{
    BATCH_BYTES, FLAG_STAMPED, LogRelay, LogRelayConsume, RELAY_LINE_BYTES,
    TRANSCRIPT_HEADER_BYTES, TRANSCRIPT_KIND, TRANSCRIPT_MAX_ENTRIES, TranscriptDecodeError,
    TranscriptEncodeError, TranscriptEntry, decode_transcript, encode_transcript,
};

use crate::{any_index, any_u16, any_u64, next_op};

/// The guard byte the containment checks look for, on
/// [`crate::guard`](crate::guard)'s terms: a value no encoder writes, so a byte
/// that changed was written by the code under test.
const GUARD: u8 = 0xA5;

/// Storage a batch is composed into, with a guard region behind it.
///
/// Containment is measured against the slice the caller was *given* and not
/// against the length the encoder answered: a batch is zeroed over the whole
/// slice before it is written, deliberately, so a short one leaves zeroes rather
/// than whatever the buffer held before. What must never be touched is the region
/// past the slice.
struct Storage {
    bytes: [u8; BATCH_BYTES + 64],
    given: usize,
}

impl Storage {
    fn new() -> Self {
        Self {
            bytes: [GUARD; BATCH_BYTES + 64],
            given: 0,
        }
    }

    /// The slice a caller is given, of `len` bytes.
    fn room(&mut self, len: usize) -> &mut [u8] {
        self.given = len.min(BATCH_BYTES);
        let given = self.given;
        self.bytes.get_mut(..given).unwrap_or_default()
    }

    /// Whether every byte past the slice handed over is still the guard.
    fn contained(&self) -> bool {
        self.bytes
            .get(self.given..)
            .is_none_or(|tail| tail.iter().all(|byte| *byte == GUARD))
    }
}

/// Every line a batch yielded, as the harness compares them.
fn read(data: &[u8]) -> Result<Vec<(u8, Option<u64>, Vec<u8>)>, TranscriptDecodeError> {
    let mut lines = Vec::new();
    decode_transcript(data, |line| {
        // The property the store rests on, asserted on the way *out* of the
        // decoder: a line a caller is handed is printable ASCII, whatever the
        // bytes behind it were.
        assert!(
            line.line.iter().all(|byte| (0x20..=0x7e).contains(byte)),
            "a line outside the console alphabet reached a caller: {:?}",
            line.line
        );
        assert!(
            line.line.len() <= RELAY_LINE_BYTES,
            "a line longer than a relay slot reached a caller"
        );
        lines.push((line.origin, line.unix_nanos, line.line.to_vec()));
    })?;
    Ok(lines)
}

/// Drive both ABIs over one input.
pub fn transcript_block_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);

    // The decode side first, and over the whole input unreduced: this is the
    // shape a recording arrives in.
    let decoded = read(data);
    assert_padding_and_readings_are_not_transcripts(data, &decoded);

    // And then the two ABIs together, driven by the rest of the input.
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    let mut dropped = 0u32;
    let mut queued: Vec<(u8, Option<u64>, Vec<u8>)> = Vec::new();
    let mut into = [0u8; RELAY_LINE_BYTES];
    let mut storage = Storage::new();

    while let Some(op) = next_op(&mut unstructured) {
        match op % 4 {
            // Publish one line the adversary chose, of a length it chose.
            0 => {
                let origin = u8::try_from(any_index(&mut unstructured, 256)).unwrap_or(0);
                let stamped = any_u64(&mut unstructured);
                let carries = stamped.is_multiple_of(2);
                let len = (any_u16(&mut unstructured) as usize) % (RELAY_LINE_BYTES + 8);
                // Printable, because that is what a console renders; the decode
                // side above is where arbitrary bytes are driven.
                let line: Vec<u8> = (0..len)
                    .map(|at| 0x20u8.saturating_add((at % 95) as u8))
                    .collect();
                let instant = if carries { Some(stamped) } else { None };
                let before = writer.dropped();
                if writer.publish(origin, instant, &line) {
                    assert_eq!(writer.dropped(), before, "a taken line counted a drop");
                    queued.push((
                        origin,
                        instant,
                        line.get(..RELAY_LINE_BYTES).unwrap_or(&line).to_vec(),
                    ));
                } else {
                    // The hard requirement: a refusal is counted, exactly once,
                    // and publishing never waits.
                    dropped = dropped.saturating_add(1);
                    assert_eq!(writer.dropped(), dropped, "a refused line went uncounted");
                    assert_eq!(
                        reader.dropped_by_writer(),
                        dropped,
                        "the console's claim did not reach the recorder"
                    );
                }
                assert!(
                    queued.len() <= writer.capacity() as usize,
                    "the relay holds more than its capacity"
                );
            }
            // Compose a batch out of what the relay holds, offer it, and abandon
            // it: nothing may be released.
            1 => {
                let before = reader.queued();
                let taken = compose(&reader, &mut into, &mut storage, before);
                assert_eq!(
                    reader.queued(),
                    before,
                    "an abandoned batch released a slot the recorder never framed"
                );
                let _ = taken;
            }
            // Compose a batch, place it, and release exactly what it carried.
            2 => {
                let queued_now = reader.queued();
                let (len, count) = compose(&reader, &mut into, &mut storage, queued_now);
                assert!(storage.contained(), "a batch wrote past its storage");
                if count > 0 {
                    let body = storage.bytes.get(..len).unwrap_or_default();
                    let held = read(body).expect("a batch this build wrote");
                    assert_eq!(held.len(), count as usize);
                    let expected: Vec<_> = queued.drain(..count as usize).collect();
                    assert_eq!(held, expected, "a batch did not carry the lines it framed");
                    assert_eq!(reader.consume(count), count);
                }
            }
            // Encode an arbitrary batch into storage the adversary sized, and
            // check the refusal is whole and the write is contained.
            _ => {
                let room = (any_u16(&mut unstructured) as usize) % (BATCH_BYTES + 8);
                let entries = (any_index(&mut unstructured, TRANSCRIPT_MAX_ENTRIES + 4)) as usize;
                let line: Vec<u8> = (0..(any_u16(&mut unstructured) as usize % 64))
                    .map(|at| 0x20u8.saturating_add((at % 95) as u8))
                    .collect();
                let offered: Vec<TranscriptEntry<'_>> = (0..entries)
                    .map(|at| TranscriptEntry {
                        origin: (at % 10) as u8,
                        unix_nanos: (at.is_multiple_of(2)).then_some(at as u64),
                        line: &line,
                    })
                    .collect();
                let mut fresh = Storage::new();
                let room_slice = fresh.room(room);
                let answered = encode_transcript(room_slice, &offered);
                match answered {
                    Ok(len) => {
                        assert!(fresh.contained(), "an encoded batch wrote past its storage");
                        let held = read(fresh.bytes.get(..len).unwrap_or_default())
                            .expect("a batch this build wrote");
                        assert_eq!(
                            held.len(),
                            entries.min(TRANSCRIPT_MAX_ENTRIES),
                            "a batch carried a different number of lines than it took"
                        );
                    }
                    Err(TranscriptEncodeError::OutOfSpace { needed, capacity }) => {
                        assert!(
                            needed > capacity,
                            "a refusal that had the room it asked for"
                        );
                        // Nothing partial: a batch cut short is one a reader parses
                        // happily and takes lines out of.
                        assert!(
                            fresh.contained(),
                            "a refused batch wrote past the caller's storage"
                        );
                        assert!(
                            fresh
                                .bytes
                                .get(..fresh.given)
                                .is_none_or(|room| room.iter().all(|byte| *byte == GUARD)),
                            "a refused batch wrote into the caller's storage"
                        );
                    }
                }
            }
        }
    }
}

/// Compose a batch by peeking, answering its length and how many lines it holds.
fn compose(
    reader: &wire::LogRelayReader<'_>,
    into: &mut [u8; RELAY_LINE_BYTES],
    storage: &mut Storage,
    queued: u32,
) -> (usize, u32) {
    let mut batch = wire::TranscriptBatch::new(storage.room(BATCH_BYTES));
    let bounded = queued.min(TRANSCRIPT_MAX_ENTRIES as u32);
    for at in 0..bounded {
        let Some(line) = reader.peek(at, into) else {
            break;
        };
        let Some(text) = into.get(..line.len) else {
            break;
        };
        if !batch.push(&TranscriptEntry {
            origin: line.origin,
            unix_nanos: line.stamp(),
            line: text,
        }) {
            break;
        }
    }
    let count = u32::from(batch.entries());
    (batch.finish(), count)
}

/// The discriminator the whole block type rests on: padding and a metric reading
/// are never read as a transcript.
fn assert_padding_and_readings_are_not_transcripts(
    data: &[u8],
    decoded: &Result<Vec<(u8, Option<u64>, Vec<u8>)>, TranscriptDecodeError>,
) {
    match data.first().copied() {
        None | Some(0) => assert_eq!(
            decoded.as_ref().err(),
            Some(&TranscriptDecodeError::Padding),
            "padding was read as a transcript"
        ),
        Some(kind) if kind != TRANSCRIPT_KIND => assert!(
            matches!(
                decoded.as_ref().err(),
                Some(TranscriptDecodeError::UnknownKind { .. })
            ),
            "a block of another kind was read as a transcript"
        ),
        Some(_) => {
            // A leading byte that names a transcript: whatever follows, the
            // answer is a batch or a named refusal, and the header bound is what
            // makes a short input the second.
            if data.len() < TRANSCRIPT_HEADER_BYTES {
                assert!(
                    matches!(
                        decoded.as_ref().err(),
                        Some(TranscriptDecodeError::TooShort { .. })
                    ),
                    "a header this build cannot read was accepted"
                );
            }
        }
    }
    let _ = FLAG_STAMPED;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const TARGET: &str = "transcript_block";

    /// The shapes a cold fuzz run starts from, each named for what it
    /// demonstrates. Built from this build's own encoder rather than written out
    /// as bytes, so a change to the layout moves them rather than leaving files
    /// quietly meaning something else.
    fn demonstrations() -> Vec<(&'static str, Vec<u8>)> {
        let ready = b"LFW-PD time=unsynchronized domain=recorder state=ready".to_vec();
        let widest: Vec<u8> = core::iter::repeat_n(b'~', RELAY_LINE_BYTES).collect();
        let entries = [
            TranscriptEntry {
                origin: 6,
                unix_nanos: Some(1_785_443_220_000_000_000),
                line: &ready,
            },
            TranscriptEntry {
                origin: 0,
                unix_nanos: None,
                line: &widest,
            },
        ];
        let mut batch = [0u8; BATCH_BYTES];
        let len = encode_transcript(&mut batch, &entries).expect("its own length");
        let whole = batch.get(..len).unwrap_or_default().to_vec();

        let mut full = [0u8; BATCH_BYTES];
        let many: Vec<TranscriptEntry<'_>> = (0..TRANSCRIPT_MAX_ENTRIES)
            .map(|at| TranscriptEntry {
                origin: (at % 10) as u8,
                unix_nanos: Some(at as u64),
                line: &widest,
            })
            .collect();
        let full_len = encode_transcript(&mut full, &many).expect("the bound is this batch");

        let mut unprintable = whole.clone();
        if let Some(byte) = unprintable.get_mut(TRANSCRIPT_HEADER_BYTES + 12) {
            *byte = 0;
        }

        let mut wrong_version = whole.clone();
        if let Some(byte) = wrong_version.get_mut(1) {
            *byte = 0xff;
        }

        vec![
            // A whole batch this build wrote: the accept path, and the input the
            // header mutations below are derived from.
            ("batch", whole.clone()),
            // Every slot a relay holds, at the widest line the console renders:
            // the largest batch there can be, which is what the recorder's own
            // build-time assertion is about.
            ("full", full.get(..full_len).unwrap_or_default().to_vec()),
            // Text no console printed — a slot never reached, or two lines
            // spliced — which must be refused rather than stored.
            ("unprintable", unprintable),
            ("unknown-version", wrong_version),
            // The two other things this block type carries.
            ("padding-empty", vec![0u8; 1]),
            ("padding-zeroes", vec![0u8; 512]),
            ("metric-reading", vec![1u8, 1, 0, 0, 7, 0, 0, 0]),
            // A batch the bytes do not reach, at the header boundary.
            (
                "truncated",
                whole
                    .get(..TRANSCRIPT_HEADER_BYTES + 4)
                    .unwrap_or_default()
                    .to_vec(),
            ),
        ]
    }

    /// Rewrite every committed seed from the demonstration of the same name.
    ///
    /// Ignored by default and run by hand — `cargo test --manifest-path
    /// fuzz/Cargo.toml -- --ignored rewrite_the_committed_transcript_seeds` —
    /// after a deliberate change to the layout, which shifts every seed's byte
    /// image. The test below holds the corpus to the demonstrations afterwards,
    /// so this is a regeneration step and never a substitute for it.
    #[test]
    #[ignore = "regenerates the committed corpus; run by hand after a layout change"]
    fn rewrite_the_committed_transcript_seeds() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET);
        fs::create_dir_all(&dir).expect("the corpus directory");
        for (name, built) in demonstrations() {
            fs::write(dir.join(name), &built).expect("write the seed");
        }
    }

    #[test]
    fn every_transcript_demonstration_is_the_committed_seed_of_its_name() {
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

    /// The properties the whole discriminator rests on, over the shapes that
    /// actually arrive.
    #[test]
    fn no_committed_seed_of_another_kind_reads_as_a_transcript() {
        for (name, built) in demonstrations() {
            match name {
                "padding-empty" | "padding-zeroes" => {
                    assert_eq!(read(&built).err(), Some(TranscriptDecodeError::Padding));
                }
                "metric-reading" => assert!(matches!(
                    read(&built).err(),
                    Some(TranscriptDecodeError::UnknownKind { kind: 1 })
                )),
                "unprintable" => assert!(matches!(
                    read(&built).err(),
                    Some(TranscriptDecodeError::Unprintable { .. })
                )),
                _ => {}
            }
        }
    }
}
