//! `lfw_pcapng`'s block encoders, driven over the values a capture puts through
//! them and into buffers of every size around the block they must hold.
//!
//! # The adversary and the surface
//!
//! An encoder's arguments are first-party *values*, not somebody's bytes, so
//! this is not the usual parse surface — and that is exactly why it earns a
//! target rather than being left to the pass above it. Two of the numbers that
//! reach it are the network's:
//!
//! * **Untrusted network traffic**, one remove out. A frame's length on the
//!   wire becomes [`EnhancedPacket::original_len`] and its bytes become
//!   `captured`; both are chosen by whoever sent the frame, and the encoder
//!   subtracts, pads and length-prefixes them.
//! * **A byzantine neighbour PD** on the tap. The annotation the recorder
//!   attaches travels as a [`CustomBinary`] whose bytes came out of a shared
//!   slot a peer filled, and its length lands in a 16-bit Option Length field.
//!
//! A length that steered a write here would be a memory-safety fault in the one
//! domain holding a block device's capability, so the invariants below are
//! about *where the bytes went*, not about whether a call returned.
//!
//! # What the adversary may express here
//!
//! Every field of every block, unreduced: interface ids, timestamps, flags,
//! drop counts, packet ids, queue ids, speeds, snap lengths, link types,
//! verdict kinds and statistics counters are taken as full-width integers, and
//! `original_len` in particular is a whole `u32` so that
//! [`EncodeError::CapturedExceedsOriginal`] is reached from both sides. The
//! buffer offered is of arbitrary size, including shorter than the block, zero,
//! and exactly the block's length.
//!
//! # The two refusals this harness cannot reach, stated rather than implied
//!
//! [`EncodeError::PayloadTooLong`] needs more than `u32::MAX` captured octets
//! and [`EncodeError::BlockTooLong`] a block past the same bound. Both
//! parameters are a `&[u8]`, so their length is bounded by memory the harness
//! must actually hold rather than by a number it may state — the same argument
//! `free_list::MAX_PAYLOAD` records. Neither is unreachable *in principle*, and
//! neither is filtered out; they are simply beyond what a slice can be made to
//! be on this target. The crate's own host tests cover both by construction.
//!
//! # Lengths: a small band and a boundary band, and why that is not a filter
//!
//! Payload and option lengths are drawn either from `0..=2047` or from a narrow
//! band straddling 65535, where the 16-bit Option Length field flips. Nothing
//! about the *shape* of an input is excluded by that — the choice is which
//! lengths are worth spending a run on, and the only interesting one above two
//! kilobytes is the one where a refusal changes its mind. Drawing uniformly to
//! 70000 instead would spend almost every run memcpying and would reach the
//! boundary by accident, if at all.
//!
//! # What is asserted
//!
//! * **Containment.** Guard bytes surround every buffer offered, and a write
//!   never touches one. This is the claim that matters: the encoder is handed a
//!   length the network chose and a buffer the caller owns.
//! * **The measure and the write are one decision.** `*_len` and `write_*`
//!   agree exactly — the same refusal, or the same byte count — with
//!   [`EncodeError::OutOfSpace`] the single admitted difference, and admitted
//!   only when the buffer really was shorter than the measurement.
//! * **A refusal writes nothing.** Every rejected call leaves the whole buffer
//!   as it found it, which is what makes a caller's retry into a fresh buffer
//!   sound rather than hopeful.
//! * **Framing agrees with itself.** Both Block Total Length fields carry the
//!   same value, that value is the number of bytes written, and it is a
//!   multiple of four — so the block after it starts aligned.
//! * **A stream walks.** Every block written is concatenated and then walked by
//!   length alone, from the front, and the walk must land on exactly the end
//!   having counted exactly the blocks that were written. A reader has nothing
//!   else to navigate a capture by, so a block whose length does not carry to
//!   the next one truncates the file at that point.
//! * **Determinism.** Measuring one block twice yields one answer.

use std::{string::String, vec, vec::Vec};

use arbitrary::{Arbitrary as _, Unstructured};
use lfw_pcapng::{
    BLOCK_FRAMING_LEN, CustomBinary, EncodeError, EnhancedPacket, InterfaceDescription,
    InterfaceStatistics, LinkType, MIN_CUSTOM_BLOCK_LEN, SectionHeader, TimestampResolution,
    Verdict, VerdictKind, custom_block_len, enhanced_packet_len, interface_description_len,
    interface_statistics_len, section_header_len, write_custom_block, write_enhanced_packet,
    write_interface_description, write_interface_statistics, write_padding_block,
    write_section_header,
};

use crate::guard::Guarded;
use crate::{any_u16, any_u32, any_u64, next_op};

/// Blocks one input may build. A libFuzzer time budget: each block is exercised
/// against four buffers and the largest is some 70 kilobytes, so a larger count
/// buys memcpy rather than coverage.
const MAX_BLOCKS: usize = 16;

/// The alignment every pcapng block is padded to, restated here rather than
/// reached for in the crate under test: it is the format's rule, and a harness
/// that imported the encoder's own constant would agree with it by
/// construction however the encoder changed.
const ALIGNMENT: usize = 4;

/// The ordinary length band, where a block's cost is a few kilobytes at most.
const SMALL_LEN: usize = 2048;

/// The largest buffer the harness will offer, comfortably past the largest
/// block the bands below can produce.
const MAX_CAPACITY: usize = 128 * 1024;

/// Drive every block encoder over arbitrary values and arbitrary buffers.
pub fn pcapng_encode_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let mut stream: Vec<u8> = Vec::new();
    let mut blocks = 0usize;

    for _ in 0..MAX_BLOCKS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        let written = match op % 6 {
            0 => section_header(&mut unstructured),
            1 => interface_description(&mut unstructured),
            2 | 3 => enhanced_packet(&mut unstructured),
            4 => interface_statistics(&mut unstructured),
            _ => custom_or_padding(&mut unstructured),
        };
        if let Some(block) = written {
            stream.extend_from_slice(&block);
            blocks += 1;
        }
    }

    assert_stream_walks(&stream, blocks);
}

fn section_header(unstructured: &mut Unstructured<'_>) -> Option<Vec<u8>> {
    let hardware = text(unstructured);
    let os = text(unstructured);
    let application = text(unstructured);
    let schema = bytes(unstructured);
    let pen = any_u32(unstructured);
    let header = SectionHeader {
        hardware: optional(unstructured, &hardware),
        os: optional(unstructured, &os),
        application: optional(unstructured, &application),
        schema: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(CustomBinary { pen, data: &schema })
        } else {
            None
        },
    };
    exercise(
        "section header",
        unstructured,
        || section_header_len(&header),
        |out| write_section_header(out, &header),
    )
}

fn interface_description(unstructured: &mut Unstructured<'_>) -> Option<Vec<u8>> {
    let name = text(unstructured);
    let description = text(unstructured);
    let idb = InterfaceDescription {
        link_type: LinkType(any_u16(unstructured)),
        snap_len: any_u32(unstructured),
        name: optional(unstructured, &name),
        description: optional(unstructured, &description),
        speed: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(any_u64(unstructured))
        } else {
            None
        },
        // Every decimal resolution the octet admits, and the refusal past it:
        // `from_decimal_digits` is the only constructor, so a rejected digit
        // count leaves the field at the format's own default rather than
        // writing an ambiguous octet.
        timestamp_resolution: TimestampResolution::from_decimal_digits(
            u8::arbitrary(unstructured).unwrap_or(0),
        )
        .unwrap_or(TimestampResolution::MICROSECONDS),
    };
    exercise(
        "interface description",
        unstructured,
        || interface_description_len(&idb),
        |out| write_interface_description(out, &idb),
    )
}

fn enhanced_packet(unstructured: &mut Unstructured<'_>) -> Option<Vec<u8>> {
    let captured = bytes(unstructured);
    let verdict_data = bytes(unstructured);
    let custom_data = bytes(unstructured);
    let comment = text(unstructured);
    let epb = EnhancedPacket {
        interface_id: any_u32(unstructured),
        timestamp: any_u64(unstructured),
        captured: &captured,
        // Unreduced, and deliberately unrelated to `captured.len()`: this is
        // the frame's length as the wire stated it, so the two sides of
        // `CapturedExceedsOriginal` are both ordinary inputs.
        original_len: any_u32(unstructured),
        flags: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(any_u32(unstructured))
        } else {
            None
        },
        drop_count: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(any_u64(unstructured))
        } else {
            None
        },
        packet_id: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(any_u64(unstructured))
        } else {
            None
        },
        queue: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(any_u32(unstructured))
        } else {
            None
        },
        verdict: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(Verdict {
                kind: VerdictKind(u8::arbitrary(unstructured).unwrap_or(0)),
                data: &verdict_data,
            })
        } else {
            None
        },
        custom: if bool::arbitrary(unstructured).unwrap_or(false) {
            Some(CustomBinary {
                pen: any_u32(unstructured),
                data: &custom_data,
            })
        } else {
            None
        },
        comment: optional(unstructured, &comment),
    };
    exercise(
        "enhanced packet",
        unstructured,
        || enhanced_packet_len(&epb),
        |out| write_enhanced_packet(out, &epb),
    )
}

fn interface_statistics(unstructured: &mut Unstructured<'_>) -> Option<Vec<u8>> {
    let isb = InterfaceStatistics {
        interface_id: any_u32(unstructured),
        timestamp: any_u64(unstructured),
        start_time: any_u64(unstructured),
        end_time: any_u64(unstructured),
        received: any_u64(unstructured),
        dropped: any_u64(unstructured),
    };
    exercise(
        "interface statistics",
        unstructured,
        || interface_statistics_len(&isb),
        |out| write_interface_statistics(out, &isb),
    )
}

/// The two blocks that share a type code: a custom block carrying data, and the
/// padding block that fills a sector's tail with a run of zeros.
fn custom_or_padding(unstructured: &mut Unstructured<'_>) -> Option<Vec<u8>> {
    if bool::arbitrary(unstructured).unwrap_or(false) {
        let data = bytes(unstructured);
        let body = CustomBinary {
            pen: any_u32(unstructured),
            data: &data,
        };
        return exercise(
            "custom block",
            unstructured,
            || custom_block_len(&body),
            |out| write_custom_block(out, &body),
        );
    }

    // A padding block's length is the whole of its input, and it is the one
    // encoder with no `*_len` companion — the length asked for *is* the
    // measurement — so its two structural refusals are modelled here instead.
    let len = length(unstructured);
    exercise(
        "padding block",
        unstructured,
        || {
            if !len.is_multiple_of(ALIGNMENT) {
                return Err(EncodeError::BlockNotAligned { len });
            }
            if len < MIN_CUSTOM_BLOCK_LEN {
                return Err(EncodeError::BlockTooShort { len });
            }
            Ok(len)
        },
        |out| write_padding_block(out, len),
    )
}

/// Measure a block, write it into buffers of several sizes, and hold both
/// against each other and against the framing rules.
///
/// Returns the block's bytes where some buffer was long enough for it, so the
/// caller can grow the stream the walk at the end navigates.
fn exercise<M, W>(
    label: &str,
    unstructured: &mut Unstructured<'_>,
    measure: M,
    write: W,
) -> Option<Vec<u8>>
where
    M: Fn() -> Result<usize, EncodeError>,
    W: Fn(&mut [u8]) -> Result<usize, EncodeError>,
{
    let measured = measure();
    assert_eq!(
        measured,
        measure(),
        "{label}: measuring one block twice gave two answers"
    );

    let mut block = None;
    for capacity in capacities(unstructured, measured) {
        let mut guarded = Guarded::new(capacity);
        let outcome = write(guarded.out());
        guarded.assert_margins_intact(label);

        match (measured, outcome) {
            (Err(refused), Ok(bytes)) => panic!(
                "{label}: the measurement refused this block with {refused:?}, but writing it \
                 into {capacity} bytes produced {bytes}"
            ),
            (Err(refused), Err(also)) => {
                assert_eq!(
                    refused, also,
                    "{label}: the measurement and the write refused the same block differently"
                );
                assert!(
                    guarded.is_untouched(),
                    "{label}: a refused block left bytes in the caller's buffer"
                );
            }
            (
                Ok(needed),
                Err(EncodeError::OutOfSpace {
                    needed: says,
                    capacity: had,
                }),
            ) => {
                assert!(
                    needed > capacity,
                    "{label}: a {needed}-byte block was refused for want of space in {capacity} \
                     bytes"
                );
                assert_eq!(
                    says, needed,
                    "{label}: the refusal named a size the measurement disagrees with"
                );
                assert_eq!(
                    had, capacity,
                    "{label}: the refusal named a capacity the caller did not offer"
                );
                assert!(
                    guarded.is_untouched(),
                    "{label}: a block refused for space left bytes in the caller's buffer"
                );
            }
            (Ok(_), Err(other)) => panic!(
                "{label}: the measurement accepted this block, but writing it into {capacity} \
                 bytes refused with {other:?}"
            ),
            (Ok(needed), Ok(bytes)) => {
                assert_eq!(
                    bytes, needed,
                    "{label}: the write filled {bytes} bytes of a block measured at {needed}"
                );
                assert!(
                    capacity >= needed,
                    "{label}: a {needed}-byte block was written into {capacity} bytes"
                );
                assert!(
                    guarded.touched_len() <= bytes,
                    "{label}: the write reported {bytes} bytes but reached {} into the buffer",
                    guarded.touched_len()
                );
                let written = guarded.written(bytes);
                assert_framing(label, written);
                if block.is_none() {
                    block = Some(written.to_vec());
                }
            }
        }
    }
    block
}

/// The buffer sizes one block is offered: one the fuzzer chose outright, and —
/// where the block could be measured at all — the three straddling its exact
/// length, which is where the space refusal changes its mind.
///
/// Additive, never a replacement: the arbitrary capacity is always among them,
/// so no size the fuzzer can name is taken away by the targeting.
fn capacities(
    unstructured: &mut Unstructured<'_>,
    measured: Result<usize, EncodeError>,
) -> Vec<usize> {
    // Usually a small buffer, occasionally one larger than any block these
    // bands can produce. Drawing uniformly to `MAX_CAPACITY` instead spent the
    // whole time budget zeroing margins — a hundred executions a second where
    // this reaches thousands — and bought nothing, because the capacities that
    // decide anything are the three around the block's own length and they are
    // always among these.
    let ceiling = if any_u32(unstructured) % 8 == 0 {
        MAX_CAPACITY
    } else {
        SMALL_LEN * 2
    };
    let mut sizes = vec![(any_u32(unstructured) as usize) % (ceiling + 1)];
    if let Ok(needed) = measured
        && needed <= MAX_CAPACITY
    {
        sizes.push(needed.saturating_sub(1));
        sizes.push(needed);
        sizes.push(needed + ALIGNMENT);
    }
    sizes
}

/// A block frames itself: both Block Total Length fields carry the byte count,
/// and that count is aligned so the block after it starts on a boundary.
fn assert_framing(label: &str, block: &[u8]) {
    assert!(
        block.len() >= BLOCK_FRAMING_LEN,
        "{label}: a {}-byte block cannot carry its own framing",
        block.len()
    );
    assert!(
        block.len().is_multiple_of(ALIGNMENT),
        "{label}: a {}-byte block leaves the next one unaligned",
        block.len()
    );
    let leading = total_length_at(block, 4).expect("a framed block carries a leading length");
    let trailing =
        total_length_at(block, block.len() - 4).expect("a framed block carries a trailing length");
    assert_eq!(
        leading, trailing,
        "{label}: the two Block Total Length fields disagree, so a reader walking backwards and \
         one walking forwards see different blocks"
    );
    assert_eq!(
        leading,
        block.len(),
        "{label}: the Block Total Length is not the number of bytes written"
    );
}

/// Read a Block Total Length field, or `None` where the four octets are not
/// wholly inside `block`.
fn total_length_at(block: &[u8], at: usize) -> Option<usize> {
    let field: [u8; 4] = block.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(field) as usize)
}

/// Walk the concatenated blocks by their lengths alone, which is all a reader
/// has, and require the walk to land on exactly the end having seen exactly the
/// blocks that were written.
fn assert_stream_walks(stream: &[u8], blocks: usize) {
    let mut at = 0usize;
    let mut seen = 0usize;
    // One iteration per block plus a final refutation: `at` strictly increases
    // by at least `BLOCK_FRAMING_LEN` each time, so the loop is bounded by the
    // stream rather than by a cap this harness would otherwise hide behind.
    while at < stream.len() {
        let total = total_length_at(stream, at + 4)
            .unwrap_or_else(|| panic!("a block at {at} has no length field inside the stream"));
        assert!(
            total >= BLOCK_FRAMING_LEN,
            "a block at {at} claims {total} bytes, which cannot frame itself"
        );
        assert!(
            total.is_multiple_of(ALIGNMENT),
            "a block at {at} claims {total} bytes, leaving the next one unaligned"
        );
        let end = at
            .checked_add(total)
            .expect("a block length past the address space");
        assert!(
            end <= stream.len(),
            "a block at {at} claims {total} bytes and walks past the end of the stream"
        );
        let trailing = total_length_at(stream, end - 4)
            .expect("the trailing length lies inside a block the leading one admitted");
        assert_eq!(
            trailing, total,
            "the block at {at} ends with a length other than the one it began with"
        );
        at = end;
        seen += 1;
    }
    assert_eq!(
        at,
        stream.len(),
        "walking the stream by block lengths overshot its end"
    );
    assert_eq!(
        seen, blocks,
        "the walk found {seen} blocks in a stream {blocks} were written into"
    );
}

/// A length in one of the two bands the module header justifies.
fn length(unstructured: &mut Unstructured<'_>) -> usize {
    if any_u32(unstructured) % 16 == 0 {
        // Straddling 65535, where the 16-bit Option Length field decides
        // whether a value is expressible at all.
        let offset = (any_u32(unstructured) % 32) as usize;
        return usize::from(u16::MAX).saturating_sub(16) + offset;
    }
    (any_u32(unstructured) as usize) % (SMALL_LEN + 1)
}

/// A run of bytes of one of those lengths. One repeated byte rather than a
/// distinct one per position: the encoder copies them opaquely, so what varies
/// usefully is how many there are and not which they are, and materialising
/// sixty-five thousand distinct bytes would spend the input on nothing.
fn bytes(unstructured: &mut Unstructured<'_>) -> Vec<u8> {
    let len = length(unstructured);
    let byte = u8::arbitrary(unstructured).unwrap_or(0);
    vec![byte; len]
}

/// A text option's value, of one of those lengths.
///
/// Built from a repeated ASCII byte so it is a `&str` by construction: the
/// parameter is `&str`, so a non-UTF-8 value is not something any caller —
/// first-party or not — can hand this encoder, and manufacturing one would be
/// modelling an authority nobody has.
fn text(unstructured: &mut Unstructured<'_>) -> String {
    let len = length(unstructured);
    let byte = u8::arbitrary(unstructured).unwrap_or(b'a');
    // Every printable ASCII code point, so an option's bytes vary without
    // leaving what a `&str` can hold.
    let letter = char::from(0x20 + (byte % 0x5F));
    core::iter::repeat_n(letter, len).collect()
}

/// Present the value or leave the option out, so a block with no options at all
/// — which skips the whole option area and its terminator — is reachable.
fn optional<'a>(unstructured: &mut Unstructured<'_>, value: &'a str) -> Option<&'a str> {
    if bool::arbitrary(unstructured).unwrap_or(false) {
        Some(value)
    } else {
        None
    }
}
