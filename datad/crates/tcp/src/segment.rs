//! The TCP header on the wire: read into fields, and composed back out of them.
//!
//! Every byte reaching [`Segment::parse`] was chosen by whatever is attached to
//! the port, so the parser refuses rather than believes: a data offset that
//! names a header longer than the segment, an option whose length walks off the
//! end or claims to be shorter than its own kind, a checksum that does not
//! verify. Each is a typed error carrying the value that caused it.
//!
//! # Why the checksum is verified before any field is used
//!
//! The pseudo-header (RFC 793 section 3.1) covers the two addresses and the segment
//! length, which is what makes a segment's checksum a statement about *which
//! connection it belongs to*. Verifying it first is therefore not defensive
//! ordering: a segment whose checksum fails may have had its ports or its
//! sequence number corrupted, and matching a corrupt 4-tuple against the
//! connection table would let a bit flip in one connection's payload arrive as
//! another connection's data.
//!
//! # The option framework, and what it is a framework for
//!
//! Three options are read: maximum segment size (RFC 793), window scale
//! (RFC 7323 section 2) and SACK-permitted (RFC 2018). The first two are negotiated;
//! the third is recorded and acted on by nothing, because selective
//! acknowledgement needs a reassembly queue this stack deliberately does not
//! have (see the crate header). Recording it is what makes adding SACK a change
//! to the state machine rather than a change to the parser. Every other kind is
//! skipped by its own length, which is the only way a receiver can be forward
//! compatible with an option it has never heard of.

use net_headers::{Checksum, Ipv4Address, Protocol};

use crate::seq::SeqNumber;

/// A TCP header with no options, and so the smallest a segment can be.
pub const TCP_HEADER_LEN: usize = 20;

/// The longest header a 4-bit data offset can name: fifteen 32-bit words.
pub const MAX_TCP_HEADER_LEN: usize = 60;

/// The option area this stack composes: a maximum segment size and a NOP-padded
/// window scale, which is every option it sends.
const MAX_OPTION_LEN: usize = 8;

/// Where the checksum field sits inside the header, and so the two bytes summed
/// as zero when one is computed (RFC 1071).
const CHECKSUM_AT: usize = 16;

/// The smallest header a data offset may name, in 32-bit words.
const MIN_DATA_OFFSET: u8 = 5;

const OPTION_END: u8 = 0;
const OPTION_NOP: u8 = 1;
const OPTION_MSS: u8 = 2;
const OPTION_WINDOW_SCALE: u8 = 3;
const OPTION_SACK_PERMITTED: u8 = 4;

const OPTION_MSS_LEN: u8 = 4;
const OPTION_WINDOW_SCALE_LEN: u8 = 3;

/// The largest shift RFC 7323 section 2.2 permits a window scale to carry. A peer
/// naming more is clamped to it rather than refused, which is what that section
/// requires of a receiver.
pub const MAX_WINDOW_SCALE: u8 = 14;

/// The control bits, as one value rather than eight booleans.
///
/// A newtype rather than a `bool` per flag because the combination is what
/// decides: RFC 793 section 3.9 dispatches on `SYN` with and without `ACK`, on `RST`
/// alone, and on `FIN` beside data, and a struct of booleans makes each of those
/// a conjunction spelled out at every call site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every flag in `other` is set here.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The options a segment carried that this stack reads.
///
/// Absent rather than defaulted: RFC 7323 section 2.2 makes window scaling apply only
/// when *both* ends offered it, so "no option" and "a scale of zero" are
/// different facts and an `Option` is what keeps them apart.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub mss: Option<u16>,
    /// Already clamped to [`MAX_WINDOW_SCALE`], per RFC 7323 section 2.3.
    pub window_scale: Option<u8>,
    /// Read and recorded; nothing negotiates it. See the module header.
    pub sack_permitted: bool,
}

/// Why a segment is not one this stack will read.
///
/// Every variant carries the value that refused it, so a refusal is attributable
/// to a byte the peer sent rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentError {
    /// Fewer bytes than a header with no options.
    TooShort { got: usize },
    /// A data offset below the five words a header occupies.
    DataOffsetTooSmall { data_offset: u8 },
    /// A header longer than the segment carrying it.
    DataOffsetExceedsSegment { data_offset: u8, got: usize },
    /// The pseudo-header checksum does not verify.
    ChecksumInvalid { found: u16, computed: u16 },
    /// An option whose length field runs past the end of the option area.
    OptionTruncated { kind: u8, len: u8, remaining: usize },
    /// An option whose length cannot describe the option it names: below two,
    /// which no option but `END` and `NOP` can be, or wrong for a kind whose
    /// length is fixed.
    OptionLengthInvalid { kind: u8, len: u8 },
    /// A second occurrence of an option this stack reads. RFC 793 and RFC 7323
    /// give each of them one appearance in a header; taking the last of several
    /// would let a peer decide which of two values a middlebox and this end
    /// each negotiated under.
    OptionRepeated { kind: u8 },
}

/// One received segment, every field this stack reads decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: SeqNumber,
    pub acknowledgement: SeqNumber,
    pub flags: Flags,
    /// As it appeared on the wire, unscaled: the shift is a property of the
    /// connection rather than of the segment, so applying it here would need
    /// state this type does not have.
    pub window: u16,
    pub options: Options,
    pub payload: &'a [u8],
}

/// The destination port a segment claims, read **before anything about it has
/// been verified**.
///
/// It exists for one purpose and has exactly one safe use: choosing which
/// [`TcpStack`](crate::TcpStack) is handed the bytes, where a caller runs more
/// than one on one address. Every stack then parses the segment itself —
/// checksum over the pseudo-header first, as
/// [`Segment::parse`](Segment::parse) does — and refuses a destination that is
/// not its own, so a peer that lies here reaches a stack that refuses it rather
/// than one that believes it. **Nothing else may act on this value**: it is two
/// bytes a peer chose out of a datagram nothing has yet judged.
///
/// `None` for bytes too short to carry the field, which a caller hands to
/// whichever stack it would have used anyway — the parse there counts it as the
/// malformed segment it is, so no segment goes uncounted for being unreadable
/// here.
#[must_use]
pub const fn peeked_destination_port(segment: &[u8]) -> Option<u16> {
    // Bounded by the pattern rather than by an index: the two bytes are the
    // second field of the fixed header, and a shorter run has none.
    let [_, _, high, low, ..] = *segment else {
        return None;
    };
    Some(u16::from_be_bytes([high, low]))
}

impl<'a> Segment<'a> {
    /// The sequence space this segment occupies: its payload plus the phantom
    /// byte each of `SYN` and `FIN` takes (RFC 793 section 3.3).
    ///
    /// `u32` rather than `usize` because it is added to a sequence number, and
    /// the widening is exact: a payload is bounded by an IPv4 datagram.
    #[must_use]
    pub fn sequence_length(&self) -> u32 {
        // Lossless: `payload` is a subslice of one datagram, so at most 65 515
        // bytes.
        let payload = self.payload.len() as u32;
        payload
            .saturating_add(u32::from(self.flags.contains(Flags::SYN)))
            .saturating_add(u32::from(self.flags.contains(Flags::FIN)))
    }

    /// Read a segment addressed from `source` to `destination`, verifying its
    /// checksum over the pseudo-header those two addresses form.
    ///
    /// # Errors
    /// [`SegmentError`], naming the field and the value that refused it.
    pub fn parse(
        source: Ipv4Address,
        destination: Ipv4Address,
        bytes: &'a [u8],
    ) -> Result<Self, SegmentError> {
        let Some((header, rest)) = bytes.split_first_chunk::<TCP_HEADER_LEN>() else {
            return Err(SegmentError::TooShort { got: bytes.len() });
        };
        let [
            sp_high,
            sp_low,
            dp_high,
            dp_low,
            seq0,
            seq1,
            seq2,
            seq3,
            ack0,
            ack1,
            ack2,
            ack3,
            offset_reserved,
            flags,
            win_high,
            win_low,
            ck_high,
            ck_low,
            _urgent_high,
            _urgent_low,
        ] = *header;

        let data_offset = offset_reserved >> 4;
        if data_offset < MIN_DATA_OFFSET {
            return Err(SegmentError::DataOffsetTooSmall { data_offset });
        }
        // Saturating, though the guard above already makes it exact: the option
        // area is what the data offset names beyond the fixed header, and at most
        // ten words, so the product cannot leave `usize`.
        let option_len = usize::from(data_offset.saturating_sub(MIN_DATA_OFFSET)) * 4;
        let Some((option_area, payload)) = rest.split_at_checked(option_len) else {
            return Err(SegmentError::DataOffsetExceedsSegment {
                data_offset,
                got: bytes.len(),
            });
        };

        // Before any field is used; see the module header on why the order is
        // load-bearing rather than tidy.
        let Ok(length) = u16::try_from(bytes.len()) else {
            // A segment longer than any IPv4 datagram can carry. It has no
            // pseudo-header length to be summed under, so there is no checksum
            // to verify and the segment is refused as the wrong shape.
            return Err(SegmentError::DataOffsetExceedsSegment {
                data_offset,
                got: bytes.len(),
            });
        };
        let sum = pseudo_header(source, destination, length).add_bytes(bytes);
        if !sum.is_consistent() {
            let found = u16::from_be_bytes([ck_high, ck_low]);
            return Err(SegmentError::ChecksumInvalid {
                found,
                computed: recomputed(source, destination, bytes),
            });
        }

        Ok(Self {
            source_port: u16::from_be_bytes([sp_high, sp_low]),
            destination_port: u16::from_be_bytes([dp_high, dp_low]),
            sequence: SeqNumber::new(u32::from_be_bytes([seq0, seq1, seq2, seq3])),
            acknowledgement: SeqNumber::new(u32::from_be_bytes([ack0, ack1, ack2, ack3])),
            // The four reserved bits and the ECN bits are deliberately dropped:
            // this stack neither negotiates ECN nor refuses a peer that does,
            // and a reserved bit is not a value to act on.
            flags: Flags(flags & 0x3f),
            window: u16::from_be_bytes([win_high, win_low]),
            options: read_options(option_area)?,
            payload,
        })
    }
}

/// What one segment this stack sends carries.
///
/// The payload is borrowed rather than owned, and that is the whole design: the
/// bytes live wherever the caller put them — for the appliance, a pool buffer a
/// NIC DMA'd into — and this type never copies them anywhere but into the frame
/// on its way out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outgoing<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: SeqNumber,
    pub acknowledgement: SeqNumber,
    pub flags: Flags,
    /// Already scaled down by the shift this end advertised.
    pub window: u16,
    /// Written only on a segment carrying `SYN`, which is the only segment
    /// RFC 793 and RFC 7323 section 2.2 permit them on.
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub payload: &'a [u8],
}

/// Why a segment could not be written. About the caller's storage or a value it
/// composed, never about anything received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    DoesNotFit {
        needed: usize,
        capacity: usize,
    },
    /// A payload no IPv4 datagram can name.
    PayloadTooLong {
        len: usize,
    },
}

impl Outgoing<'_> {
    /// The bytes this segment will occupy, header and options included.
    ///
    /// # Errors
    /// [`WriteError::PayloadTooLong`] for a payload no datagram can carry.
    pub fn encoded_len(&self) -> Result<usize, WriteError> {
        let header = TCP_HEADER_LEN + self.option_len();
        header
            .checked_add(self.payload.len())
            .filter(|total| u16::try_from(*total).is_ok())
            .ok_or(WriteError::PayloadTooLong {
                len: self.payload.len(),
            })
    }

    /// The option area's length, padded to a 32-bit word as the data offset
    /// requires.
    fn option_len(&self) -> usize {
        self.option_area().1
    }

    /// Write this segment into `out`, computing its checksum over the
    /// pseudo-header `source` and `destination` form, and return its length.
    ///
    /// # Errors
    /// [`WriteError`]. Nothing is written on a refusal, so a caller that has
    /// laid out other bytes in `out` keeps them.
    pub fn write(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
        out: &mut [u8],
    ) -> Result<usize, WriteError> {
        let needed = self.encoded_len()?;
        let Some(segment) = out.get_mut(..needed) else {
            return Err(WriteError::DoesNotFit {
                needed,
                capacity: out.len(),
            });
        };

        let (options, option_len) = self.option_area();
        // Lossless: `option_len` is at most 8 and `TCP_HEADER_LEN` is 20, so the
        // sum is 28 and the quotient at most 7 — inside the four bits the field
        // has.
        let data_offset = ((TCP_HEADER_LEN + option_len) / 4) as u8;

        // The checksum covers the header it sits in, so the header is built
        // twice: once with the field zero to take the sum, and once with the
        // value. Both are whole-array constructions rather than a patch at an
        // offset, which is what keeps every index here a compile-time constant.
        let zeroed = self.header(data_offset, 0);
        let sum = pseudo_header(source, destination, needed_len(needed))
            .add_bytes(&zeroed)
            // Both pieces before the payload are of even length, so the byte
            // pairing the sum depends on is unbroken across them.
            .add_bytes(options.get(..option_len).unwrap_or_default())
            .add_bytes(self.payload);
        let header = self.header(data_offset, sum.finish());

        for (slot, byte) in segment.iter_mut().zip(
            header
                .iter()
                .chain(options.iter().take(option_len))
                .chain(self.payload),
        ) {
            *slot = *byte;
        }
        Ok(needed)
    }

    /// The fixed twenty bytes, with `checksum` in the field that carries it.
    fn header(&self, data_offset: u8, checksum: u16) -> [u8; TCP_HEADER_LEN] {
        let [sp_high, sp_low] = self.source_port.to_be_bytes();
        let [dp_high, dp_low] = self.destination_port.to_be_bytes();
        let [s0, s1, s2, s3] = self.sequence.raw().to_be_bytes();
        let [a0, a1, a2, a3] = self.acknowledgement.raw().to_be_bytes();
        let [w_high, w_low] = self.window.to_be_bytes();
        let [ck_high, ck_low] = checksum.to_be_bytes();
        [
            sp_high,
            sp_low,
            dp_high,
            dp_low,
            s0,
            s1,
            s2,
            s3,
            a0,
            a1,
            a2,
            a3,
            data_offset << 4,
            self.flags.bits(),
            w_high,
            w_low,
            ck_high,
            ck_low,
            // The urgent pointer, zero because nothing here sets `URG`.
            0,
            0,
        ]
    }

    /// The option area as bytes and the length of it that is in use.
    ///
    /// Built by value, one arm per combination, so the layout is readable as a
    /// table and no index into it is computed at run time. Empty on every segment
    /// carrying no `SYN`, which is the only one RFC 793 and RFC 7323 section 2.2 permit
    /// these options on.
    fn option_area(&self) -> ([u8; MAX_OPTION_LEN], usize) {
        if !self.flags.contains(Flags::SYN) {
            return ([0; MAX_OPTION_LEN], 0);
        }
        match (self.mss, self.window_scale) {
            (Some(mss), Some(scale)) => {
                let [high, low] = mss.to_be_bytes();
                (
                    [
                        OPTION_MSS,
                        OPTION_MSS_LEN,
                        high,
                        low,
                        OPTION_NOP,
                        OPTION_WINDOW_SCALE,
                        OPTION_WINDOW_SCALE_LEN,
                        scale,
                    ],
                    MAX_OPTION_LEN,
                )
            }
            (Some(mss), None) => {
                let [high, low] = mss.to_be_bytes();
                ([OPTION_MSS, OPTION_MSS_LEN, high, low, 0, 0, 0, 0], 4)
            }
            // A window scale alone is padded to a whole word with a leading NOP,
            // which is what keeps the data offset a count of words.
            (None, Some(scale)) => (
                [
                    OPTION_NOP,
                    OPTION_WINDOW_SCALE,
                    OPTION_WINDOW_SCALE_LEN,
                    scale,
                    0,
                    0,
                    0,
                    0,
                ],
                4,
            ),
            (None, None) => ([0; MAX_OPTION_LEN], 0),
        }
    }
}

/// The pseudo-header's length field for a segment of `needed` bytes, which
/// [`Outgoing::encoded_len`] has already held inside `u16`.
///
/// Saturating rather than fallible so the one caller has no branch to test: the
/// bound is established before this is reached.
fn needed_len(needed: usize) -> u16 {
    u16::try_from(needed).unwrap_or(u16::MAX)
}

/// The RFC 793 section 3.1 pseudo-header as a running sum: the two addresses, a zero
/// byte and the protocol number as one word, and the segment's own length.
fn pseudo_header(source: Ipv4Address, destination: Ipv4Address, length: u16) -> Checksum {
    Checksum::new()
        .add_address(source)
        .add_address(destination)
        .add_u16(u16::from(Protocol::TCP.0))
        .add_u16(length)
}

/// What the checksum field should hold, whatever it holds now: the field is part
/// of its own input, so it is summed as zero.
fn recomputed(source: Ipv4Address, destination: Ipv4Address, bytes: &[u8]) -> u16 {
    let Ok(length) = u16::try_from(bytes.len()) else {
        return 0;
    };
    let before = bytes.get(..CHECKSUM_AT).unwrap_or_default();
    let after = bytes.get(CHECKSUM_AT + 2..).unwrap_or_default();
    // The two pieces are split on an even boundary, so the pairing the sum
    // depends on is unbroken; a zero pair stands in for the field itself.
    pseudo_header(source, destination, length)
        .add_bytes(before)
        .add_u16(0)
        .add_bytes(after)
        .finish()
}

/// Walk the option area, decoding the three options this stack reads and
/// skipping every other by its own length.
///
/// The loop is bounded by the area, which the data offset bounds to
/// [`MAX_TCP_HEADER_LEN`]: every iteration consumes at least one byte, so no
/// option a peer can compose makes it run longer than the header it is in.
fn read_options(mut area: &[u8]) -> Result<Options, SegmentError> {
    let mut options = Options::default();
    while let Some((kind, rest)) = area.split_first() {
        match *kind {
            OPTION_END => break,
            OPTION_NOP => {
                area = rest;
                continue;
            }
            _ => {}
        }
        let Some((len, _)) = rest.split_first() else {
            return Err(SegmentError::OptionTruncated {
                kind: *kind,
                len: 0,
                remaining: area.len(),
            });
        };
        let len = *len;
        if len < 2 {
            return Err(SegmentError::OptionLengthInvalid { kind: *kind, len });
        }
        let Some((option, remaining)) = area.split_at_checked(usize::from(len)) else {
            return Err(SegmentError::OptionTruncated {
                kind: *kind,
                len,
                remaining: area.len(),
            });
        };
        // Each of the three is refused on its second appearance, so a repeat is
        // a typed error with a counter behind it like every other refusal here,
        // rather than the last occurrence quietly winning.
        match (*kind, option) {
            (OPTION_MSS, [_, _, high, low]) => {
                if options.mss.is_some() {
                    return Err(SegmentError::OptionRepeated { kind: *kind });
                }
                options.mss = Some(u16::from_be_bytes([*high, *low]));
            }
            (OPTION_WINDOW_SCALE, [_, _, shift]) => {
                if options.window_scale.is_some() {
                    return Err(SegmentError::OptionRepeated { kind: *kind });
                }
                // RFC 7323 section 2.3: a shift above the maximum is clamped, not
                // refused — a peer offering one is asking for a window this end
                // will simply not grow to.
                options.window_scale = Some((*shift).min(MAX_WINDOW_SCALE));
            }
            (OPTION_SACK_PERMITTED, [_, _]) => {
                if options.sack_permitted {
                    return Err(SegmentError::OptionRepeated { kind: *kind });
                }
                options.sack_permitted = true;
            }
            (OPTION_MSS | OPTION_WINDOW_SCALE | OPTION_SACK_PERMITTED, _) => {
                return Err(SegmentError::OptionLengthInvalid { kind: *kind, len });
            }
            // Every other kind, skipped by its own length. This is the whole of
            // forward compatibility: an option this stack has never heard of is
            // one it must step over rather than refuse the segment for.
            _ => {}
        }
        area = remaining;
    }
    Ok(options)
}

#[cfg(test)]
mod tests;
