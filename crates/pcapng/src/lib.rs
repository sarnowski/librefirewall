//! The pcapng encoder behind the appliance's two recording sinks:
//! Section Header, Interface Description, Enhanced Packet, Interface
//! Statistics and Custom blocks, written into storage the caller already owns.
//!
//! Faces untrusted network traffic, one step behind the parsers
//! that read it. This crate writes rather than reads, so no adversary picks its
//! control flow directly — but every Enhanced Packet Block embeds bytes that
//! arrived on a dataplane port and takes its Captured Packet Length from that
//! frame's own size, and that one attacker-influenced number reaches four
//! places at once: the block's total, the zero padding behind the payload, the
//! two Block Total Length fields every reader navigates by, and the ring space
//! the caller has left. Nothing here panics, indexes past a bound, wraps a
//! length, or writes a byte it was not given room for; a block that cannot be
//! encoded is a typed error the caller must handle.
//!
//! # Why each block is measured before it is written
//!
//! [`section_header_len`] and its four siblings run the same emitter as the
//! matching `write_*`, differing only in what consumes the bytes — a counter or
//! the caller's slice. Keeping two such walks in step by hand is a defect
//! waiting for the first block type that grows an option, and the failure it
//! produces is the worst one available here: a ring advanced by a predicted
//! length the writer did not produce leaves every later block at an offset no
//! reader can find, and an analyst discovers it days afterwards in a file that
//! cannot be re-made. One walk consumed twice cannot disagree with itself.
//!
//! Measuring first is also what makes refusal total. `write_*` reserves the
//! exact block before emitting a byte, so a caller that has run out of ring
//! space is handed its buffer back untouched and can flush and retry — rather
//! than holding a partial block it must now find some way to un-write.
//!
//! # Deliberate narrowness, and what it costs
//!
//! * **Encoder only.** Nothing here parses pcapng. A download serves a byte
//!   range off the ring without re-encoding, so the appliance
//!   never reads back what it wrote and a reader would be untested weight on
//!   the medium's format.
//! * **Little-endian only.** The byte-order magic is written, not chosen: the
//!   sinks run on x86_64, the only target, and a configurable endianness would
//!   double the encoding paths to serve a machine this appliance is not.
//! * **One custom code, at either level.** Only the binary, copyable forms are
//!   emitted — option 2989 and [`CUSTOM_BLOCK_COPYABLE`]; see [`CustomBinary`].
//! * **No Decryption Secrets Block and no Name Resolution Block.** The first
//!   is intended once there is TLS material to carry; neither has a
//!   producer yet, and a block type nothing emits is a block type nothing
//!   tests.
//! * **Options are written in ascending code order.** The format does not ask
//!   for it. A fixed order makes an encoded block a function of its input
//!   alone, which is what lets the tests pin whole blocks byte for byte instead
//!   of asserting field by field.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests;

use core::fmt;

/// Identifies both the format and the byte order it was written in: a reader
/// finding the bytes reversed knows the section is big-endian. Every integer
/// this crate writes is little-endian, so a reader sees exactly this value.
pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// The IANA Private Enterprise Number tagging every custom option this crate
/// writes.
///
/// **Nobody's.** No registered PEN stands behind these annotations, and one must
/// replace this before any capture leaves a customer's premises. 4294967295 is
/// the value chosen to hold the place because IANA reserves it and can
/// therefore never assign it: a file that escapes with this number cannot be
/// mistaken for another organisation's annotations, and a reader that validates
/// PENs rejects the option outright rather than decoding our layout as someone
/// else's. The name says the same thing the value does, so a caller cannot read
/// ownership into a number that has none.
pub const UNREGISTERED_PEN: u32 = 0xFFFF_FFFF;

/// Block Type, Block Total Length, and the repeated Block Total Length: the
/// bytes every block spends on framing itself.
pub const BLOCK_FRAMING_LEN: usize = 12;

/// Custom Block, copyable — a reader that does not understand the enterprise
/// number carries it into a rewritten file rather than dropping it.
pub const CUSTOM_BLOCK_COPYABLE: u32 = 0x0000_0BAD;

/// The smallest Custom Block that can be written: the two length fields, the
/// type, and the enterprise number, with no data at all.
pub const MIN_CUSTOM_BLOCK_LEN: usize = 16;

/// Option Code and Option Length, ahead of every option's value.
const OPTION_HEADER_LEN: usize = 4;

/// Byte-order magic, major and minor version, and the 64-bit section length.
const SECTION_HEADER_BODY_LEN: usize = 16;

/// LinkType, a reserved half-word, and SnapLen.
const INTERFACE_DESCRIPTION_BODY_LEN: usize = 8;

/// Interface ID, the two timestamp halves, and the captured and original
/// lengths, ahead of the packet bytes themselves.
const ENHANCED_PACKET_BODY_LEN: usize = 20;

/// Interface ID and the two timestamp halves.
const INTERFACE_STATISTICS_BODY_LEN: usize = 12;

/// The Private Enterprise Number ahead of a custom option's own payload.
const PEN_LEN: usize = 4;

/// Every block and every option is padded to this boundary, and a Block Total
/// Length is always a multiple of it.
const ALIGNMENT: usize = 4;

const BLOCK_SECTION_HEADER: u32 = 0x0A0D_0D0A;
const BLOCK_INTERFACE_DESCRIPTION: u32 = 0x0000_0001;
const BLOCK_INTERFACE_STATISTICS: u32 = 0x0000_0005;
const BLOCK_ENHANCED_PACKET: u32 = 0x0000_0006;

/// Written where a section's length is not known in advance, which is always
/// the case for a ring being appended to.
const SECTION_LENGTH_UNSPECIFIED: u64 = u64::MAX;

const VERSION_MAJOR: u16 = 1;
const VERSION_MINOR: u16 = 0;

const OPT_END_OF_OPT: u16 = 0;
const OPT_COMMENT: u16 = 1;

const SHB_HARDWARE: u16 = 2;
const SHB_OS: u16 = 3;
const SHB_USERAPPL: u16 = 4;

const IF_NAME: u16 = 2;
const IF_DESCRIPTION: u16 = 3;
const IF_SPEED: u16 = 8;
const IF_TSRESOL: u16 = 9;

const EPB_FLAGS: u16 = 2;
const EPB_DROPCOUNT: u16 = 4;
const EPB_PACKETID: u16 = 5;
const EPB_QUEUE: u16 = 6;
const EPB_VERDICT: u16 = 7;

const ISB_STARTTIME: u16 = 2;
const ISB_ENDTIME: u16 = 3;
const ISB_IFRECV: u16 = 4;
const ISB_IFDROP: u16 = 5;

/// A custom option carrying binary data, copyable: code 2989.
///
/// Copyable rather than the 19373 form because the annotation describes the
/// packet, not the file that happens to hold it — a tool that filters a
/// recording into a smaller one should carry the verdict and flow identity
/// across with the packets it keeps, which is exactly the distinction the two
/// code pairs draw.
const CUSTOM_BINARY_COPYABLE: u16 = 2989;

// The block framing and the four fixed bodies are the offsets every reader
// navigates by, so a width that drifts must be a compile error here rather than
// a file that parses into the wrong fields.
const _: () = {
    assert!(BLOCK_FRAMING_LEN == 12);
    assert!(OPTION_HEADER_LEN == 4);
    assert!(SECTION_HEADER_BODY_LEN == 16);
    assert!(INTERFACE_DESCRIPTION_BODY_LEN == 8);
    assert!(ENHANCED_PACKET_BODY_LEN == 20);
    assert!(INTERFACE_STATISTICS_BODY_LEN == 12);
    assert!(PEN_LEN == 4);

    // Each fixed body is a whole number of alignment units, so nothing but a
    // variable-length payload can leave a body unaligned.
    assert!(BLOCK_FRAMING_LEN.is_multiple_of(ALIGNMENT));
    assert!(OPTION_HEADER_LEN.is_multiple_of(ALIGNMENT));
    assert!(SECTION_HEADER_BODY_LEN.is_multiple_of(ALIGNMENT));
    assert!(INTERFACE_DESCRIPTION_BODY_LEN.is_multiple_of(ALIGNMENT));
    assert!(ENHANCED_PACKET_BODY_LEN.is_multiple_of(ALIGNMENT));
    assert!(INTERFACE_STATISTICS_BODY_LEN.is_multiple_of(ALIGNMENT));
    assert!(PEN_LEN.is_multiple_of(ALIGNMENT));

    // The smallest each block type can be, which is what a caller reserving a
    // ring segment budgets from.
    assert!(BLOCK_FRAMING_LEN + SECTION_HEADER_BODY_LEN == 28);
    assert!(BLOCK_FRAMING_LEN + INTERFACE_DESCRIPTION_BODY_LEN == 20);
    assert!(BLOCK_FRAMING_LEN + ENHANCED_PACKET_BODY_LEN == 32);
    assert!(BLOCK_FRAMING_LEN + INTERFACE_STATISTICS_BODY_LEN == 24);
    assert!(MIN_CUSTOM_BLOCK_LEN == BLOCK_FRAMING_LEN + PEN_LEN);
};

/// Why a block could not be encoded.
///
/// Every variant but [`EncodeError::MeasureDisagreed`] is decided before a byte is
/// written, so the buffer is untouched and only [`OutOfSpace`](Self::OutOfSpace) is
/// worth a retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// The buffer is shorter than the block. `needed` is the block's exact
    /// encoded length, so a caller flushing and retrying knows what to make
    /// room for rather than doubling until it fits.
    OutOfSpace { needed: usize, capacity: usize },
    /// Captured packet bytes beyond what the 32-bit Captured Packet Length
    /// field can express.
    PayloadTooLong { len: usize },
    /// An option value beyond what the 16-bit Option Length field can express.
    /// `len` is the whole value, including a custom option's Private Enterprise
    /// Number.
    OptionTooLong { code: u16, len: usize },
    /// More captured bytes than the frame they were captured from had, which
    /// would describe a packet that grew in transit.
    CapturedExceedsOriginal { captured: u32, original: u32 },
    /// The assembled block is beyond what the 32-bit Block Total Length fields
    /// can express, and so cannot be framed however much room the caller has.
    BlockTooLong,
    /// A padding block whose length is not a multiple of four, which would
    /// leave every block written after it unaligned.
    BlockNotAligned { len: usize },
    /// A padding block below [`MIN_CUSTOM_BLOCK_LEN`], which cannot frame
    /// itself at all.
    BlockTooShort { len: usize },
    /// The two walks disagreed about a block's length, so the reservation ran out
    /// under the writer — a defect in this crate, both being one emitter, and its
    /// own variant because it leaves bytes a retry would double.
    MeasureDisagreed { measured: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfSpace { needed, capacity } => write!(
                f,
                "a {needed}-byte block does not fit {capacity} bytes of buffer"
            ),
            Self::PayloadTooLong { len } => write!(
                f,
                "{len} captured bytes exceed the {} a 32-bit length holds",
                u32::MAX
            ),
            Self::OptionTooLong { code, len } => write!(
                f,
                "option {code} carries {len} bytes, beyond the {} a 16-bit length holds",
                u16::MAX
            ),
            Self::CapturedExceedsOriginal { captured, original } => write!(
                f,
                "{captured} captured bytes exceed the {original} the packet had"
            ),
            Self::BlockTooLong => write!(
                f,
                "the block exceeds the {} a 32-bit total length holds",
                u32::MAX
            ),
            Self::BlockNotAligned { len } => {
                write!(f, "a {len}-byte block is not a multiple of {ALIGNMENT}")
            }
            Self::BlockTooShort { len } => write!(
                f,
                "a {len}-byte block is below the {MIN_CUSTOM_BLOCK_LEN} its framing needs"
            ),
            Self::MeasureDisagreed { measured } => {
                write!(
                    f,
                    "a block did not fit the {measured} bytes measured for it"
                )
            }
        }
    }
}

/// What an interface's frames are, in the numbering `tcpdump` maintains and
/// every pcapng reader keys its dissectors off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkType(pub u16);

impl LinkType {
    /// IEEE 802.3 Ethernet, which is every dataplane port this appliance has.
    pub const ETHERNET: Self = Self(1);
}

/// What a verdict in an [`epb_verdict`](EnhancedPacket::verdict) option was
/// reached by, which is what tells a reader how to read the octets behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerdictKind(pub u8);

impl VerdictKind {
    pub const HARDWARE: Self = Self(0);
    pub const LINUX_EBPF_TC: Self = Self(1);
    pub const LINUX_EBPF_XDP: Self = Self(2);
}

/// The tick length of every timestamp in a section, as the negative power of
/// ten an `if_tsresol` option with its high bit clear denotes.
///
/// A separate type because the octet has two meanings — clear high bit for
/// powers of ten, set for powers of two — and a reader that guesses the wrong
/// one renders plausible times that are wrong by orders of magnitude rather
/// than failing. Only the decimal form is constructible here, so the ambiguous
/// octet cannot be written by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimestampResolution(u8);

impl TimestampResolution {
    pub const MILLISECONDS: Self = Self(3);
    pub const MICROSECONDS: Self = Self(6);
    pub const NANOSECONDS: Self = Self(9);

    /// A resolution of 10^-`digits` seconds.
    ///
    /// `None` beyond 127, where the octet would instead select the
    /// power-of-two form.
    #[must_use]
    pub const fn from_decimal_digits(digits: u8) -> Option<Self> {
        if digits > 0x7F {
            None
        } else {
            Some(Self(digits))
        }
    }

    #[must_use]
    pub const fn decimal_digits(self) -> u8 {
        self.0
    }
}

/// A PEN-tagged custom option: the structured firewall state pcapng has no
/// standard field for, in whatever layout the sink and its
/// readers agree on.
///
/// The encoder treats `data` as opaque. A reader that does not recognise
/// [`pen`](Self::pen) skips the option and still sees a valid capture, which is
/// what lets the annotation ride along without narrowing the audience for the
/// file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomBinary<'a> {
    pub pen: u32,
    pub data: &'a [u8],
}

/// What the appliance decided about a packet, on the packet it decided about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict<'a> {
    pub kind: VerdictKind,
    pub data: &'a [u8],
}

/// Opens a section, and so opens every ring segment of a recording.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionHeader<'a> {
    pub hardware: Option<&'a str>,
    pub os: Option<&'a str>,
    pub application: Option<&'a str>,
    /// Which version of the custom-option layout the blocks in this section
    /// carry, so a reader learns the schema from the file rather than from the
    /// appliance that wrote it.
    pub schema: Option<CustomBinary<'a>>,
}

/// Declares one interface. Blocks refer to interfaces by the position of their
/// description within the section, counting from zero, so the order these are
/// written in is the numbering
/// [`EnhancedPacket::interface_id`] uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceDescription<'a> {
    pub link_type: LinkType,
    /// Bytes of each frame the sink retains, or zero for no limit.
    pub snap_len: u32,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    /// Bits per second, where the interface's rate is known.
    pub speed: Option<u64>,
    /// Always written, rather than left to the format's default of microseconds
    /// — a resolution a reader had to assume is one the file cannot be audited
    /// against.
    pub timestamp_resolution: TimestampResolution,
}

/// One packet, and what the appliance knew about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnhancedPacket<'a> {
    pub interface_id: u32,
    /// Ticks since the epoch, at the interface's
    /// [`timestamp_resolution`](InterfaceDescription::timestamp_resolution).
    /// Written as the format's two halves, high word first.
    pub timestamp: u64,
    /// The bytes retained, which is the whole frame unless the sink's snap
    /// length cut it short.
    pub captured: &'a [u8],
    /// The frame's length on the wire, which exceeds `captured.len()` exactly
    /// when the sink truncated it.
    pub original_len: u32,
    pub flags: Option<u32>,
    /// Frames the interface lost between this packet and the previous one it
    /// recorded — a recording is meant to state its own loss in-band.
    pub drop_count: Option<u64>,
    /// Correlates the ingress and egress observations of one forwarded frame,
    /// so a rewrite is a relation between two records rather than something an
    /// analyst infers from tuples.
    pub packet_id: Option<u64>,
    pub queue: Option<u32>,
    pub verdict: Option<Verdict<'a>>,
    pub custom: Option<CustomBinary<'a>>,
    pub comment: Option<&'a str>,
}

/// What an interface has seen and lost, as of one instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceStatistics {
    pub interface_id: u32,
    /// When this report was made, in the same ticks as
    /// [`EnhancedPacket::timestamp`].
    pub timestamp: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub received: u64,
    pub dropped: u64,
}

/// The exact bytes [`write_section_header`] will write.
///
/// # Errors
/// The same [`EncodeError`] the write would refuse with, except
/// [`EncodeError::OutOfSpace`], which is a property of the caller's buffer
/// rather than of the block.
pub fn section_header_len(header: &SectionHeader<'_>) -> Result<usize, EncodeError> {
    let options = section_header_options(header)?;
    let body = section_header_body();
    measure(BLOCK_SECTION_HEADER, Body::fixed(&body), &options).map(|measured| measured.bytes)
}

/// Write a Section Header Block into `out`, answering its length.
///
/// # Errors
/// [`EncodeError::OutOfSpace`] when `out` is shorter than
/// [`section_header_len`], in which case `out` is untouched; otherwise
/// whatever that function refuses the block for.
pub fn write_section_header(
    out: &mut [u8],
    header: &SectionHeader<'_>,
) -> Result<usize, EncodeError> {
    let options = section_header_options(header)?;
    let body = section_header_body();
    write_block(out, BLOCK_SECTION_HEADER, Body::fixed(&body), &options)
}

/// The exact bytes [`write_interface_description`] will write.
///
/// # Errors
/// As [`section_header_len`].
pub fn interface_description_len(idb: &InterfaceDescription<'_>) -> Result<usize, EncodeError> {
    let options = interface_description_options(idb)?;
    let body = interface_description_body(idb);
    measure(BLOCK_INTERFACE_DESCRIPTION, Body::fixed(&body), &options)
        .map(|measured| measured.bytes)
}

/// Write an Interface Description Block into `out`, answering its length.
///
/// # Errors
/// As [`write_section_header`].
pub fn write_interface_description(
    out: &mut [u8],
    idb: &InterfaceDescription<'_>,
) -> Result<usize, EncodeError> {
    let options = interface_description_options(idb)?;
    let body = interface_description_body(idb);
    write_block(
        out,
        BLOCK_INTERFACE_DESCRIPTION,
        Body::fixed(&body),
        &options,
    )
}

/// The exact bytes [`write_enhanced_packet`] will write.
///
/// # Errors
/// As [`section_header_len`], plus [`EncodeError::PayloadTooLong`] and
/// [`EncodeError::CapturedExceedsOriginal`] for a packet the format cannot
/// describe.
pub fn enhanced_packet_len(epb: &EnhancedPacket<'_>) -> Result<usize, EncodeError> {
    let options = enhanced_packet_options(epb)?;
    let body = enhanced_packet_body(epb)?;
    measure(
        BLOCK_ENHANCED_PACKET,
        Body::with_payload(&body, epb.captured),
        &options,
    )
    .map(|measured| measured.bytes)
}

/// Write an Enhanced Packet Block into `out`, answering its length.
///
/// # Errors
/// As [`enhanced_packet_len`], plus [`EncodeError::OutOfSpace`] when `out` is
/// shorter than the block, in which case `out` is untouched.
pub fn write_enhanced_packet(
    out: &mut [u8],
    epb: &EnhancedPacket<'_>,
) -> Result<usize, EncodeError> {
    let options = enhanced_packet_options(epb)?;
    let body = enhanced_packet_body(epb)?;
    write_block(
        out,
        BLOCK_ENHANCED_PACKET,
        Body::with_payload(&body, epb.captured),
        &options,
    )
}

/// The exact bytes [`write_interface_statistics`] will write.
///
/// # Errors
/// As [`section_header_len`].
pub fn interface_statistics_len(isb: &InterfaceStatistics) -> Result<usize, EncodeError> {
    let options = interface_statistics_options(isb);
    let body = interface_statistics_body(isb);
    measure(BLOCK_INTERFACE_STATISTICS, Body::fixed(&body), &options).map(|measured| measured.bytes)
}

/// Write an Interface Statistics Block into `out`, answering its length.
///
/// # Errors
/// As [`write_section_header`].
pub fn write_interface_statistics(
    out: &mut [u8],
    isb: &InterfaceStatistics,
) -> Result<usize, EncodeError> {
    let options = interface_statistics_options(isb);
    let body = interface_statistics_body(isb);
    write_block(
        out,
        BLOCK_INTERFACE_STATISTICS,
        Body::fixed(&body),
        &options,
    )
}

/// The exact bytes [`write_custom_block`] will write.
///
/// # Errors
/// [`EncodeError::BlockTooLong`] alone: the data is not an option, so nothing
/// caps it below the block's own 32-bit length.
pub fn custom_block_len(body: &CustomBinary<'_>) -> Result<usize, EncodeError> {
    let pen = custom_block_body(body);
    measure(
        CUSTOM_BLOCK_COPYABLE,
        Body::with_payload(&pen, body.data),
        &[],
    )
    .map(|measured| measured.bytes)
}

/// Write a Custom Block into `out`, answering its length.
///
/// # Errors
/// As [`write_section_header`].
pub fn write_custom_block(out: &mut [u8], body: &CustomBinary<'_>) -> Result<usize, EncodeError> {
    let pen = custom_block_body(body);
    write_block(
        out,
        CUSTOM_BLOCK_COPYABLE,
        Body::with_payload(&pen, body.data),
        &[],
    )
}

/// Write a Custom Block occupying exactly `len` bytes, its data zero-filled.
///
/// A recording reaches the medium in whole sectors, and the slack behind the
/// last block of one has to be bytes every reader steps over rather than a
/// short read truncating the file. [`CUSTOM_BLOCK_COPYABLE`] is a type libpcap
/// itself knows to skip, and [`UNREGISTERED_PEN`] tags data no other tool claims.
///
/// # Errors
/// [`EncodeError::BlockNotAligned`] or [`EncodeError::BlockTooShort`] for a
/// `len` no buffer would make writable; otherwise as [`write_custom_block`].
pub fn write_padding_block(out: &mut [u8], len: usize) -> Result<usize, EncodeError> {
    if !len.is_multiple_of(ALIGNMENT) {
        return Err(EncodeError::BlockNotAligned { len });
    }
    let zeros = len
        .checked_sub(MIN_CUSTOM_BLOCK_LEN)
        .ok_or(EncodeError::BlockTooShort { len })?;
    let pen = UNREGISTERED_PEN.to_le_bytes();
    write_block(out, CUSTOM_BLOCK_COPYABLE, Body::zeroed(&pen, zeros), &[])
}

/// A block's length in both forms the encoder needs it in, derived together so
/// the `usize` a caller sizes a buffer with and the `u32` the two Block Total
/// Length fields carry can never be checked against different bounds.
#[derive(Clone, Copy)]
struct Measured {
    bytes: usize,
    field: u32,
}

impl Measured {
    fn new(bytes: usize) -> Result<Self, EncodeError> {
        let field = u32::try_from(bytes).map_err(|_| EncodeError::BlockTooLong)?;
        Ok(Self { bytes, field })
    }
}

/// A block's body: the fixed fields every block of its type has, then the
/// variable-length data an Enhanced Packet or Custom Block carries.
#[derive(Clone, Copy)]
struct Body<'a> {
    fixed: &'a [u8],
    payload: Payload<'a>,
}

impl<'a> Body<'a> {
    const fn fixed(fixed: &'a [u8]) -> Self {
        Self {
            fixed,
            payload: Payload::Bytes(&[]),
        }
    }

    const fn with_payload(fixed: &'a [u8], payload: &'a [u8]) -> Self {
        Self {
            fixed,
            payload: Payload::Bytes(payload),
        }
    }

    const fn zeroed(fixed: &'a [u8], zeros: usize) -> Self {
        Self {
            fixed,
            payload: Payload::Zeros(zeros),
        }
    }
}

/// A block's variable-length data: bytes the caller holds, or a run of zeros
/// nobody holds — a padding block's data is as long as the hole it fills.
#[derive(Clone, Copy)]
enum Payload<'a> {
    Bytes(&'a [u8]),
    Zeros(usize),
}

impl Payload<'_> {
    const fn len(self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Zeros(len) => len,
        }
    }

    fn emit<S: Sink>(self, sink: &mut S) -> Result<(), Full> {
        match self {
            Self::Bytes(bytes) => sink.push(bytes),
            Self::Zeros(len) => sink.zeros(len),
        }
    }
}

/// A value short enough for the two-octet Option Length field, held with the
/// length that proves it.
///
/// The length is a field rather than a recomputation because establishing it is
/// where the bound gets enforced: [`Value::new`] checks it for a borrowed value,
/// and [`Value::integer`] has nothing to check because an [`Inline`] is eight
/// octets at most. Either way the emitter is handed a length it can write, and
/// so has no failure of its own to invent one for.
#[derive(Clone, Copy)]
struct Value<'a> {
    len: u16,
    inline: Inline,
    tail: &'a [u8],
}

impl<'a> Value<'a> {
    const EMPTY: Self = Self {
        len: 0,
        inline: Inline::None,
        tail: &[],
    };

    fn new(code: u16, inline: Inline, tail: &'a [u8]) -> Result<Self, EncodeError> {
        let inline_len = usize::from(inline.len());
        let len = inline_len
            .checked_add(tail.len())
            .and_then(|len| u16::try_from(len).ok())
            .ok_or(EncodeError::OptionTooLong {
                code,
                len: inline_len.saturating_add(tail.len()),
            })?;
        Ok(Self { len, inline, tail })
    }

    fn text(code: u16, text: &'a str) -> Result<Self, EncodeError> {
        Self::new(code, Inline::None, text.as_bytes())
    }

    /// An option whose whole value is a fixed-width number.
    ///
    /// Infallible where [`Value::new`] is not: an [`Inline`] is at most eight
    /// octets, so the length it yields is one the Option Length field holds
    /// whatever the number was, and there is no bound left to check.
    const fn integer(inline: Inline) -> Self {
        Self {
            len: inline.len(),
            inline,
            tail: &[],
        }
    }

    fn custom(code: u16, custom: CustomBinary<'a>) -> Result<Self, EncodeError> {
        Self::new(code, Inline::from_u32(custom.pen), custom.data)
    }

    fn verdict(code: u16, verdict: Verdict<'a>) -> Result<Self, EncodeError> {
        Self::new(code, Inline::from_u8(verdict.kind.0), verdict.data)
    }
}

/// The leading bytes of an option value that are built from a number rather
/// than borrowed: a whole fixed-width value, or the tag ahead of a borrowed
/// one.
///
/// An enum of the three widths that occur rather than a buffer and a length,
/// so the length of what is emitted is the variant itself and no arithmetic
/// stands between the two.
#[derive(Clone, Copy)]
enum Inline {
    None,
    One([u8; 1]),
    Four([u8; 4]),
    Eight([u8; 8]),
}

impl Inline {
    const fn from_u8(value: u8) -> Self {
        Self::One([value])
    }

    const fn from_u32(value: u32) -> Self {
        Self::Four(value.to_le_bytes())
    }

    const fn from_u64(value: u64) -> Self {
        Self::Eight(value.to_le_bytes())
    }

    /// A timestamp option, which is not a little-endian `u64` but the same pair
    /// of 32-bit halves an Enhanced Packet Block writes: the high word first,
    /// each half in the section's byte order. Reading one as a `u64` yields a
    /// time roughly four billion seconds away from the truth.
    const fn from_timestamp(value: u64) -> Self {
        let (high, low) = split_timestamp(value);
        let [h0, h1, h2, h3] = high.to_le_bytes();
        let [l0, l1, l2, l3] = low.to_le_bytes();
        Self::Eight([h0, h1, h2, h3, l0, l1, l2, l3])
    }

    const fn len(self) -> u16 {
        match self {
            Self::None => 0,
            Self::One(_) => 1,
            Self::Four(_) => 4,
            Self::Eight(_) => 8,
        }
    }

    const fn as_slice(&self) -> &[u8] {
        match self {
            Self::None => &[],
            Self::One(bytes) => bytes,
            Self::Four(bytes) => bytes,
            Self::Eight(bytes) => bytes,
        }
    }
}

/// The emitter ran out of the room it was promised. Private, because what that
/// means differs by sink — a `usize` that will not hold a running total, or a
/// slice shorter than the block measured for it — and a caller is told which by
/// the [`EncodeError`] it becomes on the way out.
struct Full;

/// Where a block's bytes go. The measuring pass and the writing pass drive one
/// emitter through this, which is what makes a predicted length and a written
/// length the same walk rather than two that have to be kept in step.
trait Sink {
    fn push(&mut self, bytes: &[u8]) -> Result<(), Full>;

    /// A run of `len` zero bytes, emitted rather than materialised.
    fn zeros(&mut self, len: usize) -> Result<(), Full>;

    /// Zero to the next four-octet boundary after a run of `len` bytes.
    /// Written rather than skipped, so a block never carries whatever the ring
    /// held before it.
    fn pad(&mut self, len: usize) -> Result<(), Full> {
        match padding_for(len) {
            1 => self.push(&[0]),
            2 => self.push(&[0, 0]),
            3 => self.push(&[0, 0, 0]),
            _ => Ok(()),
        }
    }
}

struct Counter {
    bytes: usize,
}

impl Sink for Counter {
    /// A counter cares only how many bytes there are, never which.
    fn push(&mut self, bytes: &[u8]) -> Result<(), Full> {
        self.zeros(bytes.len())
    }

    fn zeros(&mut self, len: usize) -> Result<(), Full> {
        self.bytes = self.bytes.checked_add(len).ok_or(Full)?;
        Ok(())
    }
}

struct Filler<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Filler<'_> {
    /// The next `len` bytes of the buffer, taken only if all of them are there.
    fn take(&mut self, len: usize) -> Result<&mut [u8], Full> {
        let end = self.at.checked_add(len).ok_or(Full)?;
        let target = self.out.get_mut(self.at..end).ok_or(Full)?;
        self.at = end;
        Ok(target)
    }
}

impl Sink for Filler<'_> {
    fn push(&mut self, bytes: &[u8]) -> Result<(), Full> {
        self.take(bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    fn zeros(&mut self, len: usize) -> Result<(), Full> {
        self.take(len)?.fill(0);
        Ok(())
    }
}

/// Bytes of padding that carry `len` bytes to the next four-octet boundary.
const fn padding_for(len: usize) -> usize {
    (ALIGNMENT - (len % ALIGNMENT)) % ALIGNMENT
}

/// The two halves the format splits a timestamp into, high word first.
const fn split_timestamp(timestamp: u64) -> (u32, u32) {
    let [a, b, c, d, e, f, g, h] = timestamp.to_be_bytes();
    (
        u32::from_be_bytes([a, b, c, d]),
        u32::from_be_bytes([e, f, g, h]),
    )
}

fn measure(
    block_type: u32,
    body: Body<'_>,
    options: &[Option<(u16, Value<'_>)>],
) -> Result<Measured, EncodeError> {
    let mut counter = Counter { bytes: 0 };
    // The total is not known until this pass has finished, and passing zero for
    // it costs nothing: the field is four octets whatever it holds, so the
    // count is the same one the writing pass will produce with the real value.
    emit(&mut counter, block_type, 0, body, options).map_err(|Full| EncodeError::BlockTooLong)?;
    Measured::new(counter.bytes)
}

fn write_block(
    out: &mut [u8],
    block_type: u32,
    body: Body<'_>,
    options: &[Option<(u16, Value<'_>)>],
) -> Result<usize, EncodeError> {
    let capacity = out.len();
    let measured = measure(block_type, body, options)?;
    let out_of_space = EncodeError::OutOfSpace {
        needed: measured.bytes,
        capacity,
    };
    // Reserving the whole block before a byte is emitted is what makes the
    // refusal total: a caller that is out of room never sees a partial block it
    // would have to unwind before retrying into a fresh buffer.
    let block = out.get_mut(..measured.bytes).ok_or(out_of_space)?;
    let mut filler = Filler { out: block, at: 0 };
    let disagreed = EncodeError::MeasureDisagreed {
        measured: measured.bytes,
    };
    emit(&mut filler, block_type, measured.field, body, options).map_err(|Full| disagreed)?;
    Ok(measured.bytes)
}

fn emit<S: Sink>(
    sink: &mut S,
    block_type: u32,
    total: u32,
    body: Body<'_>,
    options: &[Option<(u16, Value<'_>)>],
) -> Result<(), Full> {
    sink.push(&block_type.to_le_bytes())?;
    sink.push(&total.to_le_bytes())?;
    sink.push(body.fixed)?;
    body.payload.emit(sink)?;
    sink.pad(body.payload.len())?;
    if options.iter().any(Option::is_some) {
        for &(code, value) in options.iter().flatten() {
            emit_option(sink, code, value)?;
        }
        emit_option(sink, OPT_END_OF_OPT, Value::EMPTY)?;
    }
    sink.push(&total.to_le_bytes())
}

fn emit_option<S: Sink>(sink: &mut S, code: u16, value: Value<'_>) -> Result<(), Full> {
    sink.push(&code.to_le_bytes())?;
    sink.push(&value.len.to_le_bytes())?;
    sink.push(value.inline.as_slice())?;
    sink.push(value.tail)?;
    sink.pad(usize::from(value.len))
}

fn section_header_body() -> [u8; SECTION_HEADER_BODY_LEN] {
    let [m0, m1, m2, m3] = BYTE_ORDER_MAGIC.to_le_bytes();
    let [j0, j1] = VERSION_MAJOR.to_le_bytes();
    let [n0, n1] = VERSION_MINOR.to_le_bytes();
    let [s0, s1, s2, s3, s4, s5, s6, s7] = SECTION_LENGTH_UNSPECIFIED.to_le_bytes();
    [
        m0, m1, m2, m3, j0, j1, n0, n1, s0, s1, s2, s3, s4, s5, s6, s7,
    ]
}

fn section_header_options<'a>(
    header: &SectionHeader<'a>,
) -> Result<[Option<(u16, Value<'a>)>; 4], EncodeError> {
    Ok([
        option(SHB_HARDWARE, header.hardware, Value::text)?,
        option(SHB_OS, header.os, Value::text)?,
        option(SHB_USERAPPL, header.application, Value::text)?,
        option(CUSTOM_BINARY_COPYABLE, header.schema, Value::custom)?,
    ])
}

fn interface_description_body(
    idb: &InterfaceDescription<'_>,
) -> [u8; INTERFACE_DESCRIPTION_BODY_LEN] {
    let [l0, l1] = idb.link_type.0.to_le_bytes();
    let [s0, s1, s2, s3] = idb.snap_len.to_le_bytes();
    [l0, l1, 0, 0, s0, s1, s2, s3]
}

fn interface_description_options<'a>(
    idb: &InterfaceDescription<'a>,
) -> Result<[Option<(u16, Value<'a>)>; 4], EncodeError> {
    Ok([
        option(IF_NAME, idb.name, Value::text)?,
        option(IF_DESCRIPTION, idb.description, Value::text)?,
        integer_option(IF_SPEED, idb.speed, Inline::from_u64),
        Some((
            IF_TSRESOL,
            Value::integer(Inline::from_u8(idb.timestamp_resolution.decimal_digits())),
        )),
    ])
}

/// The Captured Packet Length field describing `len` retained bytes of a frame
/// that was `original_len` bytes on the wire.
///
/// Split out from the body it belongs to because the bound it enforces is
/// otherwise reachable only from a slice larger than the address space a test
/// can allocate, and a bound no test can reach is a bound nobody has checked.
fn captured_length(len: usize, original_len: u32) -> Result<u32, EncodeError> {
    let captured = u32::try_from(len).map_err(|_| EncodeError::PayloadTooLong { len })?;
    if captured > original_len {
        return Err(EncodeError::CapturedExceedsOriginal {
            captured,
            original: original_len,
        });
    }
    Ok(captured)
}

fn enhanced_packet_body(
    epb: &EnhancedPacket<'_>,
) -> Result<[u8; ENHANCED_PACKET_BODY_LEN], EncodeError> {
    let captured_len = captured_length(epb.captured.len(), epb.original_len)?;
    let (high, low) = split_timestamp(epb.timestamp);
    let [i0, i1, i2, i3] = epb.interface_id.to_le_bytes();
    let [h0, h1, h2, h3] = high.to_le_bytes();
    let [w0, w1, w2, w3] = low.to_le_bytes();
    let [c0, c1, c2, c3] = captured_len.to_le_bytes();
    let [o0, o1, o2, o3] = epb.original_len.to_le_bytes();
    Ok([
        i0, i1, i2, i3, h0, h1, h2, h3, w0, w1, w2, w3, c0, c1, c2, c3, o0, o1, o2, o3,
    ])
}

fn enhanced_packet_options<'a>(
    epb: &EnhancedPacket<'a>,
) -> Result<[Option<(u16, Value<'a>)>; 7], EncodeError> {
    Ok([
        option(OPT_COMMENT, epb.comment, Value::text)?,
        integer_option(EPB_FLAGS, epb.flags, Inline::from_u32),
        integer_option(EPB_DROPCOUNT, epb.drop_count, Inline::from_u64),
        integer_option(EPB_PACKETID, epb.packet_id, Inline::from_u64),
        integer_option(EPB_QUEUE, epb.queue, Inline::from_u32),
        option(EPB_VERDICT, epb.verdict, Value::verdict)?,
        option(CUSTOM_BINARY_COPYABLE, epb.custom, Value::custom)?,
    ])
}

fn interface_statistics_body(isb: &InterfaceStatistics) -> [u8; INTERFACE_STATISTICS_BODY_LEN] {
    let (high, low) = split_timestamp(isb.timestamp);
    let [i0, i1, i2, i3] = isb.interface_id.to_le_bytes();
    let [h0, h1, h2, h3] = high.to_le_bytes();
    let [w0, w1, w2, w3] = low.to_le_bytes();
    [i0, i1, i2, i3, h0, h1, h2, h3, w0, w1, w2, w3]
}

fn custom_block_body(body: &CustomBinary<'_>) -> [u8; PEN_LEN] {
    body.pen.to_le_bytes()
}

/// Every statistic is a fixed-width number the caller always supplies, so this
/// block has no option that can be refused and no option that can be absent.
fn interface_statistics_options<'a>(isb: &InterfaceStatistics) -> [Option<(u16, Value<'a>)>; 4] {
    [
        Some((
            ISB_STARTTIME,
            Value::integer(Inline::from_timestamp(isb.start_time)),
        )),
        Some((
            ISB_ENDTIME,
            Value::integer(Inline::from_timestamp(isb.end_time)),
        )),
        Some((ISB_IFRECV, Value::integer(Inline::from_u64(isb.received)))),
        Some((ISB_IFDROP, Value::integer(Inline::from_u64(isb.dropped)))),
    ]
}

/// Pair an option's code with its encoded value, where the caller set the field
/// that carries it and encoding it can be refused.
fn option<'a, T, F>(
    code: u16,
    field: Option<T>,
    encode: F,
) -> Result<Option<(u16, Value<'a>)>, EncodeError>
where
    F: FnOnce(u16, T) -> Result<Value<'a>, EncodeError>,
{
    match field {
        Some(value) => Ok(Some((code, encode(code, value)?))),
        None => Ok(None),
    }
}

/// As [`option`], for a value that is a fixed-width number and so carries no
/// length this crate could have to refuse.
fn integer_option<'a, T, F>(code: u16, field: Option<T>, encode: F) -> Option<(u16, Value<'a>)>
where
    F: FnOnce(T) -> Inline,
{
    field.map(|value| (code, Value::integer(encode(value))))
}
