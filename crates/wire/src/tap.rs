//! The recording tap: a bounded single-producer/single-consumer ring of frame
//! observations, laid out across the two regions its two directions are granted
//! in.
//!
//! Faces two adversaries at once, and they are not the same
//! adversary. The **byzantine neighbour protection domain** writes both cursors, the
//! annotation words and the drop count, so every one of them is a value chosen
//! rather than computed. **Untrusted network traffic** supplies the payload: the
//! forwarder copies frame bytes in, so a slot's payload is attacker-chosen even
//! when the forwarder is entirely correct, and the recorder may treat it as
//! bytes to be written out and never as anything it parses here.
//!
//! # Two regions, because a region is the unit of grant
//!
//! [`TapRecords`] holds the slots, the producer cursor and the producer's drop
//! count; [`TapConsume`] holds the recorder's cursor alone. The forwarder maps
//! the first read-write and the second read-only, and the recorder maps them
//! the other way round — [`crate::LogRecords`]'s split, for the reason its
//! header gives at length: only two regions can give each domain write access to
//! exactly the direction it speaks in, and a recorder that could store into the
//! slots could mint an observation of traffic that never crossed the appliance.
//! That last is the difference that matters here, because the artifact this ring
//! feeds is evidence.
//!
//! The handles carry the asymmetry rather than restating it, as the log ring's
//! do: [`TapWriter`] reaches the consume cursor only through a view with no
//! store on it, and [`TapReader`] is the mirror image.
//!
//! # Fixed slots, because variable-length framing has a wrap
//!
//! A byte-oriented ring must decide what a record spanning the end of the buffer
//! means, and every answer costs something: a length prefix the reader must
//! trust, a wrap marker the writer must reserve room for, or a copy split in
//! two. All three put peer-written arithmetic between the reader and the bytes
//! it addresses. A fixed slot has none: the index is masked, the payload bound
//! is the array's own length, and the only peer-written length is checked by the
//! slicing operation that needs it.
//!
//! The cost is the one this trades for: a slot is [`TAP_SNAP_LEN`] bytes whether
//! the frame filled it or not, so the region is sized by the snap length rather
//! than by the traffic.
//!
//! # The protocol is the log ring's, repeated rather than shared
//!
//! Each side's position lives in domain-private memory and the shared cursor is
//! a *publication* of it, never a value this side reads back — the rule
//! [`crate::LogRecords`] states and `queue::SpscRing` states before it. This is
//! the third repetition of that protocol in the workspace and it is deliberate,
//! on the terms the log ring already set: a ring type generic over its slot
//! would still need its layout pinned per instantiation, which is most of what
//! is written here, and the two readers do not share a signature — a log record
//! is returned by value, while a tap record is an annotation plus a payload the
//! reader must copy out of a slot the producer may reuse.
//!
//! # A full ring refuses the newest record, and never the producer
//!
//! **A tap that backpressured the forwarder would be a traffic-generator denial
//! of service on forwarding**: anyone who can send packets could stall the
//! dataplane by outrunning the recorder's medium, which turns an observability
//! feature into a remote outage. So [`TapWriter::write`] never waits and never
//! evicts. It refuses the *newest* record and counts it, which also keeps the
//! producer inside the slots the recorder has released — a producer that
//! overwrote the slot being read would let a payload be assembled out of two
//! frames and recorded as a third that never existed.
//!
//! `epb_dropcount` is the pcapng field the count lands in, which
//! is why it is a field of the shared region and not a number the producer keeps
//! to itself: a capture that silently omits is worse than one that states how
//! much it omitted.
//!
//! # What each side still achieves against the other
//!
//! * **Flow control is advisory in both directions**, exactly as in the log
//!   ring: a forged cursor presents stale or zeroed slots, or stalls the
//!   producer, and in-bounds is all either side may claim.
//! * **An annotation is untrusted input.** Per-field atomics mean a read
//!   concurrent with a write can yield fields from two different writes: always
//!   a well-formed value, never undefined behaviour, and refused by the checks
//!   in [`TapReader::read`] before anything is recorded.
//! * **A payload the recorder copies is bytes and nothing else.** Its length is
//!   bounded by the slicing operation that produces the destination, so a
//!   `captured_len` of [`u32::MAX`] costs a refusal rather than a read past the
//!   region.

use core::{
    mem::size_of,
    sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
};

use crate::{MAPPING_ALIGN, MAX_INTERFACES};

/// The bytes of a frame a tap slot carries. A frame longer than this is
/// recorded truncated, with the original length preserved.
///
/// ABI rather than a tuning knob: with [`TAP_SLOTS`] it sizes the region the
/// system description reserves, so moving it rebuilds every domain that maps
/// one. 2048 holds a standard 1518-byte Ethernet frame whole and leaves room
/// for the jumbo frames a link may be configured for, without paying the 9 KiB
/// a full jumbo MTU would cost on every slot.
pub const TAP_SNAP_LEN: usize = 2048;

/// Slots one records region holds, of which [`TapRecords::capacity`] are
/// usable. ABI on [`TAP_SNAP_LEN`]'s terms.
///
/// Sized for the recorder's scheduling round rather than for a burst: the ring
/// absorbs what arrives between two drains, and anything beyond that is the
/// medium's throughput problem, which no slot count fixes.
pub const TAP_SLOTS: usize = 64;

/// Words held at zero after [`TapAnnotation`]'s fields, so a field added later
/// takes one of them instead of moving every offset behind it — and with them
/// the struct size, the region size and the system description's reservation.
pub const TAP_RESERVED_WORDS: usize = 3;

/// Set in [`TapAnnotation`]'s flags word for a frame observed on its way out.
pub const TAP_FLAG_OUTBOUND: u32 = 1;

/// Every bit the flags word currently defines. A bit outside this mask is
/// refused rather than ignored, for the reason [`TapFault::ReservedNonZero`]
/// gives.
pub const TAP_FLAGS_KNOWN: u32 = TAP_FLAG_OUTBOUND;

/// Drop reasons this ABI encodes, which is `routing::DropReason::ALL.len()`.
///
/// Restated here rather than imported: `wire` is the crate every region's
/// layout is expressed in, and a dependency on `routing` would forbid the
/// reverse edge for good. [`TapDropReason`] mirrors that enum the way
/// [`crate::LogRecord`] mirrors `lfw_log::Event` — as integers, in the source
/// enum's declaration order, offset by one so zero can mean *no reason*.
pub const TAP_DROP_REASON_COUNT: u32 = 11;

/// Bytes the system description reserves for one records region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const TAP_RECORDS_REGION_SIZE: usize = size_of::<TapRecords>().next_multiple_of(MAPPING_ALIGN);

/// As [`TAP_RECORDS_REGION_SIZE`]. A page for one word is what a region costs
/// when a region is the unit of grant.
pub const TAP_CONSUME_REGION_SIZE: usize = size_of::<TapConsume>().next_multiple_of(MAPPING_ALIGN);

/// The mask that bounds every cursor, and what makes an out-of-range one an
/// in-range index rather than a fault.
const MASK: u32 = (TAP_SLOTS - 1) as u32;

/// Which way past the appliance the observed frame was going.
///
/// pcapng's `epb_flags` direction bits, reduced to the two
/// values a forwarding appliance distinguishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapDirection {
    Inbound,
    Outbound,
}

impl TapDirection {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Inbound => 0,
            Self::Outbound => TAP_FLAG_OUTBOUND,
        }
    }

    /// `None` for a word carrying any bit outside [`TAP_FLAGS_KNOWN`], on
    /// [`crate::Verdict::from_bits`]'s terms: the field is peer-written, so an
    /// undecodable value is input to reject rather than one to coerce.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Inbound),
            TAP_FLAG_OUTBOUND => Some(Self::Outbound),
            _ => None,
        }
    }
}

/// What the appliance decided about the observed frame — `routing::Decision`
/// without its payload, which lives in the annotation's own fields.
///
/// pcapng carries it as `epb_verdict`, a custom option of the recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapVerdict {
    Forwarded,
    Dropped,
}

impl TapVerdict {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Forwarded => 0,
            Self::Dropped => 1,
        }
    }

    /// `None` for every other bit pattern, on [`TapDirection::from_bits`]'s
    /// terms.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Forwarded),
            1 => Some(Self::Dropped),
            _ => None,
        }
    }
}

/// Why a frame was not forwarded — `routing::DropReason` as integers, in that
/// enum's declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapDropReason {
    UnconfiguredIngressPort,
    InterfaceDisabled,
    NotAddressedToUs,
    VlanTagged,
    MartianSource,
    UnroutableDestination,
    AddressedToThisRouter,
    TtlExpired,
    NoRoute,
    EgressIsIngress,
    NoNeighbour,
}

impl TapDropReason {
    /// One higher than the mirrored enum's index, so zero is free to mean *no
    /// reason* and a zeroed slot names none.
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::UnconfiguredIngressPort => 1,
            Self::InterfaceDisabled => 2,
            Self::NotAddressedToUs => 3,
            Self::VlanTagged => 4,
            Self::MartianSource => 5,
            Self::UnroutableDestination => 6,
            Self::AddressedToThisRouter => 7,
            Self::TtlExpired => 8,
            Self::NoRoute => 9,
            Self::EgressIsIngress => 10,
            Self::NoNeighbour => 11,
        }
    }

    /// `None` for zero — which names no reason rather than a reason this side
    /// failed to decode — and for every value above [`TAP_DROP_REASON_COUNT`].
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            1 => Some(Self::UnconfiguredIngressPort),
            2 => Some(Self::InterfaceDisabled),
            3 => Some(Self::NotAddressedToUs),
            4 => Some(Self::VlanTagged),
            5 => Some(Self::MartianSource),
            6 => Some(Self::UnroutableDestination),
            7 => Some(Self::AddressedToThisRouter),
            8 => Some(Self::TtlExpired),
            9 => Some(Self::NoRoute),
            10 => Some(Self::EgressIsIngress),
            11 => Some(Self::NoNeighbour),
            _ => None,
        }
    }
}

/// The verdict and its reason as one value, so the combinations that mean
/// nothing cannot be built.
///
/// On the wire they are two words and a peer may set them independently; here
/// a forwarded frame has no reason to carry and a dropped one cannot fail
/// to. [`TapAnnotation::new`] takes this rather than the two words, so no
/// first-party producer can emit the pairs [`TapFault::DropReasonOnForwarded`]
/// and [`TapFault::DropReasonMissingOnDropped`] name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapOutcome {
    Forwarded,
    Dropped(TapDropReason),
}

impl TapOutcome {
    const fn verdict(self) -> TapVerdict {
        match self {
            Self::Forwarded => TapVerdict::Forwarded,
            Self::Dropped(_) => TapVerdict::Dropped,
        }
    }

    const fn drop_reason(self) -> u32 {
        match self {
            Self::Forwarded => 0,
            Self::Dropped(reason) => reason.to_bits(),
        }
    }
}

/// The annotation a dataplane observation carries alongside the frame.
///
/// Every field is private and the two lengths are absent from
/// [`new`](Self::new) entirely: [`TapWriter::write`] derives `captured_len` from
/// the bytes it actually copied and takes `original_len` beside them, so no
/// producer can state a length its payload does not have. A peer
/// writing the region directly still can, which is what the reader checks.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapAnnotation {
    packet_id: u64,
    timestamp: u64,
    interface_id: u32,
    original_len: u32,
    captured_len: u32,
    verdict: u32,
    drop_reason: u32,
    flags: u32,
    generation: u32,
    _reserved: [u32; TAP_RESERVED_WORDS],
}

impl TapAnnotation {
    /// `packet_id` is the value pcapng carries as `epb_packetid`: the *same*
    /// number on the ingress and the egress observation of one forwarded frame,
    /// which is what lets a reader relate the two rather than infer the relation
    /// by comparing tuples.
    ///
    /// `timestamp` is the raw timestamp-counter reading at observation, not a
    /// wall-clock instant: converting it needs the calibration
    /// [`crate::ClockCalibration`] publishes, and that is the recorder's job,
    /// because a reading converted here would be converted on the dataplane
    /// against a calibration the forwarder would have to re-read per frame.
    #[must_use]
    pub const fn new(
        packet_id: u64,
        timestamp: u64,
        interface_id: u8,
        outcome: TapOutcome,
        direction: TapDirection,
        generation: u32,
    ) -> Self {
        Self {
            packet_id,
            timestamp,
            interface_id: interface_id as u32,
            original_len: 0,
            captured_len: 0,
            verdict: outcome.verdict().to_bits(),
            drop_reason: outcome.drop_reason(),
            flags: direction.to_bits(),
            generation,
            _reserved: [0; TAP_RESERVED_WORDS],
        }
    }
}

/// One observation, with every peer-written field decoded or refused.
///
/// The captured bytes are not a field: [`TapReader::read`] returns them as the
/// slice it filled, so their length is the slice's own and cannot disagree with
/// anything here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedTap {
    pub packet_id: u64,
    /// The raw timestamp-counter reading, still unconverted.
    pub timestamp: u64,
    /// Checked against [`MAX_INTERFACES`], so it indexes an interface table.
    pub interface_id: u8,
    /// The frame's length on the wire, which the captured bytes may be shorter
    /// than and never longer.
    pub original_len: u32,
    pub outcome: TapOutcome,
    pub direction: TapDirection,
    /// The configuration generation in force when the frame was observed.
    pub generation: u32,
}

/// An annotation the producer's bytes cannot be.
///
/// Where several hold, the first in this list is the one reported: the two
/// length faults come first because they are the ones that bound a copy, and a
/// reader that reported a stale verdict while a length was still unchecked
/// would be answering the less important question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapFault {
    /// More captured bytes claimed than a slot can hold. Detected by the
    /// slicing that produces the copy's destination, so the check and the bound
    /// are one operation rather than two that could drift apart.
    CapturedLenPastSnap {
        captured_len: u32,
    },
    /// More bytes captured than the frame had on the wire.
    CapturedLenPastOriginal {
        captured_len: u32,
        original_len: u32,
    },
    /// An interface no configured table has a row for.
    InterfaceUnknown {
        interface_id: u32,
    },
    /// A flags word carrying a bit outside [`TAP_FLAGS_KNOWN`].
    FlagsUnknown {
        flags: u32,
    },
    /// A reserved word left non-zero.
    ///
    /// Refused rather than ignored, which is the opposite of how this crate
    /// treats an alignment `_pad`: padding names nothing ever, while a reserved
    /// word names nothing *yet*. A reader that ignored one would keep ignoring
    /// it on the day it is given a meaning, and the field would be silently
    /// dropped by exactly the readers that most needed rebuilding.
    ReservedNonZero {
        reserved: [u32; TAP_RESERVED_WORDS],
    },
    VerdictUnknown {
        verdict: u32,
    },
    DropReasonUnknown {
        drop_reason: u32,
    },
    /// A forwarded frame carrying a reason it was dropped.
    DropReasonOnForwarded {
        drop_reason: u32,
    },
    /// A dropped frame naming no reason, which no routing decision produces.
    DropReasonMissingOnDropped,
}

/// A frame already cut to what a slot holds, carrying its own length as the
/// `u32` the slot records.
///
/// The bound and the length are established once, in [`take`](Self::take),
/// which is the only constructor — so the recorded `captured_len` cannot
/// disagree with the bytes recorded beside it, and no conversion anywhere else
/// needs a fallible step or a fallback for a case that cannot arise.
struct Snapped<'frame> {
    bytes: &'frame [u8],
    len: u32,
}

impl<'frame> Snapped<'frame> {
    fn take(frame: &'frame [u8]) -> Self {
        match frame.get(..TAP_SNAP_LEN) {
            Some(bytes) => Self {
                bytes,
                len: TAP_SNAP_LEN as u32,
            },
            // `get` answered `None`, so the frame is shorter than
            // [`TAP_SNAP_LEN`] and the cast keeps every bit of its length.
            None => Self {
                bytes: frame,
                len: frame.len() as u32,
            },
        }
    }
}

/// The shared-memory image of one observation: the annotation as atomics,
/// followed by the payload as one atomic per byte.
///
/// Per-byte rather than packed into words for the log slot's reason,
/// which applies with full force to a frame: the payload is a byte sequence
/// taken off a wire, so packing it would make the byte order of the region a
/// thing this crate chooses rather than a thing it mirrors.
///
/// Atomic because a peer may write any slot at any moment, and a non-atomic
/// access racing with that write is undefined behaviour — which is what lets
/// this crate hold its `unsafe` count at zero while two domains write one
/// region. Accesses are `Relaxed`: all the ordering a slot needs is the
/// release/acquire pair on the cursor that publishes it.
#[repr(C)]
struct TapSlot {
    packet_id: AtomicU64,
    timestamp: AtomicU64,
    interface_id: AtomicU32,
    original_len: AtomicU32,
    captured_len: AtomicU32,
    verdict: AtomicU32,
    drop_reason: AtomicU32,
    flags: AtomicU32,
    generation: AtomicU32,
    _reserved: [AtomicU32; TAP_RESERVED_WORDS],
    payload: [AtomicU8; TAP_SNAP_LEN],
}

impl TapSlot {
    /// A function rather than a `const`: a `const` holding an atomic is copied
    /// at each mention, so a store through one is read back by nobody.
    const fn zero() -> Self {
        Self {
            packet_id: AtomicU64::new(0),
            timestamp: AtomicU64::new(0),
            interface_id: AtomicU32::new(0),
            original_len: AtomicU32::new(0),
            captured_len: AtomicU32::new(0),
            verdict: AtomicU32::new(0),
            drop_reason: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            _reserved: [const { AtomicU32::new(0) }; TAP_RESERVED_WORDS],
            payload: [const { AtomicU8::new(0) }; TAP_SNAP_LEN],
        }
    }

    /// Bytes past the payload keep whatever the previous record left there.
    /// Zeroing them would cost [`TAP_SNAP_LEN`] stores per frame on the
    /// dataplane to hide bytes the recorder is entitled to see anyway, and no
    /// reader reaches them: the copy out is bounded by the captured length.
    fn store(&self, annotation: &TapAnnotation, original_len: u32, payload: &Snapped<'_>) {
        self.packet_id
            .store(annotation.packet_id, Ordering::Relaxed);
        self.timestamp
            .store(annotation.timestamp, Ordering::Relaxed);
        self.interface_id
            .store(annotation.interface_id, Ordering::Relaxed);
        self.original_len.store(original_len, Ordering::Relaxed);
        self.verdict.store(annotation.verdict, Ordering::Relaxed);
        self.drop_reason
            .store(annotation.drop_reason, Ordering::Relaxed);
        self.flags.store(annotation.flags, Ordering::Relaxed);
        self.generation
            .store(annotation.generation, Ordering::Relaxed);
        for (cell, word) in self._reserved.iter().zip(annotation._reserved) {
            cell.store(word, Ordering::Relaxed);
        }
        for (cell, byte) in self.payload.iter().zip(payload.bytes) {
            cell.store(*byte, Ordering::Relaxed);
        }
        // Last, and the reason it is last is the reader's: a length published
        // before the bytes it counts would let a recorder copy out a payload
        // half of which belongs to the previous frame. The `Release` that makes
        // this visible is the producer cursor's, one store later.
        self.captured_len.store(payload.len, Ordering::Relaxed);
    }

    /// Every annotation word, exactly as the producer left them.
    fn load(&self) -> TapAnnotation {
        let mut reserved = [0; TAP_RESERVED_WORDS];
        for (word, cell) in reserved.iter_mut().zip(&self._reserved) {
            *word = cell.load(Ordering::Relaxed);
        }
        TapAnnotation {
            packet_id: self.packet_id.load(Ordering::Relaxed),
            timestamp: self.timestamp.load(Ordering::Relaxed),
            interface_id: self.interface_id.load(Ordering::Relaxed),
            original_len: self.original_len.load(Ordering::Relaxed),
            captured_len: self.captured_len.load(Ordering::Relaxed),
            verdict: self.verdict.load(Ordering::Relaxed),
            drop_reason: self.drop_reason.load(Ordering::Relaxed),
            flags: self.flags.load(Ordering::Relaxed),
            generation: self.generation.load(Ordering::Relaxed),
            _reserved: reserved,
        }
    }

    /// One observation, checked and copied out, or the first fault its words
    /// carry.
    ///
    /// `into` is a whole snap-length array rather than a slice, which is what
    /// removes a "buffer too small" case from the signature: the only length
    /// that can be wrong is the peer's, and `get_mut` refuses that one while
    /// producing the destination it bounds.
    fn read_into<'buf>(
        &self,
        into: &'buf mut [u8; TAP_SNAP_LEN],
    ) -> Result<(CheckedTap, &'buf [u8]), TapFault> {
        let raw = self.load();

        let captured_len = raw.captured_len;
        let Some(target) = into.get_mut(..captured_len as usize) else {
            return Err(TapFault::CapturedLenPastSnap { captured_len });
        };
        if captured_len > raw.original_len {
            return Err(TapFault::CapturedLenPastOriginal {
                captured_len,
                original_len: raw.original_len,
            });
        }

        // Two refusals rather than one, because two things can be wrong with the
        // word: it may not be a `u8` at all, and a `u8` may still name no row.
        let Ok(interface_id) = u8::try_from(raw.interface_id) else {
            return Err(TapFault::InterfaceUnknown {
                interface_id: raw.interface_id,
            });
        };
        if usize::from(interface_id) >= MAX_INTERFACES {
            return Err(TapFault::InterfaceUnknown {
                interface_id: raw.interface_id,
            });
        }

        if raw._reserved.iter().any(|word| *word != 0) {
            return Err(TapFault::ReservedNonZero {
                reserved: raw._reserved,
            });
        }

        let Some(direction) = TapDirection::from_bits(raw.flags) else {
            return Err(TapFault::FlagsUnknown { flags: raw.flags });
        };

        let Some(verdict) = TapVerdict::from_bits(raw.verdict) else {
            return Err(TapFault::VerdictUnknown {
                verdict: raw.verdict,
            });
        };
        let reason = if raw.drop_reason == 0 {
            None
        } else {
            match TapDropReason::from_bits(raw.drop_reason) {
                Some(reason) => Some(reason),
                None => {
                    return Err(TapFault::DropReasonUnknown {
                        drop_reason: raw.drop_reason,
                    });
                }
            }
        };
        let outcome = match (verdict, reason) {
            (TapVerdict::Forwarded, None) => TapOutcome::Forwarded,
            (TapVerdict::Dropped, Some(reason)) => TapOutcome::Dropped(reason),
            (TapVerdict::Forwarded, Some(reason)) => {
                return Err(TapFault::DropReasonOnForwarded {
                    drop_reason: reason.to_bits(),
                });
            }
            (TapVerdict::Dropped, None) => return Err(TapFault::DropReasonMissingOnDropped),
        };

        for (byte, cell) in target.iter_mut().zip(&self.payload) {
            *byte = cell.load(Ordering::Relaxed);
        }

        Ok((
            CheckedTap {
                packet_id: raw.packet_id,
                timestamp: raw.timestamp,
                interface_id,
                original_len: raw.original_len,
                outcome,
                direction,
                generation: raw.generation,
            },
            target,
        ))
    }
}

/// The records half of the ring: the slots, the cursor that publishes them and
/// the producer's count of what it refused. The forwarder maps this read-write
/// and the recorder read-only.
///
/// Every field is private and no accessor reaches one, so the ordering each
/// word carries is a property of this type rather than a convention its users
/// are asked to keep.
#[repr(C)]
pub struct TapRecords {
    tail: AtomicU32,
    dropped: AtomicU32,
    slots: [TapSlot; TAP_SLOTS],
}

impl TapRecords {
    /// As [`TapSlot::zero`]: a function, because a `const` holding an atomic is
    /// copied at each mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            tail: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            slots: [const { TapSlot::zero() }; TAP_SLOTS],
        }
    }

    /// How many observations the ring holds at once. One slot is always left
    /// unused, which tells a full ring from an empty one without a flag.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        MASK as usize
    }

    /// Take the producing side's handle: this region to write, the recorder's
    /// cursor to read.
    ///
    /// Take it **once** per ring and keep it: a second restarts at position zero
    /// and overwrites slots the first published. No type stops it, for
    /// [`crate::LogRecords::writer`]'s reason — the flag that would close it
    /// could only live in a region a peer writes.
    #[must_use]
    pub const fn writer<'ring>(&'ring self, consume: &'ring TapConsume) -> TapWriter<'ring> {
        TapWriter {
            records: self,
            consume: PeerConsume::new(consume),
            tail: 0,
            dropped: 0,
        }
    }

    /// The slot a cursor names. Total by construction: `MASK` is one below
    /// [`TAP_SLOTS`], which the assertion block below holds to a power of two,
    /// so the masked value indexes the array for every `u32` there is.
    fn slot(&self, at: u32) -> &TapSlot {
        &self.slots[(at & MASK) as usize]
    }
}

impl Default for TapRecords {
    fn default() -> Self {
        Self::zero()
    }
}

/// The consume half of the ring: how far the recorder has read, and nothing
/// else. The recorder maps this read-write and the forwarder read-only.
///
/// Its own region rather than a field of [`TapRecords`], which is what denies
/// the forwarder the one write that would matter here — forging the cursor that
/// decides which of its slots it may reuse, and so overwriting an observation
/// the recorder has not yet written to the medium while reporting no loss.
#[repr(C)]
pub struct TapConsume {
    head: AtomicU32,
}

impl TapConsume {
    /// As [`TapRecords::zero`].
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            head: AtomicU32::new(0),
        }
    }

    /// Take the draining side's handle: this region to write, the producer's
    /// records to read. On [`TapRecords::writer`]'s terms.
    #[must_use]
    pub const fn reader<'ring>(&'ring self, records: &'ring TapRecords) -> TapReader<'ring> {
        TapReader {
            consume: self,
            records: PeerRecords::new(records),
            head: 0,
            refused: 0,
        }
    }
}

impl Default for TapConsume {
    fn default() -> Self {
        Self::zero()
    }
}

/// Each side's view of the region it reads and may not write.
///
/// A module of their own, and that is the whole mechanism: the borrow each view
/// wraps is private to it, so nothing outside — including the two handles in the
/// parent — can reach past a view to the region behind it.
mod peer {
    use core::sync::atomic::Ordering;

    use super::{MASK, TapConsume, TapRecords, TapSlot};

    /// The records region as the recorder holds it: loads only.
    pub(super) struct PeerRecords<'ring>(&'ring TapRecords);

    impl<'ring> PeerRecords<'ring> {
        pub(super) const fn new(records: &'ring TapRecords) -> Self {
            Self(records)
        }

        pub(super) const fn capacity(&self) -> usize {
            self.0.capacity()
        }

        /// Masked into range because it is attacker-controlled. Acquire so the
        /// producer's slot writes are visible before this side reads them.
        pub(super) fn tail(&self) -> u32 {
            self.0.tail.load(Ordering::Acquire) & MASK
        }

        pub(super) fn dropped(&self) -> u32 {
            self.0.dropped.load(Ordering::Acquire)
        }

        pub(super) fn slot(&self, at: u32) -> &TapSlot {
            self.0.slot(at)
        }
    }

    /// The consume region as the forwarder holds it, on [`PeerRecords`]'s terms.
    pub(super) struct PeerConsume<'ring>(&'ring TapConsume);

    impl<'ring> PeerConsume<'ring> {
        pub(super) const fn new(consume: &'ring TapConsume) -> Self {
            Self(consume)
        }

        /// On [`PeerRecords::tail`]'s terms, for the cursor going the other way.
        pub(super) fn head(&self) -> u32 {
            self.0.head.load(Ordering::Acquire) & MASK
        }
    }
}

use peer::{PeerConsume, PeerRecords};

/// An observation the ring had no slot for. Carries the producer's running
/// total so a caller that only ever sees refusals still has the number to
/// expose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapRingFull {
    /// Observations this producer has refused, saturating at [`u32::MAX`]
    /// rather than wrapping: a wrap would turn a sustained flood back into a
    /// small number.
    pub dropped: u32,
}

/// Why [`TapWriter::write`] recorded nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapWriteError {
    /// The recorder has not released a slot. Counted, and the only variant that
    /// is: the observation was offered and lost, which is what
    /// `epb_dropcount` reports.
    Full(TapRingFull),
    /// More bytes to record than the frame is said to have had on the wire,
    /// which is a first-party inconsistency rather than a peer's. Refused
    /// rather than clamped, because clamping either length would silently
    /// change what the record claims, and not counted, because
    /// nothing well-formed was ever offered.
    FrameExceedsWireLength { frame_len: usize, original_len: u32 },
}

/// The producing side, holding this domain's publish position and its own drop
/// count in private memory.
pub struct TapWriter<'ring> {
    records: &'ring TapRecords,
    consume: PeerConsume<'ring>,
    tail: u32,
    /// The authoritative count, published to the records region but never read
    /// back from it: a count this side reads out of shared memory could be
    /// walked backwards by the domain it accuses.
    dropped: u32,
}

impl TapWriter<'_> {
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.records.capacity()
    }

    /// Record one observation, publishing it to the recorder, and answer how
    /// many payload bytes crossed.
    ///
    /// `frame` is copied up to [`TAP_SNAP_LEN`] bytes and `original_len` is
    /// recorded whole, so a truncated capture still says what it truncated.
    ///
    /// **This never waits and never evicts.** A full ring costs the newest
    /// observation, never the oldest and never the producer's progress: a tap
    /// that backpressured the forwarder would let anyone who can send packets
    /// stall the dataplane by outrunning the recorder's medium.
    ///
    /// # Errors
    /// [`TapWriteError::Full`] when the ring *appears* full, having counted the
    /// drop — "appears" because fullness is judged against the recorder's
    /// published cursor, which that domain may forge either way — and
    /// [`TapWriteError::FrameExceedsWireLength`] when more bytes were handed
    /// over than the frame is said to have carried.
    pub fn write(
        &mut self,
        annotation: &TapAnnotation,
        original_len: u32,
        frame: &[u8],
    ) -> Result<usize, TapWriteError> {
        let payload = Snapped::take(frame);
        // Before the fullness test, so a malformed call is never reported as a
        // drop: a drop is an observation the ring lost, and this one was never
        // one the ring could have held.
        if payload.len > original_len {
            return Err(TapWriteError::FrameExceedsWireLength {
                frame_len: frame.len(),
                original_len,
            });
        }

        let next = self.tail.wrapping_add(1) & MASK;
        if next == self.consume.head() {
            self.dropped = self.dropped.saturating_add(1);
            self.records.dropped.store(self.dropped, Ordering::Release);
            return Err(TapWriteError::Full(TapRingFull {
                dropped: self.dropped,
            }));
        }

        self.records
            .slot(self.tail)
            .store(annotation, original_len, &payload);
        self.tail = next;
        // Release: every store above must be visible to the recorder before the
        // cursor that publishes them is.
        self.records.tail.store(next, Ordering::Release);
        Ok(payload.bytes.len())
    }

    /// Observations this producer has refused for want of a slot.
    #[must_use]
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// A best-effort instantaneous estimate of how many observations are queued.
    ///
    /// One operand is the recorder's published cursor, so under a hostile
    /// recorder this is an arbitrary number in `0..=capacity()`. Never size a
    /// following batch from it; drive writes from [`write`](Self::write)'s
    /// `Result`.
    #[must_use]
    pub fn len(&self) -> usize {
        (self.tail.wrapping_sub(self.consume.head()) & MASK) as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The draining side, holding this domain's consume position and its own tally
/// of refused observations in private memory.
pub struct TapReader<'ring> {
    consume: &'ring TapConsume,
    records: PeerRecords<'ring>,
    head: u32,
    refused: u32,
}

impl TapReader<'_> {
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.records.capacity()
    }

    /// Read one observation into `into`, answering it and the payload bytes that
    /// came with it.
    ///
    /// The outer `None` means only that nothing is queued *at this instant*,
    /// judged against the producer's published cursor; a later call may return
    /// `Some`. The inner `Err` is an annotation the producer's bytes cannot be,
    /// which is counted by [`refused`](Self::refused) and is a fact about the
    /// peer rather than a reason to stop draining.
    ///
    /// The payload is copied *before* this side's cursor advances, so a
    /// producer keeping to the protocol cannot reuse the slot underneath the
    /// copy. One that does not keep to it corrupts its own record and nothing
    /// else.
    pub fn read<'buf>(
        &mut self,
        into: &'buf mut [u8; TAP_SNAP_LEN],
    ) -> Option<Result<(CheckedTap, &'buf [u8]), TapFault>> {
        if self.head == self.records.tail() {
            return None;
        }
        let read = self.records.slot(self.head).read_into(into);
        self.head = self.head.wrapping_add(1) & MASK;
        self.consume.head.store(self.head, Ordering::Release);
        if read.is_err() {
            self.refused = self.refused.saturating_add(1);
        }
        Some(read)
    }

    /// Read at most `limit` observations, and never more than
    /// [`capacity`](Self::capacity) however large `limit` is, handing each to
    /// `visit` with the bytes it carried — empty where the annotation was
    /// refused. Answers how many were handed over.
    ///
    /// Both bounds matter and neither is the peer's. `limit` is the caller's
    /// budget per scheduling round; the capacity clamp is what makes a single
    /// drain finite for *any* caller, including one that passed [`usize::MAX`].
    /// A peer that keeps advancing its published cursor keeps
    /// [`read`](Self::read) returning `Some`, so an unbounded loop over it never
    /// returns and the recorder stops progressing on anything else.
    /// [`len`](Self::len) must not supply either bound, being peer-influenced.
    ///
    /// A callback rather than an iterator because the item borrows `into`: an
    /// iterator would have to hand out a slice of a buffer its next step
    /// overwrites, which is a shape the borrow checker rejects and a caller
    /// should not want.
    pub fn drain(
        &mut self,
        limit: usize,
        into: &mut [u8; TAP_SNAP_LEN],
        mut visit: impl FnMut(Result<(CheckedTap, &[u8]), TapFault>),
    ) -> usize {
        let bound = if limit < self.capacity() {
            limit
        } else {
            self.capacity()
        };
        let mut taken = 0;
        while taken < bound {
            let Some(read) = self.read(into) else { break };
            visit(read);
            taken += 1;
        }
        taken
    }

    /// Observations whose annotation decoded to nothing, since this handle was
    /// taken. Saturating, on [`TapRingFull::dropped`]'s terms.
    #[must_use]
    pub const fn refused(&self) -> u32 {
        self.refused
    }

    /// What the producer says it refused for want of a slot — the value pcapng
    /// carries as `epb_dropcount`. The producer's claim about itself, so it is a
    /// number to record and never one to decide under.
    #[must_use]
    pub fn dropped_by_writer(&self) -> u32 {
        self.records.dropped()
    }

    /// As best-effort as [`TapWriter::len`], and bounded the same way.
    #[must_use]
    pub fn len(&self) -> usize {
        (self.records.tail().wrapping_sub(self.head) & MASK) as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// Two cross-PD shared-memory ABIs: pin both layouts so a field reorder or a size
// change is a compile error rather than a silently corrupted mapping.
const _: () = {
    use core::mem::{align_of, offset_of};

    assert!(TAP_SLOTS.is_power_of_two(), "the cursor mask needs one");
    assert!(TAP_SLOTS >= 2, "a ring of one slot holds nothing");
    assert!(TAP_SLOTS - 1 <= u32::MAX as usize, "cursors are u32");
    // Every captured length is compared as a `u32` and then used as a `usize`,
    // which is exact only while a `usize` is at least as wide; x86_64's is.
    assert!(size_of::<usize>() >= size_of::<u32>());
    assert!(TAP_SNAP_LEN <= u32::MAX as usize);
    // A zeroed region is the valid empty state: no observation is published,
    // and a slot that a peer publishes unchanged decodes as an inbound,
    // forwarded, zero-length observation on interface 0 rather than as a fault.
    assert!(TapVerdict::Forwarded.to_bits() == 0);
    assert!(TapDirection::Inbound.to_bits() == 0);
    assert!(TapDropReason::from_bits(0).is_none());
    assert!(MAX_INTERFACES >= 1);
    // The mirrored enum's width, so a reason added to `routing::DropReason`
    // without a slot here is caught by the count rather than by a reader.
    assert!(TapDropReason::NoNeighbour.to_bits() == TAP_DROP_REASON_COUNT);
    assert!(TapDropReason::from_bits(TAP_DROP_REASON_COUNT).is_some());
    assert!(TapDropReason::from_bits(TAP_DROP_REASON_COUNT + 1).is_none());

    assert!(size_of::<TapAnnotation>() == 56);
    assert!(align_of::<TapAnnotation>() == 8);
    assert!(offset_of!(TapAnnotation, packet_id) == 0);
    assert!(offset_of!(TapAnnotation, timestamp) == 8);
    assert!(offset_of!(TapAnnotation, interface_id) == 16);
    assert!(offset_of!(TapAnnotation, original_len) == 20);
    assert!(offset_of!(TapAnnotation, captured_len) == 24);
    assert!(offset_of!(TapAnnotation, verdict) == 28);
    assert!(offset_of!(TapAnnotation, drop_reason) == 32);
    assert!(offset_of!(TapAnnotation, flags) == 36);
    assert!(offset_of!(TapAnnotation, generation) == 40);
    assert!(offset_of!(TapAnnotation, _reserved) == 44);

    // Expressing the annotation as atomics must leave the region the recorder
    // maps byte-identical to the plain image: same size, same alignment, every
    // field where the plain image puts it.
    assert!(offset_of!(TapSlot, packet_id) == offset_of!(TapAnnotation, packet_id));
    assert!(offset_of!(TapSlot, timestamp) == offset_of!(TapAnnotation, timestamp));
    assert!(offset_of!(TapSlot, interface_id) == offset_of!(TapAnnotation, interface_id));
    assert!(offset_of!(TapSlot, original_len) == offset_of!(TapAnnotation, original_len));
    assert!(offset_of!(TapSlot, captured_len) == offset_of!(TapAnnotation, captured_len));
    assert!(offset_of!(TapSlot, verdict) == offset_of!(TapAnnotation, verdict));
    assert!(offset_of!(TapSlot, drop_reason) == offset_of!(TapAnnotation, drop_reason));
    assert!(offset_of!(TapSlot, flags) == offset_of!(TapAnnotation, flags));
    assert!(offset_of!(TapSlot, generation) == offset_of!(TapAnnotation, generation));
    assert!(offset_of!(TapSlot, _reserved) == offset_of!(TapAnnotation, _reserved));
    // The payload begins exactly where the annotation ends, so a slot is the
    // annotation followed by the frame with nothing between them.
    assert!(offset_of!(TapSlot, payload) == size_of::<TapAnnotation>());
    assert!(align_of::<TapSlot>() == align_of::<TapAnnotation>());
    assert!(size_of::<TapSlot>() == size_of::<TapAnnotation>() + TAP_SNAP_LEN);

    assert!(offset_of!(TapRecords, tail) == 0);
    assert!(offset_of!(TapRecords, dropped) == 4);
    assert!(offset_of!(TapRecords, slots) == 8);
    assert!(align_of::<TapRecords>() == align_of::<AtomicU64>());
    assert!(size_of::<TapRecords>() == 8 + TAP_SLOTS * size_of::<TapSlot>());

    assert!(offset_of!(TapConsume, head) == 0);
    assert!(align_of::<TapConsume>() == align_of::<AtomicU32>());
    assert!(size_of::<TapConsume>() == 4);

    // Each region must hold its type and be mappable.
    assert!(TAP_RECORDS_REGION_SIZE >= size_of::<TapRecords>());
    assert!(TAP_RECORDS_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(TAP_CONSUME_REGION_SIZE >= size_of::<TapConsume>());
    assert!(TAP_CONSUME_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
