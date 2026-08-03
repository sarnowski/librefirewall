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
//! # An observation carries the decision, not only the bytes
//!
//! A record is a frame *and* what the appliance concluded about it: the verdict
//! and its reason, the flow it belongs to as an (index, generation) pair with the
//! classification and state that go with it, the rule that decided it, and the
//! lifecycle or policy event it caused. That is what lets the recorder write a
//! connection history rather than a second copy of the traffic, and it is why
//! [`TapDecision`] exists as one value: the combinations that mean nothing — a
//! flow with no classification, a close with no terminal state, a rule on a
//! decision the filter never took — are unrepresentable in what a first-party
//! producer builds, and refused by name in what a peer writes.
//!
//! # One observation is about no frame, and says so rather than inventing one
//!
//! The appliance can end a conversation *itself*, by re-deciding the connection
//! table when a policy commits and taking back a flow the new policy would not
//! admit. That is the one thing worth recording that no packet caused: there is no
//! frame, no wire length, no direction and no classification, because there was
//! nothing on a wire. Recording it as a frame would put a fabricated cause into an
//! artifact that is evidence, and leaving it out would make the connection history
//! silent about the one way a conversation ends that an operator asked for.
//!
//! So the ABI carries a third [`TapVerdict`] — [`TapVerdict::Revoked`] — and the
//! absence travels with it as a set of relations a reader checks in both
//! directions: a revocation names a flow and its state, carries no wire length, no
//! captured bytes, no direction, no classification and no rule, and every other
//! observation carries a wire length and a direction. Each half is a named
//! [`TapFault`], so "this record is anchored to no packet" is a property of the
//! encoding rather than a convention a reader is asked to keep.
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

/// Flow classifications this ABI encodes, which is
/// `lfw_flow::Classification::ALL.len()`.
///
/// Restated here on [`TAP_DROP_REASON_COUNT`]'s terms: `wire` is the crate every
/// region's layout is expressed in, and a dependency on `lfw_flow` would forbid
/// the reverse edge for good.
pub const TAP_CLASSIFICATION_COUNT: u32 = 3;

/// Flow states this ABI encodes, which is `lfw_flow::FlowState::ALL.len()` less
/// its vacant state — a slot holding no flow is what *absent* already means
/// here, so encoding it as a state would give one fact two representations.
pub const TAP_FLOW_STATE_COUNT: u32 = 12;

/// Lifecycle and policy events this ABI encodes, which is
/// [`TapEvent::ALL`]'s length.
pub const TAP_EVENT_COUNT: u32 = 7;

/// Rules one generation may carry, which is `pipeline::MAX_RULES`.
///
/// Restated here on [`TAP_DROP_REASON_COUNT`]'s terms. It is what bounds the
/// rule word, so a recorder narrowing it to the two octets its annotation
/// carries is narrowing a value already proved to fit.
pub const TAP_RULE_COUNT: u32 = 256;

/// Set in [`TapAnnotation`]'s flags word for a frame observed on its way out.
pub const TAP_FLAG_OUTBOUND: u32 = 1;

/// Every bit the flags word currently defines. A bit outside this mask is
/// refused rather than ignored, for the reason [`TapFault::ReservedNonZero`]
/// gives.
pub const TAP_FLAGS_KNOWN: u32 = TAP_FLAG_OUTBOUND;

/// Drop reasons this ABI encodes, which is `pipeline::DropReason::ALL.len()`.
///
/// Restated here rather than imported: `wire` is the crate every region's
/// layout is expressed in, and a dependency on `pipeline` would forbid the
/// reverse edge for good. [`TapDropReason`] mirrors that enum the way
/// [`crate::LogRecord`] mirrors `lfw_log::Event` — as integers, in the source
/// enum's declaration order, offset by one so zero can mean *no reason*.
pub const TAP_DROP_REASON_COUNT: u32 = 25;

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

/// What the appliance decided about the observed frame — `pipeline::Verdict`
/// without its payload, which lives in the annotation's own fields.
///
/// pcapng carries it as `epb_verdict`, a custom option of the recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapVerdict {
    Forwarded,
    Dropped,
    /// Neither, because there was no frame: the appliance ended a flow of its own
    /// accord. See this module's header on what such a record does and does not
    /// carry.
    Revoked,
}

impl TapVerdict {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Forwarded => 0,
            Self::Dropped => 1,
            Self::Revoked => 2,
        }
    }

    /// `None` for every other bit pattern, on [`TapDirection::from_bits`]'s
    /// terms.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Forwarded),
            1 => Some(Self::Dropped),
            2 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Why a frame was not forwarded — `pipeline::DropReason` as integers, in that
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
    FlowUnsupportedProtocol,
    FlowFragment,
    FlowMalformed,
    FlowInvalidFlags,
    FlowMidStream,
    FlowInvalidState,
    FlowOutOfWindow,
    FlowNoSuchFlow,
    FlowQuotedInvalid,
    FlowUnsupportedIcmp,
    FlowTableFull,
    FlowBucketFull,
    PolicyDenied,
    NoPolicyMatch,
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
            Self::FlowUnsupportedProtocol => 12,
            Self::FlowFragment => 13,
            Self::FlowMalformed => 14,
            Self::FlowInvalidFlags => 15,
            Self::FlowMidStream => 16,
            Self::FlowInvalidState => 17,
            Self::FlowOutOfWindow => 18,
            Self::FlowNoSuchFlow => 19,
            Self::FlowQuotedInvalid => 20,
            Self::FlowUnsupportedIcmp => 21,
            Self::FlowTableFull => 22,
            Self::FlowBucketFull => 23,
            Self::PolicyDenied => 24,
            Self::NoPolicyMatch => 25,
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
            12 => Some(Self::FlowUnsupportedProtocol),
            13 => Some(Self::FlowFragment),
            14 => Some(Self::FlowMalformed),
            15 => Some(Self::FlowInvalidFlags),
            16 => Some(Self::FlowMidStream),
            17 => Some(Self::FlowInvalidState),
            18 => Some(Self::FlowOutOfWindow),
            19 => Some(Self::FlowNoSuchFlow),
            20 => Some(Self::FlowQuotedInvalid),
            21 => Some(Self::FlowUnsupportedIcmp),
            22 => Some(Self::FlowTableFull),
            23 => Some(Self::FlowBucketFull),
            24 => Some(Self::PolicyDenied),
            25 => Some(Self::NoPolicyMatch),
            _ => None,
        }
    }
}

/// What the appliance's connection tracker made of the frame — `lfw_flow`'s
/// classification vocabulary as integers, in that enum's declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapClassification {
    New,
    Established,
    Related,
}

impl TapClassification {
    /// One higher than the mirrored enum's index, so zero is free to mean *no
    /// flow* and a zeroed slot names none.
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::New => 1,
            Self::Established => 2,
            Self::Related => 3,
        }
    }

    /// `None` for zero — which names no flow rather than a classification this
    /// side failed to decode — and for every value above
    /// [`TAP_CLASSIFICATION_COUNT`].
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            1 => Some(Self::New),
            2 => Some(Self::Established),
            3 => Some(Self::Related),
            _ => None,
        }
    }
}

/// Where a flow stands after the frame — `lfw_flow::FlowState` as integers, in
/// that enum's declaration order, with its vacant state absent.
///
/// Vacant is left out rather than mapped to zero because zero already means
/// *this observation names no flow*: a slot holding nothing and an observation
/// about no slot are the same fact, and giving it two encodings would let a
/// reader see a flow whose state says there is none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapFlowState {
    SynSent,
    SynReceived,
    Established,
    FinWait,
    CloseWait,
    Closing,
    TimeWait,
    Closed,
    UdpUnreplied,
    UdpAssured,
    IcmpUnreplied,
    IcmpReplied,
}

impl TapFlowState {
    /// The mirrored enum's discriminant, which already reserves zero for its
    /// vacant state — so no offset is applied here and the two numberings agree
    /// value for value.
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::SynSent => 1,
            Self::SynReceived => 2,
            Self::Established => 3,
            Self::FinWait => 4,
            Self::CloseWait => 5,
            Self::Closing => 6,
            Self::TimeWait => 7,
            Self::Closed => 8,
            Self::UdpUnreplied => 9,
            Self::UdpAssured => 10,
            Self::IcmpUnreplied => 11,
            Self::IcmpReplied => 12,
        }
    }

    /// `None` for zero — the vacant state, which names no flow — and for every
    /// value above [`TAP_FLOW_STATE_COUNT`].
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            1 => Some(Self::SynSent),
            2 => Some(Self::SynReceived),
            3 => Some(Self::Established),
            4 => Some(Self::FinWait),
            5 => Some(Self::CloseWait),
            6 => Some(Self::Closing),
            7 => Some(Self::TimeWait),
            8 => Some(Self::Closed),
            9 => Some(Self::UdpUnreplied),
            10 => Some(Self::UdpAssured),
            11 => Some(Self::IcmpUnreplied),
            12 => Some(Self::IcmpReplied),
            _ => None,
        }
    }

    /// Whether a flow in this state is over: both closes acknowledged, or a
    /// reset. These are the two ways a conversation ends on a packet, and so
    /// the two a [`TapEvent::FlowClosed`] may carry.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::TimeWait | Self::Closed)
    }
}

/// Which flow the observation is about, as the tracker resolved it.
///
/// The identity is the **(slot, generation) pair** the tracker issues and never
/// the bare slot: slots are reused as connections come and go, so across a ring
/// holding hours of history a bare index would silently merge two unrelated
/// conversations that happened to occupy one slot at different times — and the
/// merge would look ordinary and be wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapFlow {
    pub slot: u32,
    pub generation: u32,
    /// What the frame was to the flow, absent on the one observation no frame
    /// caused: a classification is a statement about a packet, so a revocation
    /// carries none rather than borrowing the last one the flow saw.
    pub classification: Option<TapClassification>,
    pub state: TapFlowState,
}

/// The lifecycle or policy event the frame caused.
///
/// This is what the log recording selects on: an observation carrying one is an
/// event worth a place in the connection history, and one carrying none is a
/// packet the capture holds alone. The vocabulary is deliberately small — every
/// member is a *transition* the appliance made, so the rate is bounded by how
/// fast connections are admitted rather than by the packet rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapEvent {
    /// A flow was opened and the filter admitted the packet that opened it.
    FlowOpened,
    /// An existing flow changed state without ending.
    FlowAdvanced,
    /// A flow reached a state it does not leave. Which one says how it closed.
    FlowClosed,
    /// A rule matched the opening packet and its action is to drop, so the flow
    /// it had just opened was withdrawn.
    PolicyDenied,
    /// No rule was about the opening packet, so the default deny refused it and
    /// the flow it had just opened was withdrawn.
    PolicyNoMatch,
    /// The tracker refused the packet outright, and it never reached the filter.
    /// The drop reason says which refusal.
    FlowRefused,
    /// A newly committed policy no longer admits a conversation it had admitted,
    /// so the appliance took the flow back. The one event no packet caused, which
    /// is why it is the one that carries no frame.
    FlowRevoked,
}

impl TapEvent {
    /// Every event, so a reader's table and this ABI's own bound are built by
    /// iteration rather than by a list that drifts from the enum.
    pub const ALL: [Self; 7] = [
        Self::FlowOpened,
        Self::FlowAdvanced,
        Self::FlowClosed,
        Self::PolicyDenied,
        Self::PolicyNoMatch,
        Self::FlowRefused,
        Self::FlowRevoked,
    ];

    /// One higher than this enum's index, so zero is free to mean *no event*.
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::FlowOpened => 1,
            Self::FlowAdvanced => 2,
            Self::FlowClosed => 3,
            Self::PolicyDenied => 4,
            Self::PolicyNoMatch => 5,
            Self::FlowRefused => 6,
            Self::FlowRevoked => 7,
        }
    }

    /// `None` for zero — which names no event — and for every value above
    /// [`TAP_EVENT_COUNT`].
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            1 => Some(Self::FlowOpened),
            2 => Some(Self::FlowAdvanced),
            3 => Some(Self::FlowClosed),
            4 => Some(Self::PolicyDenied),
            5 => Some(Self::PolicyNoMatch),
            6 => Some(Self::FlowRefused),
            7 => Some(Self::FlowRevoked),
            _ => None,
        }
    }

    /// Whether this event is about a flow the observation must also name.
    #[must_use]
    pub const fn names_a_flow(self) -> bool {
        matches!(
            self,
            Self::FlowOpened | Self::FlowAdvanced | Self::FlowClosed | Self::FlowRevoked
        )
    }

    /// Whether the filter reached a decision naming one of the operator's rules.
    ///
    /// True for exactly the two outcomes a matching rule has. The filter is
    /// consulted once per conversation, on the packet that opens it, so every
    /// other event happened with no rule involved — which is why this is also
    /// the whole of when a rule may appear.
    #[must_use]
    pub const fn names_a_rule(self) -> bool {
        matches!(self, Self::FlowOpened | Self::PolicyDenied)
    }
}

/// Which of the operator's rules decided the frame, identified the way the
/// dataplane identifies one: by its **position** in the running generation.
///
/// Position rather than the document's own id, because position is what the
/// dataplane has — it is the precedence order and the slot the rule's hit
/// counter occupies, and the management domain is what joins it to the id an
/// operator wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapRule(u16);

impl TapRule {
    /// `None` for a position no generation can declare, so a rule that reaches
    /// the region is one the annotation's two octets hold.
    #[must_use]
    pub const fn new(position: usize) -> Option<Self> {
        if position < TAP_RULE_COUNT as usize {
            // Lossless: the bound above is below `u16::MAX`, which the assertion
            // block holds it to.
            Some(Self(position as u16))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn position(self) -> u16 {
        self.0
    }

    /// One higher than the position, so zero is free to mean *no rule matched*.
    const fn to_bits(self) -> u32 {
        self.0 as u32 + 1
    }

    /// `None` for zero — no rule matched — and for every value above
    /// [`TAP_RULE_COUNT`].
    const fn from_bits(bits: u32) -> Option<Self> {
        match bits.checked_sub(1) {
            Some(position) if position < TAP_RULE_COUNT => Some(Self(position as u16)),
            _ => None,
        }
    }
}

/// Everything the appliance decided about one frame, as one value.
///
/// A struct rather than six arguments to [`TapAnnotation::new`] because four of
/// them would be integers, and an argument order slipped between two would put
/// one flow's identity on another's packet in an artifact meant to be evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapDecision {
    pub outcome: TapOutcome,
    /// Which way past the appliance the frame was going, absent on the one
    /// observation no frame caused: a direction is a property of a packet on a
    /// wire, and a revocation happened on none.
    pub direction: Option<TapDirection>,
    /// The configuration generation the decision was taken under.
    pub generation: u32,
    /// The flow the frame belongs to, absent where the tracker resolved none.
    pub flow: Option<TapFlow>,
    /// The rule that decided it, absent where the filter matched none or was
    /// never consulted.
    pub rule: Option<TapRule>,
    /// The lifecycle or policy event it caused, absent where it caused none.
    pub event: Option<TapEvent>,
}

impl TapDecision {
    const fn flow_slot(&self) -> u32 {
        match self.flow {
            Some(flow) => flow.slot,
            None => 0,
        }
    }

    const fn flow_generation(&self) -> u32 {
        match self.flow {
            Some(flow) => flow.generation,
            None => 0,
        }
    }

    const fn classification(&self) -> u32 {
        match self.flow {
            Some(TapFlow {
                classification: Some(classification),
                ..
            }) => classification.to_bits(),
            Some(_) | None => 0,
        }
    }

    const fn flags(&self) -> u32 {
        match self.direction {
            Some(direction) => direction.to_bits(),
            None => 0,
        }
    }

    const fn flow_state(&self) -> u32 {
        match self.flow {
            Some(flow) => flow.state.to_bits(),
            None => 0,
        }
    }

    const fn event(&self) -> u32 {
        match self.event {
            Some(event) => event.to_bits(),
            None => 0,
        }
    }

    const fn rule(&self) -> u32 {
        match self.rule {
            Some(rule) => rule.to_bits(),
            None => 0,
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
    /// The observation is about a flow the appliance ended and about no frame, so
    /// there is nothing that was forwarded or dropped. It carries no reason for
    /// the same reason a forwarded frame does not: the [`TapEvent::FlowRevoked`]
    /// beside it is the whole of why.
    Revoked,
}

impl TapOutcome {
    /// Whether this outcome is about a frame at all, which is what decides every
    /// per-frame field of the record.
    #[must_use]
    pub const fn observes_a_frame(self) -> bool {
        !matches!(self, Self::Revoked)
    }

    const fn verdict(self) -> TapVerdict {
        match self {
            Self::Forwarded => TapVerdict::Forwarded,
            Self::Dropped(_) => TapVerdict::Dropped,
            Self::Revoked => TapVerdict::Revoked,
        }
    }

    const fn drop_reason(self) -> u32 {
        match self {
            Self::Forwarded | Self::Revoked => 0,
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
    flow_slot: u32,
    flow_generation: u32,
    classification: u32,
    event: u32,
    flow_state: u32,
    rule: u32,
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
    ///
    /// Every field a [`TapDecision`] carries is written from that value alone, so
    /// no first-party producer can emit a combination the checks in
    /// [`TapReader::read`] name — a flow's identity without its classification, a
    /// close with no terminal state, a rule on a decision the filter never took.
    #[must_use]
    pub const fn new(
        packet_id: u64,
        timestamp: u64,
        interface_id: u8,
        decision: TapDecision,
    ) -> Self {
        Self {
            packet_id,
            timestamp,
            interface_id: interface_id as u32,
            original_len: 0,
            captured_len: 0,
            verdict: decision.outcome.verdict().to_bits(),
            drop_reason: decision.outcome.drop_reason(),
            flags: decision.flags(),
            generation: decision.generation,
            flow_slot: decision.flow_slot(),
            flow_generation: decision.flow_generation(),
            classification: decision.classification(),
            event: decision.event(),
            flow_state: decision.flow_state(),
            rule: decision.rule(),
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
    /// Which way past the appliance the frame was going, absent where the
    /// observation is about no frame.
    pub direction: Option<TapDirection>,
    /// The configuration generation in force when the frame was observed.
    pub generation: u32,
    /// The flow the frame belongs to, absent where the tracker resolved none.
    pub flow: Option<TapFlow>,
    /// The rule that decided it, absent where the filter matched none or was
    /// never consulted.
    pub rule: Option<TapRule>,
    /// The lifecycle or policy event it caused, absent where it caused none.
    pub event: Option<TapEvent>,
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
    /// A revocation carrying a reason. Its verdict is neither of the two a reason
    /// belongs to, and the event beside it is already the whole of why the flow
    /// ended.
    DropReasonOnRevocation {
        drop_reason: u32,
    },
    /// A revocation claiming a frame was on a wire. Refused rather than trusted
    /// in either direction, because these two words are the whole of how a reader
    /// tells a record about a flow from a record about a packet.
    WireLengthOnRevocation {
        original_len: u32,
        captured_len: u32,
    },
    /// A revocation carrying a direction, which is a property of a packet on a
    /// wire and there was none.
    DirectionOnRevocation {
        flags: u32,
    },
    /// A revocation carrying a classification, which is a statement about a
    /// packet.
    ClassificationOnRevocation {
        classification: u32,
    },
    /// An observation of a frame whose wire length is zero, which no frame the
    /// pipeline reached a decision about can have — it parsed as IPv4 over
    /// Ethernet, so it carried at least the two headers. The mirror of
    /// [`Self::WireLengthOnRevocation`]: without it a peer could write a record
    /// about no packet under an event that claims one.
    WireLengthMissing {
        verdict: u32,
    },
    /// An observation of a frame naming no direction, which the two the ABI
    /// encodes leave no room for.
    DirectionMissing {
        verdict: u32,
    },
    /// A revocation whose event is not [`TapEvent::FlowRevoked`], or that event on
    /// a verdict that is not [`TapVerdict::Revoked`]. The two are one fact written
    /// twice, so a reader that accepted them apart would report a flow ended by a
    /// policy as a frame, or the reverse.
    RevocationEventMismatch {
        verdict: u32,
        event: u32,
    },
    ClassificationUnknown {
        classification: u32,
    },
    FlowStateUnknown {
        flow_state: u32,
    },
    EventUnknown {
        event: u32,
    },
    /// A rule position no generation can declare.
    RuleUnknown {
        rule: u32,
    },
    /// A flow's identity or state with no classification to say what the frame
    /// was to it. Refused rather than read as an unclassified flow, because a
    /// classification is what makes the identity mean anything: without one there
    /// is no statement about whether the slot was opened, advanced or reported
    /// on, and a reader folding events by flow would merge it into whichever
    /// conversation last held the slot.
    FlowWithoutClassification {
        flow_slot: u32,
        flow_generation: u32,
        flow_state: u32,
    },
    /// A classified flow in no state, which is the vacant slot a classification
    /// cannot have been reached against.
    FlowStateMissingOnClassified {
        classification: u32,
    },
    /// A lifecycle event about no flow.
    FlowEventWithoutFlow {
        event: u32,
    },
    /// A close whose state is one a flow leaves, so the record says a
    /// conversation ended and does not say how.
    CloseEventWithoutTerminalState {
        flow_state: u32,
    },
    /// A rule on an event the filter took no part in. The filter is consulted
    /// once per conversation, on the packet that opens it, so an advance, a
    /// close, a tracker refusal and an unmatched policy all happened with no rule
    /// involved — and a rule on one of them would credit a hit to a rule that
    /// never ran.
    RuleOnEventWithoutFilterDecision {
        rule: u32,
        event: u32,
    },
    /// A filter decision naming no rule, which neither of its two outcomes
    /// produces: an admission is a rule whose action is to accept, and a denial
    /// is one whose action is to drop.
    RuleMissingOnFilterDecision {
        event: u32,
    },
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
    flow_slot: AtomicU32,
    flow_generation: AtomicU32,
    classification: AtomicU32,
    event: AtomicU32,
    flow_state: AtomicU32,
    rule: AtomicU32,
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
            flow_slot: AtomicU32::new(0),
            flow_generation: AtomicU32::new(0),
            classification: AtomicU32::new(0),
            event: AtomicU32::new(0),
            flow_state: AtomicU32::new(0),
            rule: AtomicU32::new(0),
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
        self.flow_slot
            .store(annotation.flow_slot, Ordering::Relaxed);
        self.flow_generation
            .store(annotation.flow_generation, Ordering::Relaxed);
        self.classification
            .store(annotation.classification, Ordering::Relaxed);
        self.event.store(annotation.event, Ordering::Relaxed);
        self.flow_state
            .store(annotation.flow_state, Ordering::Relaxed);
        self.rule.store(annotation.rule, Ordering::Relaxed);
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
            flow_slot: self.flow_slot.load(Ordering::Relaxed),
            flow_generation: self.flow_generation.load(Ordering::Relaxed),
            classification: self.classification.load(Ordering::Relaxed),
            event: self.event.load(Ordering::Relaxed),
            flow_state: self.flow_state.load(Ordering::Relaxed),
            rule: self.rule.load(Ordering::Relaxed),
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
            (TapVerdict::Revoked, None) => TapOutcome::Revoked,
            (TapVerdict::Forwarded, Some(reason)) => {
                return Err(TapFault::DropReasonOnForwarded {
                    drop_reason: reason.to_bits(),
                });
            }
            (TapVerdict::Dropped, None) => return Err(TapFault::DropReasonMissingOnDropped),
            (TapVerdict::Revoked, Some(reason)) => {
                return Err(TapFault::DropReasonOnRevocation {
                    drop_reason: reason.to_bits(),
                });
            }
        };

        // The whole of what tells a record about a flow from a record about a
        // packet, checked in both directions before anything downstream reads
        // either: a revocation carries none of the four per-frame facts, and every
        // other observation carries the two that no frame can be without.
        let direction = if outcome.observes_a_frame() {
            if raw.original_len == 0 {
                return Err(TapFault::WireLengthMissing {
                    verdict: raw.verdict,
                });
            }
            match TapDirection::from_bits(raw.flags) {
                Some(direction) => Some(direction),
                None => return Err(TapFault::FlagsUnknown { flags: raw.flags }),
            }
        } else {
            if raw.original_len != 0 || captured_len != 0 {
                return Err(TapFault::WireLengthOnRevocation {
                    original_len: raw.original_len,
                    captured_len,
                });
            }
            if raw.flags != 0 {
                return Err(TapFault::DirectionOnRevocation { flags: raw.flags });
            }
            if raw.classification != 0 {
                return Err(TapFault::ClassificationOnRevocation {
                    classification: raw.classification,
                });
            }
            None
        };
        if outcome.observes_a_frame() == (raw.event == TapEvent::FlowRevoked.to_bits()) {
            return Err(TapFault::RevocationEventMismatch {
                verdict: raw.verdict,
                event: raw.event,
            });
        }

        let decoded = decode_decision(&raw, outcome.observes_a_frame())?;

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
                flow: decoded.flow,
                rule: decoded.rule,
                event: decoded.event,
            },
            target,
        ))
    }
}

/// The flow, the rule and the event a slot's words name, or the first way they
/// cannot be a decision this appliance took.
///
/// Split out of [`TapSlot::read_into`] because it is where most of the checking
/// now lives and none of it touches the payload: the copy out is bounded by a
/// length already established, and every refusal here is about the relations
/// between six words rather than about a bound.
struct Decoded {
    flow: Option<TapFlow>,
    rule: Option<TapRule>,
    event: Option<TapEvent>,
}

/// `observes_a_frame` is the caller's already-checked answer to whether this
/// record is about a packet at all. It is passed in rather than re-derived
/// because the four relations that hang off it are checked in one place — here
/// the only one left is the classification, which a revocation may not carry and
/// every other observation must.
fn decode_decision(raw: &TapAnnotation, observes_a_frame: bool) -> Result<Decoded, TapFault> {
    let classification = match raw.classification {
        0 => None,
        bits => match TapClassification::from_bits(bits) {
            Some(classification) => Some(classification),
            None => {
                return Err(TapFault::ClassificationUnknown {
                    classification: bits,
                });
            }
        },
    };
    let state = match raw.flow_state {
        0 => None,
        bits => match TapFlowState::from_bits(bits) {
            Some(state) => Some(state),
            None => return Err(TapFault::FlowStateUnknown { flow_state: bits }),
        },
    };
    let flow = match (classification, state) {
        (Some(classification), Some(state)) => Some(TapFlow {
            slot: raw.flow_slot,
            generation: raw.flow_generation,
            classification: Some(classification),
            state,
        }),
        // A state with no classification is a flow with no packet, which is
        // exactly a revocation and nothing else: the caller has already refused a
        // classification on one, so reaching here with a frame means an
        // observation of one arrived unclassified.
        (None, Some(state)) if !observes_a_frame => Some(TapFlow {
            slot: raw.flow_slot,
            generation: raw.flow_generation,
            classification: None,
            state,
        }),
        (None, None) => {
            if raw.flow_slot != 0 || raw.flow_generation != 0 {
                return Err(TapFault::FlowWithoutClassification {
                    flow_slot: raw.flow_slot,
                    flow_generation: raw.flow_generation,
                    flow_state: raw.flow_state,
                });
            }
            None
        }
        (None, Some(_)) => {
            return Err(TapFault::FlowWithoutClassification {
                flow_slot: raw.flow_slot,
                flow_generation: raw.flow_generation,
                flow_state: raw.flow_state,
            });
        }
        (Some(_), None) => {
            return Err(TapFault::FlowStateMissingOnClassified {
                classification: raw.classification,
            });
        }
    };

    let event = match raw.event {
        0 => None,
        bits => match TapEvent::from_bits(bits) {
            Some(event) => Some(event),
            None => return Err(TapFault::EventUnknown { event: bits }),
        },
    };
    let rule = match raw.rule {
        0 => None,
        bits => match TapRule::from_bits(bits) {
            Some(rule) => Some(rule),
            None => return Err(TapFault::RuleUnknown { rule: bits }),
        },
    };

    if let Some(event) = event {
        if event.names_a_flow() && flow.is_none() {
            return Err(TapFault::FlowEventWithoutFlow { event: raw.event });
        }
        if event == TapEvent::FlowClosed && !flow.is_some_and(|flow| flow.state.is_terminal()) {
            return Err(TapFault::CloseEventWithoutTerminalState {
                flow_state: raw.flow_state,
            });
        }
        if event.names_a_rule() != rule.is_some() {
            return Err(if rule.is_some() {
                TapFault::RuleOnEventWithoutFilterDecision {
                    rule: raw.rule,
                    event: raw.event,
                }
            } else {
                TapFault::RuleMissingOnFilterDecision { event: raw.event }
            });
        }
    } else if rule.is_some() {
        return Err(TapFault::RuleOnEventWithoutFilterDecision {
            rule: raw.rule,
            event: raw.event,
        });
    }
    Ok(Decoded { flow, rule, event })
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
    // A zeroed region is the valid empty state: with both cursors at zero no slot
    // is ever read. A zeroed slot a peer publishes *anyway* is refused, by
    // `TapFault::WireLengthMissing` — it claims a forwarded frame of no length,
    // which no frame the pipeline decided on can be, having parsed as IPv4 over
    // Ethernet. That is a tightening of what a reader accepts and it is the point:
    // the only way to reach one is a forged cursor, and a record about no packet
    // must not be readable as a record about one.
    assert!(TapVerdict::Forwarded.to_bits() == 0);
    assert!(TapDirection::Inbound.to_bits() == 0);
    assert!(TapDropReason::from_bits(0).is_none());
    assert!(MAX_INTERFACES >= 1);
    // The mirrored enum's width, so a reason added to `pipeline::DropReason`
    // without a slot here is caught by the count rather than by a reader.
    assert!(TapDropReason::NoPolicyMatch.to_bits() == TAP_DROP_REASON_COUNT);
    assert!(TapDropReason::from_bits(TAP_DROP_REASON_COUNT).is_some());
    assert!(TapDropReason::from_bits(TAP_DROP_REASON_COUNT + 1).is_none());
    // The four vocabularies the decision words carry, each held to its own
    // width the same way: a member added to the mirrored enum without a slot
    // here is caught by the count rather than by a reader.
    assert!(TapClassification::Related.to_bits() == TAP_CLASSIFICATION_COUNT);
    assert!(TapClassification::from_bits(TAP_CLASSIFICATION_COUNT).is_some());
    assert!(TapClassification::from_bits(TAP_CLASSIFICATION_COUNT + 1).is_none());
    assert!(TapFlowState::IcmpReplied.to_bits() == TAP_FLOW_STATE_COUNT);
    assert!(TapFlowState::from_bits(TAP_FLOW_STATE_COUNT).is_some());
    assert!(TapFlowState::from_bits(TAP_FLOW_STATE_COUNT + 1).is_none());
    assert!(TapEvent::FlowRevoked.to_bits() == TAP_EVENT_COUNT);
    assert!(TapEvent::ALL.len() == TAP_EVENT_COUNT as usize);
    assert!(TapEvent::from_bits(TAP_EVENT_COUNT).is_some());
    assert!(TapEvent::from_bits(TAP_EVENT_COUNT + 1).is_none());
    assert!(TapClassification::from_bits(0).is_none());
    assert!(TapFlowState::from_bits(0).is_none());
    assert!(TapEvent::from_bits(0).is_none());
    // A rule position is encoded one higher than itself, so the last declarable
    // position and nothing above it decodes — and the encoded form stays inside
    // the two octets a recorder's annotation holds it in.
    assert!(TapRule::new(TAP_RULE_COUNT as usize).is_none());
    assert!(TapRule::from_bits(0).is_none());
    assert!(TapRule::from_bits(TAP_RULE_COUNT).is_some());
    assert!(TapRule::from_bits(TAP_RULE_COUNT + 1).is_none());
    assert!(TAP_RULE_COUNT <= u16::MAX as u32);

    assert!(size_of::<TapAnnotation>() == 80);
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
    assert!(offset_of!(TapAnnotation, flow_slot) == 44);
    assert!(offset_of!(TapAnnotation, flow_generation) == 48);
    assert!(offset_of!(TapAnnotation, classification) == 52);
    assert!(offset_of!(TapAnnotation, event) == 56);
    assert!(offset_of!(TapAnnotation, flow_state) == 60);
    assert!(offset_of!(TapAnnotation, rule) == 64);
    assert!(offset_of!(TapAnnotation, _reserved) == 68);

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
    assert!(offset_of!(TapSlot, flow_slot) == offset_of!(TapAnnotation, flow_slot));
    assert!(offset_of!(TapSlot, flow_generation) == offset_of!(TapAnnotation, flow_generation));
    assert!(offset_of!(TapSlot, classification) == offset_of!(TapAnnotation, classification));
    assert!(offset_of!(TapSlot, event) == offset_of!(TapAnnotation, event));
    assert!(offset_of!(TapSlot, flow_state) == offset_of!(TapAnnotation, flow_state));
    assert!(offset_of!(TapSlot, rule) == offset_of!(TapAnnotation, rule));
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
