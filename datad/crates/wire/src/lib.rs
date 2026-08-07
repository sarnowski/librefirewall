//! The layout of the descriptor protection domains exchange over the
//! shared-memory dataplane queues.
//!
//! Faces the byzantine neighbour protection domain: everything read
//! out of a shared region here is peer-written input. The descriptor is fixed
//! but not checked — whether one is in bounds is a question about the pool it
//! indexes, so only the domain that owns that pool can answer it. The
//! configuration image is fixed *and* checked, because every rule about it is a
//! rule about this ABI and no later owner knows more than the layout does.
//!
//! Every field is a little-endian `u32` and no byte-swapping code exists,
//! because x86_64 is the only target: the native image of a
//! `#[repr(C)]` struct of `u32`s already *is* the wire image. The byte-image
//! tests below exist so a port to a big-endian target fails them rather than
//! silently shipping swapped descriptors. That fixes the descriptor as a peer
//! domain reads it, and says nothing about byte order inside packet payloads.
//!
//! The verdict rides in the descriptor because a domain that decides against a
//! frame cannot return its buffer: a return is a produce on a free ring that
//! already has one producer. One `u32` moves the decision to the domain that
//! owns that producer, and costs no new grant.
//!
//! The configuration handover is the same kind of object and is here for the
//! same reason. A [`ConfigImage`] is an already-validated model as fixed-layout
//! POD, so the domain that applies it needs neither a parser nor an allocator —
//! keeping the document parser out of the dataplane is the whole point of
//! validating in a separate domain. [`ConfigImage::check`] is what turns one
//! into values a domain can decide under: it refuses or decodes every field,
//! and bounds both arrays by the capacities below rather than by the count the
//! writer put in the region.
//!
//! It holds the image to the *whole* rule set rather than to its fields alone,
//! because the domain that writes the region is the one that parses an
//! attacker's document: a rule the writer alone enforced is a rule a compromised
//! writer does not enforce. One call sees every entry at once, so the rules
//! about a *pair* of them are decidable here — and what is not is named on the
//! function.
//!
//! Holding every rule is still not enough on its own, and that is the sharp
//! part: a copy taken while the writer publishes again can be *two* images, one
//! field from each, and every field-level rule holds of such a copy because
//! every field of it is a field some publisher wrote. What refuses one is the
//! whole-image machinery around the fields — a counter the publisher raises
//! before the bytes move and a reader compares across its copy, and a digest of
//! the image's own bytes that a blend does not match. The counter is what makes
//! a blend unreachable; the digest is what makes one visible if it ever is.
//!
//! The domain that writes the handover only ever holds a shared reference to
//! the region, because no attach path mints a `&mut` to memory a second domain
//! maps. So the image in it is expressed as atomics rather than plain fields:
//! that is what lets a writer exist here without `unsafe`, and the assertions
//! below hold the result byte-identical to the plain image the reader maps.
//!
//! # A region's layout is declared once, and the trade that buys
//!
//! The plain image, the atomic mirror and the offset assertions are three
//! transcriptions of one layout, and they are emitted from one declaration by
//! `shared_image!` rather than written out three times. The cost is real and is
//! worth naming: a struct behind a macro is a struct a reader cannot grep for a
//! field of, and rustdoc shows the expansion rather than the source. What it
//! buys is that the three cannot disagree — a mirror that drifted from its
//! image would corrupt every generation that crosses, silently, and no amount
//! of reading one of the three catches it.
//!
//! The trade is only worth it while the declaration stays a *byte map*: each
//! field states the offset it sits at, padding says that it is padding, and the
//! macro asserts every one of those offsets against what the compiler laid out.
//! A reader answering "what is at offset 12" reads one column of one list. A
//! macro that computed the offsets instead of checking them, or that decided
//! anything about what a field *means*, would have taken the readability and
//! given back nothing — so nothing here validates a value, and every semantic
//! rule about a region stays hand-written below where it can be read as a rule.
//! [`ConfigImage`] stays that plain value — what a writer composes and a reader
//! copies out. Its words move `Relaxed` under the counter that brackets a
//! publication, and nothing stops the writer publishing again the moment a
//! reader is done, which is why a [`CheckedConfig`] owns decoded values rather
//! than borrowing.
//!
//! Four more objects of the same kind follow, all here because a region's
//! layout cannot be expressed in terms of the crate that reads it: the log
//! transport, whose [`LogRecord`] is `lfw_log::Event` reduced to integers and
//! whose two halves are one region per direction as the handover is;
//! [`ClockCalibration`] under a seqlock; the recording tap [`TapRecords`] feeds;
//! and the window a recording is downloaded through. Each decodes peer-written
//! bytes first — the last step before a hostile writer reaches a serial
//! line, or before those bytes reach a file offered as evidence.

#![cfg_attr(not(test), no_std)]

mod clock;
mod config_rule;
mod download;
mod image;
mod log_record;
mod log_ring;
mod log_slot;
mod relay;
mod signing;
mod submission;
mod tap;

use core::{
    fmt,
    mem::{align_of, offset_of, size_of},
    sync::atomic::{AtomicU8, AtomicU32, Ordering, fence},
};

pub use clock::{CLOCK_CALIBRATION_REGION_SIZE, CalibrationImage, ClockCalibration, LOAD_ATTEMPTS};
pub use config_rule::{ConfigRule, Enforcement};
pub use download::{
    DOWNLOAD_REPLY_REGION_SIZE, DOWNLOAD_REQUEST_REGION_SIZE, DOWNLOAD_WINDOW_LEN, DownloadDemand,
    DownloadFault, DownloadPoll, DownloadRefusal, DownloadReply, DownloadRequest,
    DownloadRequester, DownloadResponder, DownloadSink, DownloadStatus, PendingDownload,
};
pub use log_record::{
    CauseImage, CheckedBody, CheckedCause, CheckedDetail, CheckedIdentifier, CheckedOperands,
    CheckedRecord, CheckedStamp, CheckedText, CheckedValue, IdentifierImage, LOG_CAUSE_BYTES,
    LOG_CHANGE_KIND_COUNT, LOG_DIAL_OUTCOME_COUNT, LOG_DOMAIN_COUNT, LOG_DOMAIN_STATE_COUNT,
    LOG_FIELD_COUNT, LOG_GENERATION_OUTCOME_COUNT, LOG_IDENTIFIER_BYTES, LOG_NEXT_HOP_VIA_COUNT,
    LOG_OBJECT_KIND_COUNT, LOG_OFFERED_POINTS, LOG_ONBOARD_END_COUNT, LOG_ONBOARD_OUTCOME_COUNT,
    LOG_OPERANDS, LOG_PRIMITIVE_COUNT, LOG_REJECT_REASON_COUNT, LOG_TLS_INCOMPATIBLE_COUNT,
    LOG_TLS_REFUSAL_COUNT, LogDetailKind, LogKind, LogRecord, LogRecordError, LogStampKind,
    LogText, LogValueKind, TextFault, TextImage, ValueImage,
};
pub use log_ring::{
    LOG_CONSUME_REGION_SIZE, LOG_RECORDS_REGION_SIZE, LOG_RING_SLOTS, LogConsume, LogDrain,
    LogReader, LogRecords, LogRingFull, LogWriter,
};
pub use relay::{
    MAX_RELAY_PAYLOAD, PendingRelay, RELAY_REPLY_REGION_SIZE, RELAY_REQUEST_REGION_SIZE, RelayBusy,
    RelayDemand, RelayEnding, RelayFault, RelayOperation, RelayPoll, RelayRefusal, RelayReply,
    RelayRequest, RelayRequester, RelayResponder, RelayStatus,
};
pub use signing::{
    DEVICE_ID_LEN, DeviceIdentity, MAX_CERTIFICATE_LEN, MAX_SIGN_MESSAGE, MAX_SIGNATURE_LEN,
    PUBLIC_KEY_LEN, PendingSignature, SIGN_REPLY_REGION_SIZE, SIGN_REQUEST_REGION_SIZE,
    SignAnswerBuffer, SignDemand, SignFault, SignOperation, SignPoll, SignRefusal, SignReply,
    SignRequest, SignRequester, SignResponder, SignStatus,
};
pub use submission::{
    CONFIG_REPLY_REGION_SIZE, CONFIG_REQUEST_REGION_SIZE, ConfigAnswer, ConfigDemand, ConfigFault,
    ConfigOperation, ConfigPoll, ConfigReply, ConfigRequest, ConfigRequester, ConfigResponder,
    ConfigStatus, MAX_DOCUMENT_BYTES, PendingConfigRequest,
};
pub use tap::{
    CheckedTap, TAP_CLASSIFICATION_COUNT, TAP_CONSUME_REGION_SIZE, TAP_DROP_REASON_COUNT,
    TAP_EVENT_COUNT, TAP_FLAG_OUTBOUND, TAP_FLAGS_KNOWN, TAP_FLOW_STATE_COUNT,
    TAP_RECORDS_REGION_SIZE, TAP_RESERVED_WORDS, TAP_RULE_COUNT, TAP_SLOTS, TAP_SNAP_LEN,
    TapAnnotation, TapClassification, TapConsume, TapDecision, TapDirection, TapDropReason,
    TapEvent, TapFault, TapFlow, TapFlowState, TapOutcome, TapReader, TapRecords, TapRingFull,
    TapRule, TapVerdict, TapWriteError, TapWriter,
};

use image::{checked_value, shared_image};
use log_record::check_bounded_text;

/// The producing domain's decision about the frame a [`Descriptor`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Transmit,
    /// The buffer goes back to its owner unread.
    Discard,
}

impl Verdict {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Transmit => 0,
            Self::Discard => 1,
        }
    }

    /// `None` for every other bit pattern: the field is peer-written, so an
    /// undecodable value is input to reject rather than one to coerce.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Transmit),
            1 => Some(Self::Discard),
            _ => None,
        }
    }
}

/// The `len` bytes at `offset` in pool buffer `buffer`, and the verdict on them.
///
/// `offset` exists so a producer can publish data that does not begin at the
/// buffer's front: on a NIC receive the frame sits behind the device's own
/// header, and handing the descriptor on publishes it without moving a byte.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub buffer: u32,
    pub offset: u32,
    pub len: u32,
    /// The producing domain's [`Verdict`] as raw bits — this crate fixes the
    /// ABI and validates nothing, so the consumer decodes and may refuse it.
    pub verdict: u32,
}

impl Descriptor {
    pub const ZERO: Self = Self {
        buffer: 0,
        offset: 0,
        len: 0,
        verdict: 0,
    };

    /// Takes a [`Verdict`] rather than bits, so only a peer writing the shared
    /// word directly can mint a descriptor its consumer cannot decode.
    #[must_use]
    pub const fn new(buffer: u32, offset: u32, len: u32, verdict: Verdict) -> Self {
        Self {
            buffer,
            offset,
            len,
            verdict: verdict.to_bits(),
        }
    }
}

impl Default for Descriptor {
    fn default() -> Self {
        Self::ZERO
    }
}

// The descriptor crosses protection domains byte for byte, so a field reorder
// or a width change must be a compile error here rather than a silent break of
// the image the peer domain reads.
const _: () = {
    assert!(size_of::<Descriptor>() == 16);
    assert!(align_of::<Descriptor>() == 4);
    assert!(offset_of!(Descriptor, buffer) == 0);
    assert!(offset_of!(Descriptor, offset) == 4);
    assert!(offset_of!(Descriptor, len) == 8);
    assert!(offset_of!(Descriptor, verdict) == 12);
    // Transmit is zero, so a zeroed region is still the valid empty state.
    assert!(Verdict::Transmit.to_bits() == 0);
};

// Slot counts are ABI rather than a tuning knob: each one sizes the region the
// system description reserves, so moving one rebuilds every domain that maps it.
pub const MAX_INTERFACES: usize = 8;
pub const MAX_NEIGHBOURS: usize = 32;
/// Filter rules one generation may carry. The largest of the three by two
/// orders of magnitude, because a ruleset is the one part of a configuration
/// that grows with what an operator wants to express rather than with the
/// hardware: eight ports and thirty-two neighbours describe this appliance,
/// and two hundred and fifty-six rules describe a policy.
pub const MAX_RULES: usize = 256;

/// Bits an IPv4 prefix can name.
pub const MAX_PREFIX_LENGTH: u8 = 32;

/// The granularity Microkit maps a memory region at, so the smallest reservation
/// that can hold anything and the multiple every size rounds to.
pub const MAPPING_ALIGN: usize = 0x1000;

shared_image! {
    /// One interface as the validating domain left it.
    ///
    /// The padding is declared rather than implied, so these offsets are the
    /// ones a writer in another language computes for the same declaration. No
    /// field is placed in it, so the bytes a peer leaves there name nothing.
    InterfaceImage mirrored by InterfaceSlot, 36 bytes aligned 1 {
        @0 port: byte,
        /// 0 or 1 as raw bits. The region is peer-written, so any byte can
        /// appear here and [`ConfigImage::check`] refuses the ones that are
        /// neither.
        @1 enabled: byte,
        @2 prefix_length: byte,
        @3 _pad: padding(1),
        @4 mac: bytes(6),
        @10 _pad2: padding(2),
        /// Network order, as the address appears in a header.
        @12 address: bytes(4),
        /// The `id` of the document's `<interface>`, which nothing else here
        /// implies: a port is hardware topology, fixed at build time rather
        /// than configured.
        @16 id: identifier,
    }
}

shared_image! {
    /// One statically configured neighbour. It carries no prefix: a neighbour
    /// is a single host, and which prefix reaches it is its interface's
    /// business.
    NeighbourImage mirrored by NeighbourSlot, 16 bytes aligned 1 {
        @0 port: byte,
        @1 _pad: padding(3),
        @4 mac: bytes(6),
        @10 _pad2: padding(2),
        @12 address: bytes(4),
    }
}

shared_image! {
    /// The management interface as the validating domain left it: the
    /// appliance's own presence on the management port, which is kept out of
    /// the dataplane.
    ///
    /// It carries no port, unlike an [`InterfaceImage`]: the management port is
    /// not in the router's port set and no number in this image can put it
    /// there.
    ///
    /// It carries a gateway, which an [`InterfaceImage`] does not. The
    /// asymmetry is the point rather than an omission: the only thing that
    /// reads a gateway is the outbound dial of the port it belongs to, and no
    /// dataplane port has one — the forwarder decides an egress from the
    /// prefixes it holds and hands the frame to a neighbour, never to a next
    /// hop of its own. A gateway beside an interface would be a field nothing
    /// in this build can read.
    ManagementImage mirrored by ManagementSlot, 20 bytes aligned 1 {
        /// 0 or 1 as raw bits, on [`InterfaceImage::enabled`]'s terms. A zero
        /// here is what a zeroed region says, and it is why every other field
        /// below is left uninterpreted in that case.
        @0 enabled: byte,
        @1 prefix_length: byte,
        /// Whether `gateway` states one at all, 0 or 1 as raw bits, on
        /// [`RuleImage`]'s terms and for its reason: no address is reserved to
        /// mean "none", so a port that reaches only its own link says so in a
        /// byte of its own rather than by holding an address an operator could
        /// also have meant.
        @2 gateway_stated: byte,
        @3 _pad: padding(1),
        @4 mac: bytes(6),
        @10 _pad2: padding(2),
        /// Network order, as the address appears in a header.
        @12 address: bytes(4),
        /// The station everything outside `address`'s prefix is handed to.
        /// Uninterpreted where `gateway_stated` is 0, on `enabled`'s terms.
        @16 gateway: bytes(4),
    }
}

shared_image! {
    /// One filter rule, with every criterion as a pair: a byte saying whether
    /// the criterion is stated at all, and the value it states.
    ///
    /// The pair is why there is no wildcard *value* anywhere below. A criterion
    /// that meant "any" by holding a reserved number would make one port, one
    /// protocol or one ICMP type unwritable, and would put the reader in the
    /// position of telling a wildcard from a value an operator meant — so
    /// "stated" is its own byte, held to 0 or 1 by [`ConfigImage::check`] on
    /// [`InterfaceImage::enabled`]'s terms.
    ///
    /// An interface criterion crosses as the *port* the named interface holds,
    /// as a [`NeighbourImage`]'s does and for the same reason: what a rule
    /// decides against on the packet path is a port, and resolving the name
    /// twice would be two answers to one question.
    RuleImage mirrored by RuleSlot, 54 bytes aligned 2 {
        /// 0 accepts and 1 drops, as raw bits.
        @0 action: byte,
        @1 ingress_stated: byte,
        @2 ingress_port: byte,
        @3 egress_stated: byte,
        @4 egress_port: byte,
        @5 source_stated: byte,
        @6 source_prefix_length: byte,
        @7 destination_stated: byte,
        /// Network order, as the address appears in a header.
        @8 source_network: bytes(4),
        @12 destination_network: bytes(4),
        @16 destination_prefix_length: byte,
        @17 protocol_stated: byte,
        /// The IANA protocol number, so a rule can name one this build's parser
        /// does not break down.
        @18 protocol: byte,
        @19 icmp_type_stated: byte,
        @20 icmp_type: byte,
        @21 source_port_stated: byte,
        @22 destination_port_stated: byte,
        @23 tracking_stated: byte,
        /// Which of the two things that reach the filter a rule is about: 0 a
        /// conversation opening, 1 traffic an existing conversation is the reason
        /// for. A closed pair rather than a wildcard number, on the terms above.
        @24 tracking: byte,
        @25 _pad: padding(1),
        /// Inclusive, and equal for a single port: one shape rather than two,
        /// so nothing downstream branches on which of them the document wrote.
        @26 source_port_low: half,
        @28 source_port_high: half,
        @30 destination_port_low: half,
        @32 destination_port_high: half,
        /// The `id` of the document's `<rule>`, which is what a per-rule metric
        /// is labelled by and what a refusal names.
        @34 id: identifier,
    }
}

shared_image! {
    /// A whole configuration generation as bytes in a shared region.
    ///
    /// The arrays are always their full size, so the image is one fixed-size
    /// object whatever it holds: the region is reserved once at build time and
    /// a generation that fills it is the same shape as a generation that does
    /// not. [`ConfigImage::ZERO`] is generation zero — no interfaces, no
    /// neighbours — so a zeroed region is already the fail-closed
    /// configuration, which is what lets a domain come up before anything has
    /// been written to it.
    ConfigImage mirrored by ConfigSlot, 14664 bytes aligned 4 {
        @0 generation: word,
        /// How many of `interfaces` the writer filled, as raw bits:
        /// peer-written, so it may name more than the array holds.
        @4 interface_count: word,
        @8 neighbour_count: word,
        /// The fold of every other byte of this image, which
        /// [`ConfigImage::check`] refuses a mismatch of. It is what makes the
        /// image self-describing: a copy assembled from two publications differs
        /// from both in some interior byte, so it does not fold to the word
        /// either of them wrote.
        @12 digest: digest,
        @16 management: nested(ManagementImage, ManagementSlot),
        @36 interfaces: array(InterfaceImage, InterfaceSlot, MAX_INTERFACES),
        @324 neighbours: array(NeighbourImage, NeighbourSlot, MAX_NEIGHBOURS),
        @836 rule_count: word,
        /// **In document order**, which is the one order that is a decision
        /// rather than a layout: a ruleset is first-match-wins, so a writer
        /// that reordered these would be rewriting the policy.
        @840 rules: array(RuleImage, RuleSlot, MAX_RULES),
    }
}

/// What the image digest's fold starts from.
///
/// Zero and not FNV's own basis, so an all-zero image folds to zero and matches
/// the zero its own digest field holds: a zeroed region is the fail-closed
/// generation and has to stay a coherent image.
const DIGEST_BASIS: u32 = 0;

impl ConfigImage {
    /// The digest of this image's own bytes — every field but the one that
    /// carries it, which cannot be part of what it covers.
    #[must_use]
    pub fn computed_digest(&self) -> u32 {
        self.fold(DIGEST_BASIS)
    }

    /// Write the digest of this image's own bytes into it, which is what makes
    /// it one a reader will take.
    ///
    /// The publisher's last act on an image, after every other field is final:
    /// a field set afterwards is a field the digest does not cover, and
    /// [`Self::check`] refuses the result.
    pub fn seal(&mut self) {
        self.digest = self.computed_digest();
    }

    /// Decodes every field the counts cover, refusing the image on the first
    /// value that cannot be one.
    ///
    /// Decodes every field the counts cover and holds the whole image to every
    /// rule about it, refusing on the first one broken.
    ///
    /// `port_count` is how many dataplane ports this build has; it comes from
    /// the calling domain, never from the region, so it is the bound the writer
    /// cannot move.
    ///
    /// The order is part of the contract rather than an accident of the loops:
    /// the two counts, then each interface's own fields in index order, then the
    /// rules between two interfaces, then each neighbour against the interface
    /// its port names, then the rules between two neighbours, then the
    /// management entry, then the two that hold it apart from the dataplane,
    /// and finally its gateway — last because every rule about a gateway is a
    /// rule about its relationship to the address checked above it. An image
    /// breaking several rules is attributed to the first, so a refusal sends
    /// its reader to one place.
    ///
    /// # Two rules this cannot re-decide
    ///
    /// A neighbour's *identity* is absent from the image — a
    /// [`NeighbourImage`] carries a port, a MAC and an address — so two
    /// neighbours under one id are indistinguishable here. Nothing downstream
    /// of the image consumes such an id, so nothing downstream can be misled by
    /// one; it is a handle for editing the document.
    ///
    /// A *disabled* management entry is refused for nothing: `enabled == 0`
    /// leaves every other field of it uninterpreted, so there is no value for a
    /// rule to be about. [`check_management`] is where that is decided.
    ///
    /// # Errors
    /// [`ConfigImageError`], naming the field and the value that refused it.
    pub fn check(&self, port_count: u8) -> Result<CheckedConfig<'_>, ConfigImageError> {
        // First, because every rule below is a rule about *one* image and this is
        // what establishes that these bytes are one. A copy the writer changed
        // under is well-formed field by field — that is what makes it dangerous:
        // the counts come from one publication and the entries from another, so
        // each entry passes and the policy is one nobody wrote.
        let declared = self.digest;
        let folded = self.computed_digest();
        if folded != declared {
            return Err(ConfigImageError::DigestMismatch { declared, folded });
        }
        let raw_interfaces = self.interfaces.get(..self.interface_count as usize).ok_or(
            ConfigImageError::InterfaceCountExceedsCapacity {
                count: self.interface_count,
            },
        )?;
        let raw_neighbours = self.neighbours.get(..self.neighbour_count as usize).ok_or(
            ConfigImageError::NeighbourCountExceedsCapacity {
                count: self.neighbour_count,
            },
        )?;
        let raw_rules = self.rules.get(..self.rule_count as usize).ok_or(
            ConfigImageError::RuleCountExceedsCapacity {
                count: self.rule_count,
            },
        )?;

        let mut interfaces = [None; MAX_INTERFACES];
        for ((index, raw), slot) in raw_interfaces.iter().enumerate().zip(interfaces.iter_mut()) {
            *slot = Some(check_interface(raw, index, port_count)?);
        }
        check_interface_topology(&interfaces)?;

        let mut neighbours = [None; MAX_NEIGHBOURS];
        for ((index, raw), slot) in raw_neighbours.iter().enumerate().zip(neighbours.iter_mut()) {
            *slot = Some(check_neighbour(raw, index, port_count, &interfaces)?);
        }
        check_neighbour_topology(&neighbours)?;

        // Checked in place and never collected: an array of decoded rules is
        // pages long at `MAX_RULES`, and the domains that read a configuration
        // are the ones whose stacks cannot hold one. What survives the loop is
        // the borrow of the entries it accepted.
        let mut earlier_ids = [None; MAX_RULES];
        for (index, raw) in raw_rules.iter().enumerate() {
            let rule = check_rule(raw, index, port_count, &interfaces)?;
            if let Some((other, _)) = earlier_ids
                .iter()
                .flatten()
                .enumerate()
                .find(|(_, id)| **id == rule.id)
            {
                return Err(ConfigImageError::RuleIdDuplicated { index, other });
            }
            if let Some(slot) = earlier_ids.get_mut(index) {
                *slot = Some(rule.id);
            }
        }

        Ok(CheckedConfig {
            generation: self.generation,
            management: check_management(&self.management, &interfaces)?,
            interfaces,
            neighbours,
            rules: raw_rules,
            port_count,
        })
    }
}

/// Copies `bytes` into the cells that hold them, one cell at a time. Bounded
/// by the arrays, which are the same length by the signature.
pub(crate) fn store_bytes<const N: usize>(cells: &[AtomicU8; N], bytes: [u8; N]) {
    for (cell, byte) in cells.iter().zip(bytes) {
        cell.store(byte, Ordering::Relaxed);
    }
}

/// The inverse of [`store_bytes`].
pub(crate) fn load_bytes<const N: usize>(cells: &[AtomicU8; N]) -> [u8; N] {
    let mut bytes = [0; N];
    for (byte, cell) in bytes.iter_mut().zip(cells) {
        *byte = cell.load(Ordering::Relaxed);
    }
    bytes
}

/// A whole configuration image with the two generation words that publish it.
///
/// Two words rather than one because a consumer has to be able to stage a
/// generation before anybody switches to it: `offered` invites, `committed`
/// releases, and the gap between them is where every consumer acknowledges.
///
/// Every field is private and the image has no accessor of its own, so the
/// ordering each word carries is a property of this type rather than a
/// convention its users are asked to keep.
#[repr(C)]
pub struct ConfigHandover {
    offered: AtomicU32,
    committed: AtomicU32,
    /// Odd while a publication is in progress and even between them, so a reader
    /// can tell a settled region from one being rewritten under it. Bumped
    /// before the bytes move and settled after, as
    /// [`ClockCalibration`](crate::ClockCalibration)'s counter is and for the
    /// same reason — the generation word cannot carry it, being an identity a
    /// commit is keyed on rather than a progress marker.
    publishing: AtomicU32,
    image: ConfigSlot,
}

impl ConfigHandover {
    /// A function rather than a `const`, because a `const` holding an atomic is
    /// copied at every mention: publishing through one would store into a
    /// temporary and be read back by nobody.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            offered: AtomicU32::new(0),
            committed: AtomicU32::new(0),
            publishing: AtomicU32::new(0),
            image: ConfigSlot::zero(),
        }
    }

    /// Writes `image` and then releases its generation, in that order and as
    /// one call: a generation whose bytes are not yet in the region names
    /// nothing, so there is no way here to offer one that has not been written.
    ///
    /// The whole of it happens under an odd `publishing`, and this call is the
    /// only writer of the bytes — so a reader that saw the counter even before
    /// its copy and unchanged after it copied bytes no publication was moving.
    pub fn publish(&self, image: &ConfigImage) {
        // `| 1` rather than `+ 1`, so a region left odd by a writer that faulted
        // mid-publish is published into correctly rather than left permanently
        // unreadable.
        let writing = self.publishing.load(Ordering::Relaxed) | 1;
        self.publishing.store(writing, Ordering::Relaxed);
        // The odd counter must be visible before the bytes move; the `Release`
        // on the settling store below is what orders the bytes before it.
        fence(Ordering::Release);
        self.image.store(image);
        self.offered.store(image.generation, Ordering::Release);
        self.publishing
            .store(writing.wrapping_add(1), Ordering::Release);
    }

    #[must_use]
    pub fn offered_generation(&self) -> u32 {
        self.offered.load(Ordering::Acquire)
    }

    /// Copies the whole image into storage the *caller* owns, because the
    /// writer may change the region again at any moment and a view into it
    /// decides nothing.
    ///
    /// Into the caller's storage rather than out by value, and that is a
    /// property of the system rather than a calling convention: an image is
    /// pages long and grows with every entity the configuration gains, so a
    /// return by value puts a whole generation on the stack of whichever
    /// protection domain asked — twice over, once for the image and once for
    /// what it decodes to. The domains that read a configuration have stacks
    /// measured in tens of kilobytes and the hot one has sixteen, so the image
    /// lives in a field of the reader and this fills it.
    ///
    /// **It still copies exactly once**, and the `Relaxed` accesses of the copy
    /// itself buy only a read that cannot tear *within a field* — which keeps a
    /// MAC from being half of one address and half of another. What makes the
    /// copy one *image* is the counter around it: without it a copy could be a
    /// blend of two publications, one field from each, and no rule about a field
    /// refuses a blend — every field of it is a field some publisher wrote.
    ///
    /// Bounded at [`LOAD_ATTEMPTS`] attempts, on
    /// [`ClockCalibration`](crate::ClockCalibration)'s terms: a peer that holds
    /// the counter odd must not be able to spin a reader, and a caller told
    /// "nothing right now" has lost nothing it cannot ask for again. One known
    /// bound beyond that: `publishing` wraps, so a publisher completing 2^32
    /// publications inside one reader's copy would land it back on the value that
    /// reader took — tens of terabytes of stores inside one 14-kilobyte copy.
    fn load_settled(&self, image: &mut ConfigImage, word: &AtomicU32) -> Option<u32> {
        for _ in 0..LOAD_ATTEMPTS {
            let before = self.publishing.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                continue;
            }
            let generation = word.load(Ordering::Relaxed);
            *image = self.image.load();
            // The bytes must be read before the counter is read again; without
            // this the second load could be hoisted above them and a blended
            // copy would compare equal.
            fence(Ordering::Acquire);
            if self.publishing.load(Ordering::Relaxed) == before {
                return Some(generation);
            }
        }
        None
    }

    /// Copy the offered image out of the region and answer the generation it was
    /// offered under, or `None` where the publisher was rewriting it throughout.
    pub fn load_offer(&self, image: &mut ConfigImage) -> Option<u32> {
        self.load_settled(image, &self.offered)
    }

    /// As [`Self::load_offer`], for the committed generation.
    ///
    /// The word and the bytes are two claims of one publisher and are read
    /// together, but they are not made together: a commit releases a generation
    /// whose bytes a *later* offer may already have replaced, so the word this
    /// answers can name a generation the bytes are not. What tells the two apart
    /// is the image's own `generation` field, which the caller compares.
    pub fn load_committed(&self, image: &mut ConfigImage) -> Option<u32> {
        self.load_settled(image, &self.committed)
    }

    pub fn publish_committed(&self, generation: u32) {
        self.committed.store(generation, Ordering::Release);
    }

    #[must_use]
    pub fn committed_generation(&self) -> u32 {
        self.committed.load(Ordering::Acquire)
    }
}

/// What one consumer has done with the offered generation. Separate from
/// [`ConfigHandover`] because it travels the other way, and so is a region the
/// writer of that one maps read-only. Private for the reason
/// [`ConfigHandover`]'s fields are.
#[repr(C)]
pub struct ConfigAck {
    staged: AtomicU32,
    running: AtomicU32,
}

impl ConfigAck {
    /// As [`ConfigHandover::zero`].
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            staged: AtomicU32::new(0),
            running: AtomicU32::new(0),
        }
    }

    /// Highest generation this consumer has staged and can switch to.
    pub fn publish_staged(&self, generation: u32) {
        self.staged.store(generation, Ordering::Release);
    }

    #[must_use]
    pub fn staged_generation(&self) -> u32 {
        self.staged.load(Ordering::Acquire)
    }

    /// Highest generation this consumer has actually switched to.
    pub fn publish_running(&self, generation: u32) {
        self.running.store(generation, Ordering::Release);
    }

    #[must_use]
    pub fn running_generation(&self) -> u32 {
        self.running.load(Ordering::Acquire)
    }
}

/// The fewest bytes the handover region may be reserved at, whatever the image
/// currently occupies.
///
/// Every other region here is sized by what its type needs and nothing else,
/// and this one is not, because its size is not free to move: `cfg` is mapped
/// at a fixed virtual address in three protection domains and every region
/// behind it in that window moves when it grows, so a generation that outgrows
/// the reservation re-lays an address map three domains have to agree on. Four
/// pages is what the configuration ABI was first reserved at, and eight is what
/// it is reserved at now: the ruleset took the four-page map to two kilobytes
/// of headroom, and re-laying a window three domains agree on is worth doing
/// once, deliberately, rather than on the landing that discovers it is full.
/// Address space costs nothing here — the pages are reserved, not populated —
/// so the reservation is set where the entities still to be added to it, each
/// an array sized by a capacity constant beside [`MAX_INTERFACES`], land inside
/// a map already laid. What occupies it today is
/// [`size_of::<ConfigHandover>`] and the assertions below hold the two in the
/// only order that matters.
const CONFIG_REGION_RESERVATION: usize = 8 * MAPPING_ALIGN;

/// Bytes the system description reserves for the handover region: the fewest
/// [`MAPPING_ALIGN`] pages that hold the type, and never fewer than
/// [`CONFIG_REGION_RESERVATION`].
pub const CONFIG_REGION_SIZE: usize = {
    let occupied = size_of::<ConfigHandover>();
    let reserved = if occupied > CONFIG_REGION_RESERVATION {
        occupied
    } else {
        CONFIG_REGION_RESERVATION
    };
    reserved.next_multiple_of(MAPPING_ALIGN)
};

/// As [`CONFIG_REGION_SIZE`], for one consumer's acknowledgement region.
pub const CONFIG_ACK_REGION_SIZE: usize = size_of::<ConfigAck>().next_multiple_of(MAPPING_ALIGN);

/// Which of the two things that reach the filter a rule is about.
///
/// Two values and no third, because two are what can reach it: a conversation
/// opening, and traffic an existing conversation is the reason for. Traffic
/// *within* an established conversation never reaches the filter at all — the
/// tracker settles it — so there is no token for it and a document naming one
/// would be naming a choice it does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedTracking {
    /// A conversation the appliance has not seen before.
    Opening,
    /// Traffic an existing conversation accounts for without belonging to it —
    /// today an ICMP error quoting one of its datagrams.
    Related,
}

/// Why a [`ConfigImage`] was refused. Every variant carries the value that made
/// it one, so a refusal is attributable to a field rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigImageError {
    /// The image does not fold to the digest it carries, so these bytes are not
    /// one publication: either the writer sealed them wrongly, or the copy was
    /// taken across two of them.
    DigestMismatch {
        declared: u32,
        folded: u32,
    },
    /// A `tracking` byte that is neither of the two the criterion has.
    RuleTrackingUnknown {
        index: usize,
        tracking: u8,
    },
    InterfaceCountExceedsCapacity {
        count: u32,
    },
    NeighbourCountExceedsCapacity {
        count: u32,
    },
    /// Anything but 0 or 1, which no `bool` can be coerced from without picking
    /// a meaning the writer did not choose.
    InterfaceEnabledNotBoolean {
        index: usize,
        enabled: u8,
    },
    InterfacePortUnknown {
        index: usize,
        port: u8,
    },
    NeighbourPortUnknown {
        index: usize,
        port: u8,
    },
    InterfacePrefixLengthTooLong {
        index: usize,
        prefix_length: u8,
    },
    /// The group bit is set, or every byte is zero. Neither can be a source MAC
    /// the appliance forwards under.
    InterfaceMacNotUnicast {
        index: usize,
        mac: [u8; 6],
    },
    /// As [`Self::InterfaceMacNotUnicast`], for a destination the appliance
    /// would unicast a routed frame to.
    NeighbourMacNotUnicast {
        index: usize,
        mac: [u8; 6],
    },
    /// The `id` bytes are not an identifier. Checked rather than copied through
    /// because the id becomes a label value and a console field.
    InterfaceIdNotAnIdentifier {
        index: usize,
        fault: TextFault,
    },
    InterfaceAddressNotUnicast {
        index: usize,
        address: [u8; 4],
    },
    /// The prefix's own network or broadcast address.
    InterfaceAddressNotAHostAddress {
        index: usize,
        address: [u8; 4],
    },
    InterfaceIdDuplicated {
        index: usize,
        other: usize,
    },
    /// The ingress that port names would be ambiguous, and the two lookups a
    /// forwarding decision makes could answer with different entries.
    InterfacePortDuplicated {
        index: usize,
        other: usize,
        port: u8,
    },
    /// Two ports answering to one L2 address: a frame would be taken by
    /// whichever saw it first.
    InterfaceMacDuplicated {
        index: usize,
        other: usize,
        mac: [u8; 6],
    },
    /// Two interfaces covering one address, which makes its egress ambiguous.
    InterfacePrefixesOverlap {
        index: usize,
        other: usize,
    },
    NeighbourAddressNotUnicast {
        index: usize,
        address: [u8; 4],
    },
    /// A routed frame would be unicast to a directed subnet broadcast address.
    NeighbourAddressNotAHostAddress {
        index: usize,
        address: [u8; 4],
    },
    /// A port the build has and no interface addresses, so the link the
    /// neighbour sits on has no prefix for it to be inside.
    NeighbourPortUnconfigured {
        index: usize,
        port: u8,
    },
    /// Outside its own link's prefix, which is not a neighbour of it.
    NeighbourOutsidePrefix {
        index: usize,
        address: [u8; 4],
    },
    /// Holding the appliance's own address on that link.
    NeighbourIsInterfaceAddress {
        index: usize,
        address: [u8; 4],
    },
    /// Two at one address on one port, which makes resolution ambiguous.
    NeighbourAddressDuplicated {
        index: usize,
        other: usize,
    },
    /// The management entry's own rules. They carry no index of their own: the
    /// image holds exactly one management interface, so the value refused is the
    /// whole of what locates the fault. The last two name the interface they
    /// collide with instead.
    ManagementEnabledNotBoolean {
        enabled: u8,
    },
    ManagementPrefixLengthTooLong {
        prefix_length: u8,
    },
    ManagementMacNotUnicast {
        mac: [u8; 6],
    },
    ManagementAddressNotUnicast {
        address: [u8; 4],
    },
    ManagementAddressNotAHostAddress {
        address: [u8; 4],
    },
    /// One address reachable two ways: routed out of the named interface's
    /// port, and terminated off the dataplane.
    ManagementPrefixCollidesWithInterface {
        index: usize,
    },
    /// As [`Self::InterfaceMacDuplicated`], across the boundary the management
    /// port sits on the far side of.
    ManagementMacCollidesWithInterface {
        index: usize,
    },
    /// A gateway's stated flag that is neither 0 nor 1, on
    /// [`Self::RuleCriterionStatedNotBoolean`]'s terms.
    ManagementGatewayStatedNotBoolean {
        stated: u8,
    },
    /// A gateway no frame may be addressed towards, so a port holding one
    /// reaches nothing off its own link and reports the wrong reason for it.
    ManagementGatewayNotUnicast {
        gateway: [u8; 4],
    },
    /// A gateway equal to the management port's own address, which would hand
    /// every off-prefix datagram back to this node.
    ManagementGatewayIsTheAddress {
        gateway: [u8; 4],
    },
    /// A gateway outside the management port's own prefix. No station on that
    /// link can legitimately answer for it, so the only reply it could draw is
    /// one from a station claiming an address it does not hold.
    ManagementGatewayOffLink {
        gateway: [u8; 4],
    },
    RuleCountExceedsCapacity {
        count: u32,
    },
    /// A criterion's stated flag that is neither 0 nor 1, which no `Option` can
    /// be coerced from without picking a meaning the writer did not choose.
    RuleCriterionNotBoolean {
        index: usize,
        criterion: RuleCriterion,
        stated: u8,
    },
    RuleActionUnknown {
        index: usize,
        action: u8,
    },
    RulePortUnknown {
        index: usize,
        criterion: RuleCriterion,
        port: u8,
    },
    /// A port this build has and no interface addresses, so a rule naming it
    /// names a link the appliance is not on.
    RulePortUnconfigured {
        index: usize,
        criterion: RuleCriterion,
        port: u8,
    },
    RulePrefixLengthTooLong {
        index: usize,
        criterion: RuleCriterion,
        prefix_length: u8,
    },
    /// Host bits set below the prefix, so the block is not the one the address
    /// reads as.
    RulePrefixNotCanonical {
        index: usize,
        criterion: RuleCriterion,
        network: [u8; 4],
    },
    RulePortRangeReversed {
        index: usize,
        criterion: RuleCriterion,
        low: u16,
        high: u16,
    },
    /// A port criterion on a rule naming ICMP, which carries no ports: it would
    /// match nothing, whatever an operator meant by it.
    RulePortCriterionOnIcmp {
        index: usize,
        criterion: RuleCriterion,
    },
    /// The converse: an ICMP type on a rule naming something else.
    RuleIcmpTypeOnNonIcmp {
        index: usize,
        protocol: u8,
    },
    RuleIdNotAnIdentifier {
        index: usize,
        fault: TextFault,
    },
    RuleIdDuplicated {
        index: usize,
        other: usize,
    },
}

/// Which criterion of a rule a refusal is about, so one rule's eight criteria
/// are eight things to go and fix rather than one.
///
/// The tokens are the document's own attribute names, which is what makes a
/// refusal point at the text an operator edits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleCriterion {
    Ingress,
    Egress,
    Source,
    Destination,
    Protocol,
    SourcePort,
    DestinationPort,
    IcmpType,
    Tracking,
}

impl RuleCriterion {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            Self::Source => "source",
            Self::Destination => "destination",
            Self::Protocol => "protocol",
            Self::SourcePort => "source-port",
            Self::DestinationPort => "destination-port",
            Self::IcmpType => "icmp-type",
            Self::Tracking => "tracking",
        }
    }
}

impl fmt::Display for RuleCriterion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for ConfigImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch { declared, folded } => write!(
                f,
                "the image folds to {folded:#010x} and declares {declared:#010x}"
            ),
            Self::RuleTrackingUnknown { index, tracking } => write!(
                f,
                "rule {index} tracking byte {tracking} names neither an opening nor related traffic"
            ),
            Self::InterfaceCountExceedsCapacity { count } => write!(
                f,
                "interface count {count} exceeds the {MAX_INTERFACES} slots the image holds"
            ),
            Self::NeighbourCountExceedsCapacity { count } => write!(
                f,
                "neighbour count {count} exceeds the {MAX_NEIGHBOURS} slots the image holds"
            ),
            Self::InterfaceEnabledNotBoolean { index, enabled } => {
                write!(f, "interface {index} enabled byte {enabled} is not 0 or 1")
            }
            Self::InterfacePortUnknown { index, port } => {
                write!(
                    f,
                    "interface {index} names port {port}, which does not exist"
                )
            }
            Self::NeighbourPortUnknown { index, port } => {
                write!(
                    f,
                    "neighbour {index} names port {port}, which does not exist"
                )
            }
            Self::InterfacePrefixLengthTooLong {
                index,
                prefix_length,
            } => write!(
                f,
                "interface {index} prefix length {prefix_length} exceeds {MAX_PREFIX_LENGTH}"
            ),
            Self::InterfaceMacNotUnicast { index, mac } => {
                write!(f, "interface {index} MAC ")?;
                write_mac(f, *mac)?;
                write!(f, " is not unicast")
            }
            Self::NeighbourMacNotUnicast { index, mac } => {
                write!(f, "neighbour {index} MAC ")?;
                write_mac(f, *mac)?;
                write!(f, " is not unicast")
            }
            Self::InterfaceIdNotAnIdentifier { index, fault } => {
                write!(f, "interface {index} id {fault}")
            }
            Self::InterfaceAddressNotUnicast { index, address } => {
                write!(f, "interface {index} address ")?;
                write_address(f, *address)?;
                write!(f, " is not unicast")
            }
            Self::InterfaceAddressNotAHostAddress { index, address } => {
                write!(f, "interface {index} address ")?;
                write_address(f, *address)?;
                write!(f, " is its prefix's network or broadcast address")
            }
            Self::InterfaceIdDuplicated { index, other } => {
                write!(f, "interface {index} repeats interface {other}'s id")
            }
            Self::InterfacePortDuplicated { index, other, port } => write!(
                f,
                "interface {index} shares port {port} with interface {other}"
            ),
            Self::InterfaceMacDuplicated { index, other, mac } => {
                write!(f, "interface {index} shares MAC ")?;
                write_mac(f, *mac)?;
                write!(f, " with interface {other}")
            }
            Self::InterfacePrefixesOverlap { index, other } => write!(
                f,
                "interface {index} covers an address interface {other} also covers"
            ),
            Self::NeighbourAddressNotUnicast { index, address } => {
                write!(f, "neighbour {index} address ")?;
                write_address(f, *address)?;
                write!(f, " is not unicast")
            }
            Self::NeighbourAddressNotAHostAddress { index, address } => {
                write!(f, "neighbour {index} address ")?;
                write_address(f, *address)?;
                write!(f, " is its link's network or broadcast address")
            }
            Self::NeighbourPortUnconfigured { index, port } => write!(
                f,
                "neighbour {index} names port {port}, which no interface addresses"
            ),
            Self::NeighbourOutsidePrefix { index, address } => {
                write!(f, "neighbour {index} address ")?;
                write_address(f, *address)?;
                write!(f, " is outside its link's prefix")
            }
            Self::NeighbourIsInterfaceAddress { index, address } => {
                write!(f, "neighbour {index} address ")?;
                write_address(f, *address)?;
                write!(f, " is the interface's own")
            }
            Self::NeighbourAddressDuplicated { index, other } => write!(
                f,
                "neighbour {index} repeats neighbour {other}'s address on one port"
            ),
            Self::ManagementEnabledNotBoolean { enabled } => {
                write!(f, "management enabled byte {enabled} is not 0 or 1")
            }
            Self::ManagementPrefixLengthTooLong { prefix_length } => write!(
                f,
                "management prefix length {prefix_length} exceeds {MAX_PREFIX_LENGTH}"
            ),
            Self::ManagementMacNotUnicast { mac } => {
                write!(f, "management MAC ")?;
                write_mac(f, *mac)?;
                write!(f, " is not unicast")
            }
            Self::ManagementAddressNotUnicast { address } => {
                write!(f, "management address ")?;
                write_address(f, *address)?;
                write!(f, " is not unicast")
            }
            Self::ManagementAddressNotAHostAddress { address } => {
                write!(f, "management address ")?;
                write_address(f, *address)?;
                write!(f, " is its prefix's network or broadcast address")
            }
            Self::ManagementPrefixCollidesWithInterface { index } => write!(
                f,
                "management shares a prefix with interface {index}, which routes it"
            ),
            Self::ManagementMacCollidesWithInterface { index } => {
                write!(f, "management shares its MAC with interface {index}")
            }
            Self::ManagementGatewayStatedNotBoolean { stated } => {
                write!(f, "management gateway stated byte {stated} is not 0 or 1")
            }
            Self::ManagementGatewayNotUnicast { gateway } => {
                f.write_str("management gateway ")?;
                write_address(f, *gateway)?;
                f.write_str(" is not a unicast address")
            }
            Self::ManagementGatewayIsTheAddress { gateway } => {
                f.write_str("management gateway ")?;
                write_address(f, *gateway)?;
                f.write_str(" is the management address itself")
            }
            Self::ManagementGatewayOffLink { gateway } => {
                f.write_str("management gateway ")?;
                write_address(f, *gateway)?;
                f.write_str(" is outside the management prefix")
            }
            Self::RuleCountExceedsCapacity { count } => write!(
                f,
                "rule count {count} exceeds the {MAX_RULES} slots the image holds"
            ),
            Self::RuleCriterionNotBoolean {
                index,
                criterion,
                stated,
            } => write!(
                f,
                "rule {index} {criterion} stated byte {stated} is not 0 or 1"
            ),
            Self::RuleActionUnknown { index, action } => {
                write!(f, "rule {index} action byte {action} is not 0 or 1")
            }
            Self::RulePortUnknown {
                index,
                criterion,
                port,
            } => write!(
                f,
                "rule {index} {criterion} names port {port}, which does not exist"
            ),
            Self::RulePortUnconfigured {
                index,
                criterion,
                port,
            } => write!(
                f,
                "rule {index} {criterion} names port {port}, which no interface addresses"
            ),
            Self::RulePrefixLengthTooLong {
                index,
                criterion,
                prefix_length,
            } => write!(
                f,
                "rule {index} {criterion} prefix length {prefix_length} exceeds {MAX_PREFIX_LENGTH}"
            ),
            Self::RulePrefixNotCanonical {
                index,
                criterion,
                network,
            } => {
                write!(f, "rule {index} {criterion} ")?;
                write_address(f, *network)?;
                write!(f, " has host bits set below its prefix")
            }
            Self::RulePortRangeReversed {
                index,
                criterion,
                low,
                high,
            } => write!(f, "rule {index} {criterion} range {low}-{high} is empty"),
            Self::RulePortCriterionOnIcmp { index, criterion } => write!(
                f,
                "rule {index} names icmp and states a {criterion}, which icmp carries none of"
            ),
            Self::RuleIcmpTypeOnNonIcmp { index, protocol } => write!(
                f,
                "rule {index} states an icmp-type and names protocol {protocol}"
            ),
            Self::RuleIdNotAnIdentifier { index, fault } => {
                write!(f, "rule {index} id {fault}")
            }
            Self::RuleIdDuplicated { index, other } => {
                write!(f, "rule {index} repeats rule {other}'s id")
            }
        }
    }
}

fn write_mac(f: &mut fmt::Formatter<'_>, mac: [u8; 6]) -> fmt::Result {
    let [a, b, c, d, e, g] = mac;
    write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
}

fn write_address(f: &mut fmt::Formatter<'_>, address: [u8; 4]) -> fmt::Result {
    let [a, b, c, d] = address;
    write!(f, "{a}.{b}.{c}.{d}")
}

/// A unicast MAC: the group bit (IEEE 802.3 3.2.3) clear, and not the all-zero
/// address, which names nothing.
fn is_unicast(mac: [u8; 6]) -> bool {
    let [first, ..] = mac;
    first & 0x01 == 0 && mac != [0; 6]
}

/// The image carries an address in network order, as a header does.
const fn address_bits(address: [u8; 4]) -> u32 {
    u32::from_be_bytes(address)
}

/// Saturating at both ends, so no length this ABI admits shifts by the width.
const fn prefix_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else if prefix_length >= MAX_PREFIX_LENGTH {
        u32::MAX
    } else {
        u32::MAX << MAX_PREFIX_LENGTH.saturating_sub(prefix_length)
    }
}

/// Neither multicast (224.0.0.0/4), the limited broadcast, loopback
/// (127.0.0.0/8) nor unspecified — none of which the appliance can answer under
/// or unicast a routed frame to.
const fn is_unicast_address(address: [u8; 4]) -> bool {
    let bits = address_bits(address);
    bits & 0xf000_0000 != 0xe000_0000
        && bits != u32::MAX
        && bits & 0xff00_0000 != 0x7f00_0000
        && bits != 0
}

/// A `/31` is a two-address point-to-point link and a `/32` is a host route, so
/// neither reserves a network or broadcast address to exclude (RFC 3021).
const fn is_host_address(address: [u8; 4], prefix_length: u8) -> bool {
    if prefix_length >= MAX_PREFIX_LENGTH.saturating_sub(1) {
        return true;
    }
    let bits = address_bits(address);
    let mask = prefix_mask(prefix_length);
    let network = bits & mask;
    bits != network && bits != (network | !mask)
}

const fn inside_prefix(address: [u8; 4], network: [u8; 4], prefix_length: u8) -> bool {
    let mask = prefix_mask(prefix_length);
    address_bits(address) & mask == address_bits(network) & mask
}

/// Whether two prefixes cover a common address, which is decided entirely by
/// the shorter of the two: if the longer prefix's network falls inside the
/// shorter one, every address the longer covers the shorter covers too.
const fn prefixes_overlap(
    left: [u8; 4],
    left_length: u8,
    right: [u8; 4],
    right_length: u8,
) -> bool {
    let shorter = if left_length < right_length {
        left_length
    } else {
        right_length
    };
    inside_prefix(left, right, shorter)
}

/// Reads each field exactly once, by copying the whole entry out first: the
/// source may be the shared region, where reading a byte twice can return two
/// different values and validate one of them while keeping the other.
fn check_interface(
    raw: &InterfaceImage,
    index: usize,
    port_count: u8,
) -> Result<CheckedInterface, ConfigImageError> {
    let InterfaceImage {
        port,
        enabled,
        prefix_length,
        mac,
        address,
        id,
        ..
    } = *raw;

    let enabled = match enabled {
        0 => false,
        1 => true,
        other => {
            return Err(ConfigImageError::InterfaceEnabledNotBoolean {
                index,
                enabled: other,
            });
        }
    };
    if port >= port_count {
        return Err(ConfigImageError::InterfacePortUnknown { index, port });
    }
    if prefix_length > MAX_PREFIX_LENGTH {
        return Err(ConfigImageError::InterfacePrefixLengthTooLong {
            index,
            prefix_length,
        });
    }
    if !is_unicast(mac) {
        return Err(ConfigImageError::InterfaceMacNotUnicast { index, mac });
    }
    if !is_unicast_address(address) {
        return Err(ConfigImageError::InterfaceAddressNotUnicast { index, address });
    }
    if !is_host_address(address, prefix_length) {
        return Err(ConfigImageError::InterfaceAddressNotAHostAddress { index, address });
    }
    let id = check_bounded_text(&id, false)
        .map_err(|fault| ConfigImageError::InterfaceIdNotAnIdentifier { index, fault })?;

    Ok(CheckedInterface {
        port,
        enabled,
        prefix_length,
        mac,
        address,
        id,
    })
}

/// The rules about a *pair* of interfaces. Iteration is over the entries the
/// array holds rather than the count the region claimed, and the earlier of a
/// pair is named as `other`, so a refusal always names the later entry and reads
/// in document order.
fn check_interface_topology(
    interfaces: &[Option<CheckedInterface>; MAX_INTERFACES],
) -> Result<(), ConfigImageError> {
    for (index, entry) in interfaces.iter().flatten().enumerate() {
        for (other, earlier) in interfaces.iter().flatten().take(index).enumerate() {
            if earlier.id == entry.id {
                return Err(ConfigImageError::InterfaceIdDuplicated { index, other });
            }
            if earlier.port == entry.port {
                return Err(ConfigImageError::InterfacePortDuplicated {
                    index,
                    other,
                    port: entry.port,
                });
            }
            if earlier.mac == entry.mac {
                return Err(ConfigImageError::InterfaceMacDuplicated {
                    index,
                    other,
                    mac: entry.mac,
                });
            }
            if prefixes_overlap(
                earlier.address,
                earlier.prefix_length,
                entry.address,
                entry.prefix_length,
            ) {
                return Err(ConfigImageError::InterfacePrefixesOverlap { index, other });
            }
        }
    }
    Ok(())
}

/// As [`check_interface`], for an entry with neither an enable flag nor a prefix
/// of its own — then against the interface whose port it names, which is what
/// makes it a neighbour of anything. That interface is a value rather than a
/// choice: [`check_interface_topology`] has already refused two on one port.
fn check_neighbour(
    raw: &NeighbourImage,
    index: usize,
    port_count: u8,
    interfaces: &[Option<CheckedInterface>; MAX_INTERFACES],
) -> Result<CheckedNeighbour, ConfigImageError> {
    let NeighbourImage {
        port, mac, address, ..
    } = *raw;

    if port >= port_count {
        return Err(ConfigImageError::NeighbourPortUnknown { index, port });
    }
    if !is_unicast(mac) {
        return Err(ConfigImageError::NeighbourMacNotUnicast { index, mac });
    }
    if !is_unicast_address(address) {
        return Err(ConfigImageError::NeighbourAddressNotUnicast { index, address });
    }
    let Some(interface) = interfaces.iter().flatten().find(|entry| entry.port == port) else {
        return Err(ConfigImageError::NeighbourPortUnconfigured { index, port });
    };
    if address == interface.address {
        return Err(ConfigImageError::NeighbourIsInterfaceAddress { index, address });
    }
    if !inside_prefix(address, interface.address, interface.prefix_length) {
        return Err(ConfigImageError::NeighbourOutsidePrefix { index, address });
    }
    if !is_host_address(address, interface.prefix_length) {
        return Err(ConfigImageError::NeighbourAddressNotAHostAddress { index, address });
    }

    Ok(CheckedNeighbour { port, mac, address })
}

/// Resolution is by port and address, so two entries agreeing on both would
/// answer with whichever came first.
fn check_neighbour_topology(
    neighbours: &[Option<CheckedNeighbour>; MAX_NEIGHBOURS],
) -> Result<(), ConfigImageError> {
    for (index, entry) in neighbours.iter().flatten().enumerate() {
        for (other, earlier) in neighbours.iter().flatten().take(index).enumerate() {
            if earlier.port == entry.port && earlier.address == entry.address {
                return Err(ConfigImageError::NeighbourAddressDuplicated { index, other });
            }
        }
    }
    Ok(())
}

/// The management entry, or `None` where the image carries none — then the two
/// rules that hold it apart from the dataplane, neither of which the capability
/// grants can express: an address reachable both by routing and by local
/// termination, and one L2 address on two ports.
///
/// A disabled entry is `None` rather than a [`CheckedManagement`] with a flag:
/// the fields of a disabled interface are not interpreted at all, so an
/// unaddressed port has one representation here and it is the one a zeroed
/// region produces. That is what keeps [`ConfigImage::ZERO`] — the fail-closed
/// generation every domain starts under — a valid image, and it is why a
/// disabled entry is held to no rule: there is no value left to hold.
fn check_management(
    raw: &ManagementImage,
    interfaces: &[Option<CheckedInterface>; MAX_INTERFACES],
) -> Result<Option<CheckedManagement>, ConfigImageError> {
    let ManagementImage {
        enabled,
        prefix_length,
        gateway_stated,
        mac,
        address,
        gateway,
        ..
    } = *raw;

    match enabled {
        0 => return Ok(None),
        1 => {}
        enabled => return Err(ConfigImageError::ManagementEnabledNotBoolean { enabled }),
    }
    if prefix_length > MAX_PREFIX_LENGTH {
        return Err(ConfigImageError::ManagementPrefixLengthTooLong { prefix_length });
    }
    if !is_unicast(mac) {
        return Err(ConfigImageError::ManagementMacNotUnicast { mac });
    }
    if !is_unicast_address(address) {
        return Err(ConfigImageError::ManagementAddressNotUnicast { address });
    }
    if !is_host_address(address, prefix_length) {
        return Err(ConfigImageError::ManagementAddressNotAHostAddress { address });
    }
    for (index, interface) in interfaces.iter().flatten().enumerate() {
        if prefixes_overlap(
            interface.address,
            interface.prefix_length,
            address,
            prefix_length,
        ) {
            return Err(ConfigImageError::ManagementPrefixCollidesWithInterface { index });
        }
        if interface.mac == mac {
            return Err(ConfigImageError::ManagementMacCollidesWithInterface { index });
        }
    }
    // Last, and judged against the address above rather than on its own: every
    // rule here is about the gateway's relationship to the port that would use
    // it, so an image whose address is not yet known to be a host address on a
    // legal prefix has nothing to judge a gateway against.
    let gateway = match gateway_stated {
        0 => None,
        1 => Some(gateway),
        stated => return Err(ConfigImageError::ManagementGatewayStatedNotBoolean { stated }),
    };
    if let Some(gateway) = gateway {
        if !is_unicast_address(gateway) {
            return Err(ConfigImageError::ManagementGatewayNotUnicast { gateway });
        }
        if gateway == address {
            return Err(ConfigImageError::ManagementGatewayIsTheAddress { gateway });
        }
        if !inside_prefix(gateway, address, prefix_length) {
            return Err(ConfigImageError::ManagementGatewayOffLink { gateway });
        }
    }
    Ok(Some(CheckedManagement {
        prefix_length,
        mac,
        address,
        gateway,
    }))
}

/// A stated address criterion: the block a rule matches source or destination
/// against. A wildcard is the absence of one of these rather than a value of
/// it, which is what [`CheckedRule`]'s `Option` carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedPrefix {
    /// Network order, as the address appears in a header. Its host bits are
    /// clear, which [`check_rule`] is what establishes.
    pub network: [u8; 4],
    pub prefix_length: u8,
}

/// A stated port criterion, inclusive at both ends and equal for a single
/// port. `low <= high`, which [`check_rule`] is what establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedPorts {
    pub low: u16,
    pub high: u16,
}

/// What a rule does with a frame it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedAction {
    Accept,
    Drop,
}

/// Decode one rule, criterion by criterion, then hold the criteria to each
/// other: a port criterion is meaningless on ICMP and an ICMP type criterion is
/// meaningless on anything else, and a rule carrying either is one an operator
/// wrote believing it would match something.
///
/// The order is the contract: the stated flags, then each criterion's own
/// value, then the two rules between criteria, then the identity. An operator
/// reading a refusal is sent to one attribute.
fn check_rule(
    raw: &RuleImage,
    index: usize,
    port_count: u8,
    interfaces: &[Option<CheckedInterface>; MAX_INTERFACES],
) -> Result<CheckedRule, ConfigImageError> {
    let RuleImage {
        action,
        ingress_stated,
        ingress_port,
        egress_stated,
        egress_port,
        source_stated,
        source_prefix_length,
        destination_stated,
        source_network,
        destination_network,
        destination_prefix_length,
        protocol_stated,
        protocol,
        icmp_type_stated,
        icmp_type,
        source_port_stated,
        destination_port_stated,
        tracking_stated,
        tracking,
        source_port_low,
        source_port_high,
        destination_port_low,
        destination_port_high,
        id,
        ..
    } = *raw;

    let stated = |flag: u8, criterion: RuleCriterion| match flag {
        0 => Ok(false),
        1 => Ok(true),
        flag => Err(ConfigImageError::RuleCriterionNotBoolean {
            index,
            criterion,
            stated: flag,
        }),
    };
    let action = match action {
        0 => CheckedAction::Accept,
        1 => CheckedAction::Drop,
        action => return Err(ConfigImageError::RuleActionUnknown { index, action }),
    };

    let ingress = check_rule_port(
        stated(ingress_stated, RuleCriterion::Ingress)?,
        ingress_port,
        index,
        RuleCriterion::Ingress,
        port_count,
        interfaces,
    )?;
    let egress = check_rule_port(
        stated(egress_stated, RuleCriterion::Egress)?,
        egress_port,
        index,
        RuleCriterion::Egress,
        port_count,
        interfaces,
    )?;
    let source = check_rule_prefix(
        stated(source_stated, RuleCriterion::Source)?,
        source_network,
        source_prefix_length,
        index,
        RuleCriterion::Source,
    )?;
    let destination = check_rule_prefix(
        stated(destination_stated, RuleCriterion::Destination)?,
        destination_network,
        destination_prefix_length,
        index,
        RuleCriterion::Destination,
    )?;
    let protocol = stated(protocol_stated, RuleCriterion::Protocol)?.then_some(protocol);
    let source_port = check_rule_ports(
        stated(source_port_stated, RuleCriterion::SourcePort)?,
        source_port_low,
        source_port_high,
        index,
        RuleCriterion::SourcePort,
    )?;
    let destination_port = check_rule_ports(
        stated(destination_port_stated, RuleCriterion::DestinationPort)?,
        destination_port_low,
        destination_port_high,
        index,
        RuleCriterion::DestinationPort,
    )?;
    let icmp_type = stated(icmp_type_stated, RuleCriterion::IcmpType)?.then_some(icmp_type);
    let tracking = match (stated(tracking_stated, RuleCriterion::Tracking)?, tracking) {
        (false, _) => None,
        (true, 0) => Some(CheckedTracking::Opening),
        (true, 1) => Some(CheckedTracking::Related),
        (true, tracking) => return Err(ConfigImageError::RuleTrackingUnknown { index, tracking }),
    };

    if protocol == Some(ICMP_PROTOCOL) {
        for criterion in [RuleCriterion::SourcePort, RuleCriterion::DestinationPort] {
            let stated = match criterion {
                RuleCriterion::SourcePort => source_port.is_some(),
                _ => destination_port.is_some(),
            };
            if stated {
                return Err(ConfigImageError::RulePortCriterionOnIcmp { index, criterion });
            }
        }
    }
    if icmp_type.is_some()
        && let Some(protocol) = protocol
        && protocol != ICMP_PROTOCOL
    {
        return Err(ConfigImageError::RuleIcmpTypeOnNonIcmp { index, protocol });
    }

    let id = check_bounded_text(&id, false)
        .map_err(|fault| ConfigImageError::RuleIdNotAnIdentifier { index, fault })?;

    Ok(CheckedRule {
        id,
        ingress,
        egress,
        source,
        destination,
        protocol,
        source_port,
        destination_port,
        icmp_type,
        tracking,
        action,
    })
}

/// One interface criterion: the port it names, held to this build's port count
/// and to a port some interface actually addresses.
fn check_rule_port(
    stated: bool,
    port: u8,
    index: usize,
    criterion: RuleCriterion,
    port_count: u8,
    interfaces: &[Option<CheckedInterface>; MAX_INTERFACES],
) -> Result<Option<u8>, ConfigImageError> {
    if !stated {
        return Ok(None);
    }
    if port >= port_count {
        return Err(ConfigImageError::RulePortUnknown {
            index,
            criterion,
            port,
        });
    }
    if !interfaces.iter().flatten().any(|entry| entry.port == port) {
        return Err(ConfigImageError::RulePortUnconfigured {
            index,
            criterion,
            port,
        });
    }
    Ok(Some(port))
}

/// One address criterion, held to a legal prefix length and to naming the block
/// it appears to: `10.0.0.5/24` covers what `10.0.0.0/24` covers, and an
/// operator reading it back would not know that.
fn check_rule_prefix(
    stated: bool,
    network: [u8; 4],
    prefix_length: u8,
    index: usize,
    criterion: RuleCriterion,
) -> Result<Option<CheckedPrefix>, ConfigImageError> {
    if !stated {
        return Ok(None);
    }
    if prefix_length > MAX_PREFIX_LENGTH {
        return Err(ConfigImageError::RulePrefixLengthTooLong {
            index,
            criterion,
            prefix_length,
        });
    }
    if address_bits(network) & !prefix_mask(prefix_length) != 0 {
        return Err(ConfigImageError::RulePrefixNotCanonical {
            index,
            criterion,
            network,
        });
    }
    Ok(Some(CheckedPrefix {
        network,
        prefix_length,
    }))
}

/// One port criterion, held to being a range at all.
fn check_rule_ports(
    stated: bool,
    low: u16,
    high: u16,
    index: usize,
    criterion: RuleCriterion,
) -> Result<Option<CheckedPorts>, ConfigImageError> {
    if !stated {
        return Ok(None);
    }
    if low > high {
        return Err(ConfigImageError::RulePortRangeReversed {
            index,
            criterion,
            low,
            high,
        });
    }
    Ok(Some(CheckedPorts { low, high }))
}

/// The IANA number for ICMP, which is the one protocol whose criteria differ
/// from every other's. Stated here rather than taken from a header crate: this
/// crate depends on nothing, and the number is an assigned constant.
const ICMP_PROTOCOL: u8 = 1;

checked_value! {
    /// An enabled management interface that survived [`ConfigImage::check`].
    /// Holding one *is* the enable flag; see [`check_management`].
    CheckedManagement {
        prefix_length: u8,
        mac: [u8; 6],
        /// Network order, as the address appears in a header.
        address: [u8; 4],
        /// The station everything outside this port's prefix is handed to, or
        /// `None` where the operator stated none — then the port reaches its
        /// own link and nothing else. Holding a `Some` is the proof that the
        /// address is unicast, is not this port's own, and is on this port's
        /// link.
        gateway: Option<[u8; 4]>,
    }
}

checked_value! {
    /// One interface that survived [`ConfigImage::check`]. Its fields are
    /// private and it has no public constructor, so the only way to hold one is
    /// to have checked it — and `enabled` is a `bool` because the byte that was
    /// not 0 or 1 did not get this far.
    CheckedInterface {
        port: u8,
        enabled: bool,
        prefix_length: u8,
        mac: [u8; 6],
        /// Network order, as the address appears in a header.
        address: [u8; 4],
        /// The identity the document gave it; holding one proves
        /// `[a-z0-9-]{1,16}`.
        id: CheckedIdentifier,
    }
}

checked_value! {
    /// As [`CheckedInterface`], for a neighbour.
    CheckedNeighbour {
        port: u8,
        mac: [u8; 6],
        /// Network order, as the address appears in a header.
        address: [u8; 4],
    }
}

checked_value! {
    /// One filter rule that survived [`ConfigImage::check`].
    ///
    /// Every criterion is an `Option`, and the absence *is* the wildcard: a
    /// rule that matches every source holds `None` rather than a block covering
    /// everything, so nothing downstream compares against a value standing in
    /// for "do not compare". The two criteria that carry more than one number
    /// arrive as values whose own invariants were established here —
    /// [`CheckedPrefix`]'s host bits are clear and [`CheckedPorts`] is ordered.
    CheckedRule {
        /// Holding one proves `[a-z0-9-]{1,16}`.
        id: CheckedIdentifier,
        /// The port the named interface holds, resolved by the writer.
        ingress: Option<u8>,
        egress: Option<u8>,
        source: Option<CheckedPrefix>,
        destination: Option<CheckedPrefix>,
        /// The IANA protocol number.
        protocol: Option<u8>,
        source_port: Option<CheckedPorts>,
        destination_port: Option<CheckedPorts>,
        icmp_type: Option<u8>,
        /// Which of the two things that reach the filter this rule is about, or
        /// `None` for either of them.
        tracking: Option<CheckedTracking>,
        action: CheckedAction,
    }
}

/// Everything a [`ConfigImage`] said, decoded and owned.
///
/// Owned rather than borrowed because the image it came from may be the shared
/// region itself, and a view into bytes the writer can still change is not a
/// configuration anybody can decide under. The entries are `Option` slots
/// filled from the front, so the length is carried by the data and the writer's
/// count bounds nothing here: iteration is bounded by the arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedConfig<'image> {
    generation: u32,
    management: Option<CheckedManagement>,
    interfaces: [Option<CheckedInterface>; MAX_INTERFACES],
    neighbours: [Option<CheckedNeighbour>; MAX_NEIGHBOURS],
    /// The rule entries [`ConfigImage::check`] accepted, borrowed rather than
    /// decoded into an array of their own.
    ///
    /// The two small object kinds are owned above because owning them costs
    /// hundreds of bytes; owning this one costs pages, and the domains that
    /// read a configuration are exactly the ones whose stacks cannot hold one.
    /// The borrow is sound where the owned copies were needed for the opposite
    /// reason: what the reader holds is *its own* copy of the image, taken once
    /// by [`ConfigHandover::load_offer`] or [`ConfigHandover::load_committed`],
    /// so these bytes are not the shared region and no writer can move them
    /// under a decision.
    rules: &'image [RuleImage],
    /// Kept so a rule can be decoded on demand by the very function that
    /// checked it, rather than by a second one that could come to disagree.
    port_count: u8,
}

impl<'image> CheckedConfig<'image> {
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// The addressing of the management port, or `None` where it has none.
    #[must_use]
    pub const fn management(&self) -> Option<CheckedManagement> {
        self.management
    }

    pub fn interfaces(&self) -> impl Iterator<Item = CheckedInterface> {
        self.interfaces.iter().flatten().copied()
    }

    pub fn neighbours(&self) -> impl Iterator<Item = CheckedNeighbour> {
        self.neighbours.iter().flatten().copied()
    }

    /// One rule by its position, decoded on demand.
    ///
    /// `None` past the end, and only past the end: the decode below is the same
    /// call [`ConfigImage::check`] made over exactly these entries with exactly
    /// these arguments before it handed out this value, so a refusal here is
    /// unreachable. It is folded into the `Option` the index bound already
    /// needs rather than given a variant of its own, which leaves one way for
    /// this to answer nothing — and [`Self::rule_count`] is the bound a caller
    /// walks to, so a short read is visible to the caller rather than silent.
    /// `pipeline::Ruleset::build` is what refuses one.
    #[must_use]
    pub fn rule(&self, index: usize) -> Option<CheckedRule> {
        let raw = self.rules.get(index)?;
        check_rule(raw, index, self.port_count, &self.interfaces).ok()
    }

    /// The ruleset **in document order**, which is the order it is decided in:
    /// first match wins, so an iterator that reordered these would answer a
    /// different policy.
    pub fn rules(&self) -> impl Iterator<Item = CheckedRule> + '_ {
        (0..self.rules.len()).filter_map(|index| self.rule(index))
    }

    #[must_use]
    pub fn interface_count(&self) -> usize {
        self.interfaces().count()
    }

    #[must_use]
    pub fn neighbour_count(&self) -> usize {
        self.neighbours().count()
    }

    /// How many rules the image was accepted with, which is the bound
    /// [`Self::rule`] answers over and the number a consumer holds itself to.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// The three words that publish an image cross protection domains as the image
// does, and no declaration above covers them: `ConfigHandover` is the image
// plus a header rather than an image of its own.
const _: () = {
    assert!(size_of::<ConfigHandover>() == 14_676);
    assert!(align_of::<ConfigHandover>() == 4);
    assert!(offset_of!(ConfigHandover, offered) == 0);
    assert!(offset_of!(ConfigHandover, committed) == 4);
    assert!(offset_of!(ConfigHandover, publishing) == 8);
    assert!(offset_of!(ConfigHandover, image) == 12);

    assert!(size_of::<ConfigAck>() == 8);
    assert!(align_of::<ConfigAck>() == 4);
    assert!(offset_of!(ConfigAck, staged) == 0);
    assert!(offset_of!(ConfigAck, running) == 4);

    // A region must hold its type and be mappable, which is the whole of what
    // the derivation above is for.
    assert!(CONFIG_REGION_SIZE >= size_of::<ConfigHandover>());
    assert!(CONFIG_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(CONFIG_ACK_REGION_SIZE >= size_of::<ConfigAck>());
    assert!(CONFIG_ACK_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{sync::atomic::AtomicBool, thread};

    /// The offered image a handover holds, by value. The domains take it into
    /// storage they own, for the reason `load_offer` gives; a host test has a
    /// stack that does not care, and reads better for it.
    fn loaded(handover: &ConfigHandover) -> ConfigImage {
        let mut image = ConfigImage::ZERO;
        handover
            .load_offer(&mut image)
            .expect("no publisher is writing");
        image
    }

    /// Either verdict, so a property covers both encodable values.
    fn any_verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![Just(Verdict::Transmit), Just(Verdict::Discard)]
    }

    #[test]
    fn zero_matches_default_and_explicit_zero() {
        assert_eq!(Descriptor::default(), Descriptor::ZERO);
        assert_eq!(
            Descriptor::ZERO,
            Descriptor::new(0, 0, 0, Verdict::Transmit)
        );
    }

    #[test]
    fn descriptor_has_stable_little_endian_byte_layout() {
        // The exact on-wire image the peer PD reads: four little-endian u32s in
        // declaration order. This is the ABI regression test beyond size/align.
        let d = Descriptor::new(0x1122_3344, 0x5566_7788, 0x99AA_BBCC, Verdict::Discard);
        // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 16
        // bytes with no padding, so transmuting it to `[u8; 16]` is sound.
        let bytes: [u8; 16] = unsafe { core::mem::transmute(d) };
        assert_eq!(
            bytes,
            [
                0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xCC, 0xBB, 0xAA, 0x99, 0x01, 0x00,
                0x00, 0x00
            ]
        );
    }

    proptest! {
        /// For any field values, a descriptor round-trips through its wire image:
        /// its fields are exactly the constructor arguments, and its 16-byte
        /// `#[repr(C)]` image is the four fields as little-endian `u32`s in
        /// declaration order — and reconstructing a descriptor from those bytes
        /// yields the original.
        #[test]
        fn descriptor_round_trips_through_its_byte_image(
            buffer in any::<u32>(),
            offset in any::<u32>(),
            len in any::<u32>(),
            verdict in any_verdict(),
        ) {
            let descriptor = Descriptor::new(buffer, offset, len, verdict);
            prop_assert_eq!(descriptor.buffer, buffer);
            prop_assert_eq!(descriptor.offset, offset);
            prop_assert_eq!(descriptor.len, len);
            prop_assert_eq!(Verdict::from_bits(descriptor.verdict), Some(verdict));

            // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 16
            // bytes with no padding, so it transmutes to and from `[u8; 16]`.
            let bytes: [u8; 16] = unsafe { core::mem::transmute(descriptor) };
            let mut expected = [0u8; 16];
            expected[0..4].copy_from_slice(&buffer.to_le_bytes());
            expected[4..8].copy_from_slice(&offset.to_le_bytes());
            expected[8..12].copy_from_slice(&len.to_le_bytes());
            expected[12..16].copy_from_slice(&verdict.to_bits().to_le_bytes());
            prop_assert_eq!(bytes, expected);

            // SAFETY: same `repr(C)`, 16-byte, no-padding guarantee in reverse;
            // any bit pattern is a valid `Descriptor` (four `u32` fields).
            let recovered: Descriptor = unsafe { core::mem::transmute(bytes) };
            prop_assert_eq!(recovered, descriptor);
        }

        /// The verdict word is peer-written, so decoding is total over `u32`:
        /// exactly the values `to_bits` can produce decode, every other one is
        /// refused rather than coerced to a variant nobody chose.
        #[test]
        fn from_bits_accepts_exactly_what_to_bits_produces(bits in any::<u32>()) {
            let expected = [Verdict::Transmit, Verdict::Discard]
                .into_iter()
                .find(|verdict| verdict.to_bits() == bits);
            prop_assert_eq!(Verdict::from_bits(bits), expected);
            if let Some(verdict) = Verdict::from_bits(bits) {
                prop_assert_eq!(verdict.to_bits(), bits);
            }
        }
    }

    /// Ports this build has, in the tests. Two, as the appliance has.
    const PORTS: u8 = 2;

    /// A build with one port per interface slot the image holds. One port per
    /// interface is a rule, so the ABI's own interface capacity is only
    /// reachable on a build with that many ports — the appliance's two bound it
    /// to two, and a test about the capacity has to say which it is testing.
    const WIDE: u8 = MAX_INTERFACES as u8;

    /// A locally administered unicast address, so nothing about it is refusable.
    const UNICAST: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x50];

    /// One interface per port, each distinct in every field a rule compares:
    /// its own port, its own MAC, its own `/24` and its own id.
    fn interface(port: u8) -> InterfaceImage {
        InterfaceImage {
            port,
            enabled: 1,
            prefix_length: 24,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x50 + port],
            address: [10, 0, port, 1],
            id: IdentifierImage::from_text(&[b'd', b'p', b'0' + port]),
            ..InterfaceImage::ZERO
        }
    }

    /// The `index`th neighbour: on the port `index` cycles onto, at a host
    /// address inside that port's `/24` and distinct from every other
    /// neighbour's on it.
    fn neighbour(index: usize) -> NeighbourImage {
        let port = (index % usize::from(PORTS)) as u8;
        NeighbourImage {
            port,
            mac: UNICAST,
            address: [10, 0, port, 2 + (index / usize::from(PORTS)) as u8],
            ..NeighbourImage::ZERO
        }
    }

    /// An image whose first `interfaces` and `neighbours` slots are valid,
    /// with the counts to match.
    fn image(interfaces: usize, neighbours: usize) -> ConfigImage {
        let mut image = ConfigImage::ZERO;
        image.generation = 7;
        image.interface_count = interfaces as u32;
        image.neighbour_count = neighbours as u32;
        for (index, slot) in image.interfaces.iter_mut().enumerate() {
            *slot = interface(index as u8);
        }
        for (index, slot) in image.neighbours.iter_mut().enumerate() {
            *slot = neighbour(index);
        }
        image.seal();
        image
    }

    /// `raw` with its digest re-taken. Every test below edits a field of a valid
    /// image, and an edit leaves the digest naming the bytes before it — so
    /// without this the refusal under test is never reached and every one of
    /// them asserts the digest instead.
    fn resealed(raw: &mut ConfigImage) -> &ConfigImage {
        raw.seal();
        raw
    }

    #[test]
    fn a_zeroed_region_is_the_fail_closed_configuration() {
        let checked = ConfigImage::ZERO.check(PORTS).expect("zero is valid");
        assert_eq!(checked.generation(), 0);
        assert_eq!(checked.interface_count(), 0);
        assert_eq!(checked.neighbour_count(), 0);
        assert_eq!(
            checked.management(),
            None,
            "a zeroed region addresses no management port"
        );
        assert_eq!(checked.interfaces().next(), None);
        assert_eq!(checked.neighbours().next(), None);
    }

    /// The digest covers every byte of the image, so no single-byte edit
    /// survives it. Field by field rather than one edit, because a fold that had
    /// dropped a field would still pass every other one.
    #[test]
    fn no_byte_of_a_sealed_image_can_be_changed_without_the_digest_refusing_it() {
        let edits: [fn(&mut ConfigImage); 9] = [
            |raw| raw.generation ^= 1,
            |raw| raw.interface_count = 1,
            |raw| raw.neighbour_count = 0,
            |raw| raw.rule_count = 1,
            |raw| raw.interfaces[0].port ^= 1,
            |raw| raw.interfaces[0]._pad = [0xaa; 1],
            |raw| raw.interfaces[0].id = IdentifierImage::from_text(b"other"),
            |raw| raw.neighbours[1].address = [10, 0, 1, 9],
            |raw| raw.management.enabled = 1,
        ];
        for (index, edit) in edits.into_iter().enumerate() {
            let mut torn = image(2, 2);
            edit(&mut torn);
            let declared = torn.digest;
            assert_eq!(
                torn.check(PORTS),
                Err(ConfigImageError::DigestMismatch {
                    declared,
                    folded: torn.computed_digest(),
                }),
                "edit {index}"
            );
        }
    }

    /// The rules array is a quarter of a million bytes past the last field a
    /// four-page image ever reached, so it gets its own case: a fold that
    /// stopped at `rule_count` would pass every test above.
    #[test]
    fn a_rule_body_no_count_covers_is_still_covered_by_the_digest() {
        let mut torn = image(2, 2);
        torn.rules[MAX_RULES - 1].icmp_type ^= 0xff;
        assert!(matches!(
            torn.check(PORTS),
            Err(ConfigImageError::DigestMismatch { .. })
        ));
    }

    /// The one image whose digest is not a computation: a region the kernel
    /// zeroed is generation 0, and a reader that refused it would refuse the
    /// fail-closed configuration every domain starts under.
    #[test]
    fn the_zeroed_region_is_its_own_digest() {
        assert_eq!(ConfigImage::ZERO.digest, 0);
        assert_eq!(ConfigImage::ZERO.computed_digest(), 0);
        let mut sealed = ConfigImage::ZERO;
        sealed.seal();
        assert_eq!(sealed, ConfigImage::ZERO);
    }

    /// The blend the digest exists to refuse, assembled by hand: the counts of
    /// one publication over the entries of another. Every entry of it is
    /// well-formed and every field-level rule holds of it, which is exactly why
    /// no field-level rule can catch it.
    #[test]
    fn a_copy_assembled_from_two_publications_is_refused_as_one_image() {
        let wide = image(2, 2);
        let narrow = {
            let mut narrow = image(2, 2);
            narrow.interfaces[1] = interface(1);
            narrow.interfaces[1].address = [10, 0, 1, 9];
            narrow.seal();
            narrow
        };
        wide.check(PORTS).expect("one publication checks");
        narrow.check(PORTS).expect("the other checks too");

        let blend = ConfigImage {
            interfaces: narrow.interfaces,
            ..wide
        };
        assert!(matches!(
            blend.check(PORTS),
            Err(ConfigImageError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn a_checked_image_carries_its_generation_and_every_decoded_field() {
        let mut raw = image(2, 3);
        let checked = resealed(&mut raw).check(PORTS).expect("valid");
        assert_eq!(checked.generation(), 7);
        assert_eq!(checked.interface_count(), 2);
        assert_eq!(checked.neighbour_count(), 3);

        let first = checked.interfaces().next().expect("one interface");
        assert_eq!(first.port(), 0);
        assert!(first.enabled());
        assert_eq!(first.prefix_length(), 24);
        assert_eq!(first.mac(), UNICAST);
        assert_eq!(first.address(), [10, 0, 0, 1]);

        let hop = checked.neighbours().next().expect("one neighbour");
        assert_eq!(hop.port(), 0);
        assert_eq!(hop.mac(), UNICAST);
        assert_eq!(hop.address(), [10, 0, 0, 2]);
    }

    #[test]
    fn only_the_counted_prefix_is_read_whatever_follows_it() {
        // Every slot past the count is a value that would be refused if read.
        let mut raw = image(1, 1);
        for slot in raw.interfaces.iter_mut().skip(1) {
            slot.enabled = 0xff;
            slot.port = 0xff;
        }
        for slot in raw.neighbours.iter_mut().skip(1) {
            slot.mac = [0; 6];
        }
        let checked = resealed(&mut raw)
            .check(PORTS)
            .expect("the garbage is beyond the counts");
        assert_eq!(checked.interface_count(), 1);
        assert_eq!(checked.neighbour_count(), 1);
    }

    #[test]
    fn an_interface_count_at_capacity_is_accepted() {
        let mut raw = image(MAX_INTERFACES, 0);
        let checked = resealed(&mut raw).check(WIDE).expect("valid");
        assert_eq!(checked.interface_count(), MAX_INTERFACES);
    }

    /// One port per interface, so a build with fewer ports than the image has
    /// slots cannot run a full one — and says which entry it refused.
    #[test]
    fn more_interfaces_than_the_build_has_ports_is_refused() {
        assert_eq!(
            image(MAX_INTERFACES, 0).check(PORTS),
            Err(ConfigImageError::InterfacePortUnknown { index: 2, port: 2 })
        );
    }

    #[test]
    fn an_interface_count_above_capacity_is_refused() {
        let mut raw = image(MAX_INTERFACES, 0);
        raw.interface_count = MAX_INTERFACES as u32 + 1;
        assert_eq!(
            resealed(&mut raw).check(PORTS),
            Err(ConfigImageError::InterfaceCountExceedsCapacity { count: 9 })
        );
    }

    #[test]
    fn an_interface_count_of_u32_max_is_refused_rather_than_wrapped() {
        let mut raw = image(0, 0);
        raw.interface_count = u32::MAX;
        assert_eq!(
            resealed(&mut raw).check(PORTS),
            Err(ConfigImageError::InterfaceCountExceedsCapacity { count: u32::MAX })
        );
    }

    #[test]
    fn a_neighbour_count_at_capacity_is_accepted() {
        let mut raw = image(2, MAX_NEIGHBOURS);
        let checked = resealed(&mut raw).check(PORTS).expect("valid");
        assert_eq!(checked.neighbour_count(), MAX_NEIGHBOURS);
    }

    #[test]
    fn a_neighbour_count_above_capacity_is_refused() {
        let mut raw = image(0, MAX_NEIGHBOURS);
        raw.neighbour_count = MAX_NEIGHBOURS as u32 + 1;
        assert_eq!(
            resealed(&mut raw).check(PORTS),
            Err(ConfigImageError::NeighbourCountExceedsCapacity { count: 33 })
        );
    }

    #[test]
    fn an_enabled_byte_of_zero_or_one_is_accepted() {
        for (bits, expected) in [(0u8, false), (1, true)] {
            let mut raw = image(1, 0);
            raw.interfaces[0].enabled = bits;
            let checked = resealed(&mut raw)
                .check(PORTS)
                .expect("0 and 1 are the decodable values");
            assert_eq!(
                checked.interfaces().next().map(|i| i.enabled()),
                Some(expected)
            );
        }
    }

    #[test]
    fn an_enabled_byte_that_is_neither_zero_nor_one_is_refused() {
        for bits in [2u8, 255] {
            let mut raw = image(2, 0);
            raw.interfaces[1].enabled = bits;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::InterfaceEnabledNotBoolean {
                    index: 1,
                    enabled: bits
                })
            );
        }
    }

    #[test]
    fn an_interface_naming_a_port_the_build_does_not_have_is_refused() {
        let mut raw = image(1, 0);
        raw.interfaces[0].port = PORTS;
        assert_eq!(
            resealed(&mut raw).check(PORTS),
            Err(ConfigImageError::InterfacePortUnknown { index: 0, port: 2 })
        );
    }

    #[test]
    fn a_neighbour_naming_a_port_the_build_does_not_have_is_refused() {
        let mut raw = image(2, 2);
        raw.neighbours[1].port = 200;
        assert_eq!(
            resealed(&mut raw).check(PORTS),
            Err(ConfigImageError::NeighbourPortUnknown {
                index: 1,
                port: 200
            })
        );
    }

    #[test]
    fn a_build_with_no_ports_accepts_no_entry_at_all() {
        assert_eq!(
            image(1, 0).check(0),
            Err(ConfigImageError::InterfacePortUnknown { index: 0, port: 0 })
        );
        assert_eq!(
            image(0, 1).check(0),
            Err(ConfigImageError::NeighbourPortUnknown { index: 0, port: 0 })
        );
    }

    #[test]
    fn a_prefix_length_of_thirty_two_is_accepted() {
        let mut raw = image(1, 0);
        raw.interfaces[0].prefix_length = MAX_PREFIX_LENGTH;
        let checked = resealed(&mut raw)
            .check(PORTS)
            .expect("a host route is a prefix");
        assert_eq!(
            checked.interfaces().next().map(|i| i.prefix_length()),
            Some(32)
        );
    }

    #[test]
    fn a_prefix_length_above_thirty_two_is_refused() {
        for length in [MAX_PREFIX_LENGTH + 1, 200, u8::MAX] {
            let mut raw = image(1, 0);
            raw.interfaces[0].prefix_length = length;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::InterfacePrefixLengthTooLong {
                    index: 0,
                    prefix_length: length
                })
            );
        }
    }

    #[test]
    fn an_interface_mac_that_is_not_unicast_is_refused() {
        for mac in [[0x01, 0, 0, 0, 0, 0], [0xff; 6], [0; 6]] {
            let mut raw = image(1, 0);
            raw.interfaces[0].mac = mac;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::InterfaceMacNotUnicast { index: 0, mac })
            );
        }
    }

    #[test]
    fn a_neighbour_mac_that_is_not_unicast_is_refused() {
        for mac in [[0x01, 0, 0, 0, 0, 0], [0xff; 6], [0; 6]] {
            let mut raw = image(2, 1);
            raw.neighbours[0].mac = mac;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::NeighbourMacNotUnicast { index: 0, mac })
            );
        }
    }

    #[test]
    fn an_interface_address_no_host_may_hold_is_refused() {
        for address in [[224, 0, 0, 1], [127, 0, 0, 1], [0, 0, 0, 0], [255; 4]] {
            let mut raw = image(1, 0);
            raw.interfaces[0].address = address;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::InterfaceAddressNotUnicast { index: 0, address }),
                "{address:?}"
            );
        }
    }

    #[test]
    fn an_interface_at_its_own_network_or_broadcast_address_is_refused() {
        for address in [[10, 0, 0, 0], [10, 0, 0, 255]] {
            let mut raw = image(1, 0);
            raw.interfaces[0].address = address;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::InterfaceAddressNotAHostAddress { index: 0, address }),
                "{address:?}"
            );
        }
        // RFC 3021 leaves both usable on a point-to-point link and a host route.
        for (prefix_length, address) in [(31u8, [10, 0, 0, 0]), (32, [10, 0, 0, 255])] {
            let mut raw = image(1, 0);
            raw.interfaces[0].prefix_length = prefix_length;
            raw.interfaces[0].address = address;
            resealed(&mut raw)
                .check(PORTS)
                .expect("neither reserves an address");
        }
    }

    /// The four rules about a *pair* of interfaces, each broken on its own so
    /// what a test proves is that *that* pair is caught.
    #[test]
    fn two_interfaces_a_forwarding_domain_could_not_tell_apart_are_refused() {
        let clash = |change: fn(&mut InterfaceImage)| {
            let mut raw = image(2, 0);
            change(&mut raw.interfaces[1]);
            resealed(&mut raw).check(PORTS).map(|_| ())
        };

        assert_eq!(
            clash(|entry| entry.id = IdentifierImage::from_text(b"dp0")),
            Err(ConfigImageError::InterfaceIdDuplicated { index: 1, other: 0 })
        );
        assert_eq!(
            clash(|entry| entry.port = 0),
            Err(ConfigImageError::InterfacePortDuplicated {
                index: 1,
                other: 0,
                port: 0,
            })
        );
        assert_eq!(
            clash(|entry| entry.mac = UNICAST),
            Err(ConfigImageError::InterfaceMacDuplicated {
                index: 1,
                other: 0,
                mac: UNICAST,
            })
        );
        assert_eq!(
            clash(|entry| entry.address = [10, 0, 0, 9]),
            Err(ConfigImageError::InterfacePrefixesOverlap { index: 1, other: 0 })
        );
        // The containment case: a shorter prefix swallowing a longer one is an
        // overlap even though neither address is in the other's block.
        assert_eq!(
            clash(|entry| {
                entry.address = [10, 128, 0, 1];
                entry.prefix_length = 8;
            }),
            Err(ConfigImageError::InterfacePrefixesOverlap { index: 1, other: 0 })
        );
    }

    /// Every rule that holds a neighbour to the link it claims to be on.
    #[test]
    fn a_neighbour_that_is_not_one_of_its_links_hosts_is_refused() {
        let with = |change: fn(&mut NeighbourImage)| {
            let mut raw = image(2, 1);
            change(&mut raw.neighbours[0]);
            resealed(&mut raw).check(PORTS).map(|_| ())
        };

        for address in [[224, 0, 0, 1], [0, 0, 0, 0], [255; 4]] {
            let mut raw = image(2, 1);
            raw.neighbours[0].address = address;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::NeighbourAddressNotUnicast { index: 0, address }),
                "{address:?}"
            );
        }
        assert_eq!(
            with(|entry| entry.address = [10, 0, 0, 1]),
            Err(ConfigImageError::NeighbourIsInterfaceAddress {
                index: 0,
                address: [10, 0, 0, 1],
            })
        );
        assert_eq!(
            with(|entry| entry.address = [10, 9, 9, 9]),
            Err(ConfigImageError::NeighbourOutsidePrefix {
                index: 0,
                address: [10, 9, 9, 9],
            })
        );
        // The directed subnet broadcast of its own link, which a routed frame
        // would otherwise be unicast to.
        for address in [[10, 0, 0, 255], [10, 0, 0, 0]] {
            let mut raw = image(2, 1);
            raw.neighbours[0].address = address;
            assert_eq!(
                resealed(&mut raw).check(PORTS),
                Err(ConfigImageError::NeighbourAddressNotAHostAddress { index: 0, address }),
                "{address:?}"
            );
        }
    }

    /// A port the build has but this configuration does not address: the
    /// neighbour names a link with no prefix to be inside of.
    #[test]
    fn a_neighbour_on_a_port_no_interface_addresses_is_refused() {
        let mut raw = image(1, 2);
        raw.neighbours[0].port = 0;
        raw.neighbours[1].port = 1;
        assert_eq!(
            resealed(&mut raw).check(PORTS),
            Err(ConfigImageError::NeighbourPortUnconfigured { index: 1, port: 1 })
        );
    }

    #[test]
    fn two_neighbours_at_one_address_on_one_port_are_refused() {
        let mut raw = image(2, 3);
        raw.neighbours[2] = raw.neighbours[0];
        assert_eq!(
            resealed(&mut raw).check(PORTS),
            Err(ConfigImageError::NeighbourAddressDuplicated { index: 2, other: 0 })
        );

        // The rule is per port: one host number on two separate links is two
        // hosts, and only the prefixes overlapping would make it one.
        let mut apart = image(2, 2);
        apart.neighbours[1].port = 1;
        apart.neighbours[1].address = [10, 0, 1, 2];
        apart.check(PORTS).expect("two links, two hosts");
    }

    /// An enabled management entry decodes to its three values; a disabled one
    /// decodes to nothing at all, so an unaddressed port has one representation.
    #[test]
    fn the_management_entry_is_read_only_where_it_is_enabled() {
        let mut raw = image(1, 1);
        raw.management = ManagementImage {
            enabled: 1,
            prefix_length: 24,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x52],
            address: [10, 0, 2, 15],
            ..ManagementImage::ZERO
        };
        let management = resealed(&mut raw)
            .check(PORTS)
            .expect("an enabled entry")
            .management()
            .expect("an enabled entry decodes");
        assert_eq!(management.prefix_length(), 24);
        assert_eq!(management.mac(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
        assert_eq!(management.address(), [10, 0, 2, 15]);

        // Disabled, and every other field left as a writer put it: none of them
        // is interpreted, so none of them can refuse the image.
        let mut disabled = raw;
        disabled.management.enabled = 0;
        disabled.management.prefix_length = 99;
        disabled.management.mac = [0xff; 6];
        assert_eq!(
            resealed(&mut disabled)
                .check(PORTS)
                .expect("a disabled entry")
                .management(),
            None
        );
    }

    #[test]
    fn a_management_entry_no_endpoint_could_answer_under_is_refused_by_its_own_rule() {
        let enabled = ManagementImage {
            enabled: 1,
            prefix_length: 24,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x52],
            address: [10, 0, 2, 15],
            ..ManagementImage::ZERO
        };
        let with = |management: ManagementImage| {
            let mut raw = image(1, 1);
            raw.management = management;
            resealed(&mut raw).check(PORTS).map(|_| ())
        };

        for byte in [2u8, 3, 0xff] {
            assert_eq!(
                with(ManagementImage {
                    enabled: byte,
                    ..enabled
                }),
                Err(ConfigImageError::ManagementEnabledNotBoolean { enabled: byte })
            );
        }
        for prefix_length in [MAX_PREFIX_LENGTH + 1, 64, 255] {
            assert_eq!(
                with(ManagementImage {
                    prefix_length,
                    ..enabled
                }),
                Err(ConfigImageError::ManagementPrefixLengthTooLong { prefix_length })
            );
        }
        for mac in [[0xff; 6], [0x01, 0, 0, 0, 0, 1], [0; 6]] {
            assert_eq!(
                with(ManagementImage { mac, ..enabled }),
                Err(ConfigImageError::ManagementMacNotUnicast { mac })
            );
        }
        for address in [[224, 0, 0, 1], [127, 0, 0, 1], [0; 4], [255; 4]] {
            assert_eq!(
                with(ManagementImage { address, ..enabled }),
                Err(ConfigImageError::ManagementAddressNotUnicast { address }),
                "{address:?}"
            );
        }
        for address in [[10, 0, 2, 0], [10, 0, 2, 255]] {
            assert_eq!(
                with(ManagementImage { address, ..enabled }),
                Err(ConfigImageError::ManagementAddressNotAHostAddress { address }),
                "{address:?}"
            );
        }
    }

    /// The gateway's own four, which are the only rules here about one field's
    /// relationship to another: every one of them is judged against the address
    /// above rather than on the gateway alone.
    #[test]
    fn a_gateway_the_management_port_could_not_reach_is_refused_by_its_own_rule() {
        let enabled = ManagementImage {
            enabled: 1,
            prefix_length: 24,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x52],
            address: [10, 0, 2, 15],
            ..ManagementImage::ZERO
        };
        let with = |management: ManagementImage| {
            let mut raw = image(1, 1);
            raw.management = management;
            resealed(&mut raw).check(PORTS).map(|_| ())
        };

        // Stating none is not stating a bad one: the zeroed gateway beside a
        // zero flag is exactly what a zeroed region holds.
        with(enabled).expect("no gateway is a gateway rule breaks nothing");
        with(ManagementImage {
            gateway_stated: 1,
            gateway: [10, 0, 2, 2],
            ..enabled
        })
        .expect("a station on this port's own link");

        for stated in [2u8, 3, 0xff] {
            assert_eq!(
                with(ManagementImage {
                    gateway_stated: stated,
                    gateway: [10, 0, 2, 2],
                    ..enabled
                }),
                Err(ConfigImageError::ManagementGatewayStatedNotBoolean { stated })
            );
        }
        for gateway in [[224, 0, 0, 1], [127, 0, 0, 1], [0; 4], [255; 4]] {
            assert_eq!(
                with(ManagementImage {
                    gateway_stated: 1,
                    gateway,
                    ..enabled
                }),
                Err(ConfigImageError::ManagementGatewayNotUnicast { gateway }),
                "{gateway:?}"
            );
        }
        assert_eq!(
            with(ManagementImage {
                gateway_stated: 1,
                gateway: [10, 0, 2, 15],
                ..enabled
            }),
            Err(ConfigImageError::ManagementGatewayIsTheAddress {
                gateway: [10, 0, 2, 15]
            })
        );
        for gateway in [[10, 0, 3, 1], [192, 168, 0, 1]] {
            assert_eq!(
                with(ManagementImage {
                    gateway_stated: 1,
                    gateway,
                    ..enabled
                }),
                Err(ConfigImageError::ManagementGatewayOffLink { gateway }),
                "{gateway:?}"
            );
        }

        // A disabled entry leaves the gateway uninterpreted like every other
        // field, so none of the four can refuse one.
        with(ManagementImage {
            enabled: 0,
            gateway_stated: 0xff,
            gateway: [255; 4],
            ..enabled
        })
        .expect("a disabled entry has no gateway to be about");
    }

    /// The two rules the capability grants cannot express, and so the two a
    /// compromised writer would otherwise have had entirely to itself: one
    /// address the appliance would both route towards and terminate on, and one
    /// L2 address on a dataplane port and the management port at once.
    #[test]
    fn a_management_entry_the_dataplane_would_answer_for_too_is_refused() {
        let with = |management: ManagementImage| {
            let mut raw = image(2, 1);
            raw.management = management;
            resealed(&mut raw).check(PORTS).map(|_| ())
        };
        let enabled = ManagementImage {
            enabled: 1,
            prefix_length: 24,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x52],
            address: [10, 0, 2, 15],
            ..ManagementImage::ZERO
        };
        with(enabled).expect("the fixture keeps them apart");

        // Inside the second interface's prefix rather than the first, so the
        // refusal names which interface it collided with.
        assert_eq!(
            with(ManagementImage {
                address: [10, 0, 1, 9],
                ..enabled
            }),
            Err(ConfigImageError::ManagementPrefixCollidesWithInterface { index: 1 })
        );
        assert_eq!(
            with(ManagementImage {
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x51],
                ..enabled
            }),
            Err(ConfigImageError::ManagementMacCollidesWithInterface { index: 1 })
        );
        // A prefix short enough to swallow both dataplane prefixes collides
        // with the first of them.
        assert_eq!(
            with(ManagementImage {
                prefix_length: 8,
                address: [10, 200, 0, 1],
                ..enabled
            }),
            Err(ConfigImageError::ManagementPrefixCollidesWithInterface { index: 0 })
        );
    }

    #[test]
    fn padding_the_writer_chose_is_read_by_nothing() {
        let mut raw = image(1, 1);
        raw.interfaces[0]._pad = [0xaa; 1];
        raw.interfaces[0]._pad2 = [0xbb; 2];
        raw.neighbours[0]._pad = [0xcc; 3];
        raw.neighbours[0]._pad2 = [0xdd; 2];
        raw.management._pad = [0xee; 1];
        raw.management._pad2 = [0xff; 2];
        assert_eq!(resealed(&mut raw).check(PORTS), image(1, 1).check(PORTS));
    }

    #[test]
    fn the_layout_the_reading_domain_maps_is_the_recorded_one() {
        assert_eq!(size_of::<InterfaceImage>(), 36);
        assert_eq!(size_of::<NeighbourImage>(), 16);
        assert_eq!(size_of::<ManagementImage>(), 20);
        assert_eq!(size_of::<RuleImage>(), 54);
        assert_eq!(size_of::<ConfigImage>(), 14_664);
        assert_eq!(size_of::<ConfigHandover>(), 14_676);
        assert_eq!(size_of::<ConfigAck>(), 8);
        assert_eq!(offset_of!(ConfigImage, management), 16);
        assert_eq!(offset_of!(ConfigImage, interfaces), 36);
        assert_eq!(offset_of!(ConfigImage, neighbours), 324);
        assert_eq!(offset_of!(ConfigImage, rule_count), 836);
        assert_eq!(offset_of!(ConfigImage, rules), 840);
        assert_eq!(offset_of!(ConfigHandover, publishing), 8);
        assert_eq!(offset_of!(ConfigHandover, image), 12);
        // The handover region is reserved past what it holds, so its size is
        // the reservation rather than the one page the image would round to.
        assert_eq!(CONFIG_REGION_SIZE, 0x8000);
        assert!(CONFIG_REGION_SIZE > size_of::<ConfigHandover>());
        assert_eq!(CONFIG_ACK_REGION_SIZE, 0x1000);
    }

    /// The compile-time assertions above prove the same equalities, but only
    /// for the build that compiles them away; this is the one a failure names.
    #[test]
    fn the_atomic_image_occupies_exactly_the_bytes_the_plain_one_does() {
        assert_eq!(size_of::<ConfigSlot>(), size_of::<ConfigImage>());
        assert_eq!(align_of::<ConfigSlot>(), align_of::<ConfigImage>());
        assert_eq!(
            [
                offset_of!(ConfigSlot, generation),
                offset_of!(ConfigSlot, interface_count),
                offset_of!(ConfigSlot, neighbour_count),
                offset_of!(ConfigSlot, digest),
                offset_of!(ConfigSlot, management),
                offset_of!(ConfigSlot, interfaces),
                offset_of!(ConfigSlot, neighbours),
            ],
            [
                offset_of!(ConfigImage, generation),
                offset_of!(ConfigImage, interface_count),
                offset_of!(ConfigImage, neighbour_count),
                offset_of!(ConfigImage, digest),
                offset_of!(ConfigImage, management),
                offset_of!(ConfigImage, interfaces),
                offset_of!(ConfigImage, neighbours),
            ]
        );

        assert_eq!(size_of::<InterfaceSlot>(), size_of::<InterfaceImage>());
        assert_eq!(align_of::<InterfaceSlot>(), align_of::<InterfaceImage>());
        assert_eq!(
            [
                offset_of!(InterfaceSlot, port),
                offset_of!(InterfaceSlot, enabled),
                offset_of!(InterfaceSlot, prefix_length),
                offset_of!(InterfaceSlot, _pad),
                offset_of!(InterfaceSlot, mac),
                offset_of!(InterfaceSlot, _pad2),
                offset_of!(InterfaceSlot, address),
                offset_of!(InterfaceSlot, id),
            ],
            [
                offset_of!(InterfaceImage, port),
                offset_of!(InterfaceImage, enabled),
                offset_of!(InterfaceImage, prefix_length),
                offset_of!(InterfaceImage, _pad),
                offset_of!(InterfaceImage, mac),
                offset_of!(InterfaceImage, _pad2),
                offset_of!(InterfaceImage, address),
                offset_of!(InterfaceImage, id),
            ]
        );

        assert_eq!(size_of::<ManagementSlot>(), size_of::<ManagementImage>());
        assert_eq!(align_of::<ManagementSlot>(), align_of::<ManagementImage>());
        assert_eq!(
            [
                offset_of!(ManagementSlot, enabled),
                offset_of!(ManagementSlot, prefix_length),
                offset_of!(ManagementSlot, _pad),
                offset_of!(ManagementSlot, mac),
                offset_of!(ManagementSlot, _pad2),
                offset_of!(ManagementSlot, address),
            ],
            [
                offset_of!(ManagementImage, enabled),
                offset_of!(ManagementImage, prefix_length),
                offset_of!(ManagementImage, _pad),
                offset_of!(ManagementImage, mac),
                offset_of!(ManagementImage, _pad2),
                offset_of!(ManagementImage, address),
            ]
        );

        assert_eq!(size_of::<NeighbourSlot>(), size_of::<NeighbourImage>());
        assert_eq!(align_of::<NeighbourSlot>(), align_of::<NeighbourImage>());
        assert_eq!(
            [
                offset_of!(NeighbourSlot, port),
                offset_of!(NeighbourSlot, _pad),
                offset_of!(NeighbourSlot, mac),
                offset_of!(NeighbourSlot, _pad2),
                offset_of!(NeighbourSlot, address),
            ],
            [
                offset_of!(NeighbourImage, port),
                offset_of!(NeighbourImage, _pad),
                offset_of!(NeighbourImage, mac),
                offset_of!(NeighbourImage, _pad2),
                offset_of!(NeighbourImage, address),
            ]
        );
    }

    /// A zeroed region reads back as the zeroed image, which is what lets a
    /// reader come up against one before anything has been published.
    #[test]
    fn an_untouched_handover_holds_the_zero_image() {
        assert_eq!(loaded(&ConfigHandover::zero()), ConfigImage::ZERO);
        assert_eq!(ConfigSlot::zero().load(), ConfigImage::ZERO);
        assert_eq!(InterfaceSlot::zero().load(), InterfaceImage::ZERO);
        assert_eq!(NeighbourSlot::zero().load(), NeighbourImage::ZERO);
        assert_eq!(ManagementSlot::zero().load(), ManagementImage::ZERO);
    }

    /// Publishing is one act: the generation the reader sees and the bytes it
    /// reads under that generation are the ones handed to the same call.
    #[test]
    fn publishing_offers_the_generation_and_the_bytes_it_names() {
        let handover = ConfigHandover::zero();
        let mut offered = image(2, 3);
        offered.generation = 9;
        handover.publish(&offered);
        assert_eq!(handover.offered_generation(), offered.generation);
        assert_eq!(loaded(&handover), offered);
        // Committing moves its own word and disturbs neither of the two.
        handover.publish_committed(8);
        assert_eq!(handover.committed_generation(), 8);
        assert_eq!(handover.offered_generation(), 9);
        assert_eq!(loaded(&handover), offered);

        // A second generation replaces both together.
        let mut next = image(1, 1);
        next.generation = 10;
        handover.publish(&next);
        assert_eq!(handover.offered_generation(), 10);
        assert_eq!(loaded(&handover), next);
    }

    #[test]
    fn a_published_generation_is_what_the_other_side_reads_back() {
        let handover = ConfigHandover::zero();
        assert_eq!(handover.offered_generation(), 0);
        assert_eq!(handover.committed_generation(), 0);
        let mut offered = ConfigImage::ZERO;
        offered.generation = 4;
        handover.publish(&offered);
        handover.publish_committed(3);
        assert_eq!(handover.offered_generation(), 4);
        assert_eq!(handover.committed_generation(), 3);
        assert_eq!(loaded(&handover), offered);

        let ack = ConfigAck::zero();
        assert_eq!(ack.staged_generation(), 0);
        assert_eq!(ack.running_generation(), 0);
        ack.publish_staged(4);
        ack.publish_running(2);
        assert_eq!(ack.staged_generation(), 4);
        assert_eq!(ack.running_generation(), 2);
    }

    /// The counter is what a reader keys a settled region on, so it has to end
    /// even and differ from what a reader could have taken across every publish.
    #[test]
    fn publishing_leaves_the_counter_even_and_moved() {
        let handover = ConfigHandover::zero();
        let mut seen = handover.publishing.load(Ordering::Relaxed);
        assert_eq!(seen, 0, "a zeroed region is settled");
        for generation in 1..5u32 {
            let mut offered = image(1, 1);
            offered.generation = generation;
            offered.seal();
            handover.publish(&offered);
            let now = handover.publishing.load(Ordering::Relaxed);
            assert!(now.is_multiple_of(2), "settled after a publish");
            assert_ne!(now, seen, "a reader cannot mistake this for the last one");
            seen = now;
        }
        // A region a writer left mid-publish is published into correctly rather
        // than being left permanently unreadable.
        handover.publishing.store(7, Ordering::Relaxed);
        let mut offered = image(1, 1);
        offered.generation = 9;
        offered.seal();
        handover.publish(&offered);
        assert_eq!(handover.publishing.load(Ordering::Relaxed), 8);
        assert_eq!(loaded(&handover), offered);
    }

    /// A reader that meets an odd counter through every attempt answers nothing,
    /// which is what keeps a peer holding it odd from spinning one.
    #[test]
    fn a_region_left_mid_publish_is_read_as_nothing_rather_than_waited_on() {
        let handover = ConfigHandover::zero();
        let mut offered = image(1, 1);
        offered.generation = 3;
        offered.seal();
        handover.publish(&offered);
        handover.publishing.store(1, Ordering::Relaxed);

        let mut into = ConfigImage::ZERO;
        assert_eq!(handover.load_offer(&mut into), None);
        assert_eq!(handover.load_committed(&mut into), None);
        assert_eq!(
            into,
            ConfigImage::ZERO,
            "a discarded copy leaves the caller's storage alone"
        );

        handover.publishing.store(2, Ordering::Relaxed);
        assert_eq!(handover.load_offer(&mut into), Some(3));
        assert_eq!(into, offered);
    }

    /// The whole of C1, over a shared region and two threads: a reader copying
    /// while a publisher rewrites underneath it must come away with one
    /// publication or with nothing, never with a blend of two.
    ///
    /// It is a race, so what it proves is one-sided — a pass is evidence and the
    /// hand-assembled blend above is the proof. What makes it evidence rather
    /// than decoration is that the reader is held to discarding *something*: a
    /// reader that never met the publisher would satisfy the property vacuously,
    /// and a reader whose copies were blends would satisfy nothing at all.
    #[test]
    fn a_reader_copying_under_a_publisher_never_takes_a_blend_of_two_images() {
        /// Publications the writer makes. A copy is fourteen kilobytes and so is
        /// a publication, so the two threads contend for the whole of this.
        const PUBLICATIONS: u32 = 2_000;
        /// Reads after the publisher has stopped, over a region nothing is
        /// moving: this is what makes at least one copy certain, whatever the
        /// race did.
        const SETTLED_READS: u32 = 64;

        let handover = ConfigHandover::zero();
        let publishing_done = AtomicBool::new(false);
        // Two publications differing in every entry and in the rule bodies, so a
        // blend of them differs from both in a field a comparison can name.
        let mut first = image(2, 2);
        first.generation = 1;
        first.seal();
        let mut second = image(1, 1);
        second.generation = 2;
        second.rules[0].icmp_type = 8;
        second.rules[MAX_RULES - 1].protocol = 6;
        second.seal();
        handover.publish(&first);

        thread::scope(|scope| {
            scope.spawn(|| {
                for round in 0..PUBLICATIONS {
                    handover.publish(if round.is_multiple_of(2) {
                        &first
                    } else {
                        &second
                    });
                }
                publishing_done.store(true, Ordering::Release);
            });
            let reader = scope.spawn(|| {
                let mut taken = 0u32;
                let mut discarded = 0u32;
                let mut tail = SETTLED_READS;
                let mut into = ConfigImage::ZERO;
                loop {
                    match handover.load_offer(&mut into) {
                        Some(generation) => {
                            taken += 1;
                            assert!(
                                into == first || into == second,
                                "a copy is one publication or the other"
                            );
                            assert_eq!(into.digest, into.computed_digest());
                            assert_eq!(generation, into.generation);
                            into.check(PORTS).expect("a whole publication checks");
                        }
                        None => discarded += 1,
                    }
                    if publishing_done.load(Ordering::Acquire) {
                        tail -= 1;
                        if tail == 0 {
                            break;
                        }
                    }
                }
                (taken, discarded)
            });
            let (taken, discarded) = reader.join().expect("the reader finished");
            assert!(taken > 0, "a settled region is readable");
            assert!(
                discarded > 0,
                "the reader met the publisher at least once, so the race happened"
            );
        });
    }

    #[test]
    fn every_refusal_names_the_field_and_the_value() {
        let rendered: Vec<String> = [
            ConfigImageError::InterfaceCountExceedsCapacity { count: 9 },
            ConfigImageError::NeighbourCountExceedsCapacity { count: 33 },
            ConfigImageError::InterfaceEnabledNotBoolean {
                index: 1,
                enabled: 2,
            },
            ConfigImageError::InterfacePortUnknown { index: 2, port: 7 },
            ConfigImageError::NeighbourPortUnknown { index: 3, port: 8 },
            ConfigImageError::InterfacePrefixLengthTooLong {
                index: 4,
                prefix_length: 200,
            },
            ConfigImageError::InterfaceMacNotUnicast {
                index: 5,
                mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            },
            ConfigImageError::NeighbourMacNotUnicast {
                index: 6,
                mac: [0; 6],
            },
            ConfigImageError::InterfaceIdNotAnIdentifier {
                index: 7,
                fault: TextFault::NotInAlphabet { offset: 3 },
            },
            ConfigImageError::InterfaceAddressNotUnicast {
                index: 8,
                address: [224, 0, 0, 1],
            },
            ConfigImageError::InterfaceAddressNotAHostAddress {
                index: 9,
                address: [10, 0, 0, 255],
            },
            ConfigImageError::InterfaceIdDuplicated {
                index: 10,
                other: 0,
            },
            ConfigImageError::InterfacePortDuplicated {
                index: 11,
                other: 1,
                port: 3,
            },
            ConfigImageError::InterfaceMacDuplicated {
                index: 12,
                other: 2,
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x50],
            },
            ConfigImageError::InterfacePrefixesOverlap {
                index: 13,
                other: 3,
            },
            ConfigImageError::NeighbourAddressNotUnicast {
                index: 14,
                address: [255, 255, 255, 255],
            },
            ConfigImageError::NeighbourAddressNotAHostAddress {
                index: 15,
                address: [10, 0, 0, 255],
            },
            ConfigImageError::NeighbourPortUnconfigured { index: 16, port: 1 },
            ConfigImageError::NeighbourOutsidePrefix {
                index: 17,
                address: [10, 9, 9, 9],
            },
            ConfigImageError::NeighbourIsInterfaceAddress {
                index: 18,
                address: [10, 0, 0, 1],
            },
            ConfigImageError::NeighbourAddressDuplicated {
                index: 19,
                other: 4,
            },
            ConfigImageError::ManagementEnabledNotBoolean { enabled: 9 },
            ConfigImageError::ManagementPrefixLengthTooLong { prefix_length: 99 },
            ConfigImageError::ManagementMacNotUnicast {
                mac: [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
            },
            ConfigImageError::ManagementAddressNotUnicast {
                address: [127, 0, 0, 1],
            },
            ConfigImageError::ManagementAddressNotAHostAddress {
                address: [192, 168, 42, 0],
            },
            ConfigImageError::ManagementPrefixCollidesWithInterface { index: 5 },
            ConfigImageError::ManagementMacCollidesWithInterface { index: 6 },
        ]
        .iter()
        .map(|error| format!("{error}"))
        .collect();

        assert_eq!(
            rendered,
            [
                "interface count 9 exceeds the 8 slots the image holds",
                "neighbour count 33 exceeds the 32 slots the image holds",
                "interface 1 enabled byte 2 is not 0 or 1",
                "interface 2 names port 7, which does not exist",
                "neighbour 3 names port 8, which does not exist",
                "interface 4 prefix length 200 exceeds 32",
                "interface 5 MAC 01:02:03:04:05:06 is not unicast",
                "neighbour 6 MAC 00:00:00:00:00:00 is not unicast",
                "interface 7 id byte 3 is outside [a-z0-9-]",
                "interface 8 address 224.0.0.1 is not unicast",
                "interface 9 address 10.0.0.255 is its prefix's network or broadcast address",
                "interface 10 repeats interface 0's id",
                "interface 11 shares port 3 with interface 1",
                "interface 12 shares MAC 52:54:00:12:34:50 with interface 2",
                "interface 13 covers an address interface 3 also covers",
                "neighbour 14 address 255.255.255.255 is not unicast",
                "neighbour 15 address 10.0.0.255 is its link's network or broadcast address",
                "neighbour 16 names port 1, which no interface addresses",
                "neighbour 17 address 10.9.9.9 is outside its link's prefix",
                "neighbour 18 address 10.0.0.1 is the interface's own",
                "neighbour 19 repeats neighbour 4's address on one port",
                "management enabled byte 9 is not 0 or 1",
                "management prefix length 99 exceeds 32",
                "management MAC ff:ee:dd:cc:bb:aa is not unicast",
                "management address 127.0.0.1 is not unicast",
                "management address 192.168.42.0 is its prefix's network or broadcast address",
                "management shares a prefix with interface 5, which routes it",
                "management shares its MAC with interface 6",
            ]
        );
    }

    /// The id is the one field of an interface whose bytes reach a label value
    /// and a console line, so each of the three ways it can fail is refused by
    /// name — and a *valid* one survives with the text the document wrote.
    #[test]
    fn an_interface_id_is_refused_by_the_fault_it_carries() {
        let with = |id: IdentifierImage| {
            let mut raw = image(1, 0);
            raw.interfaces[0].id = id;
            resealed(&mut raw).check(PORTS).map(|checked| {
                checked
                    .interfaces()
                    .next()
                    .expect("one interface")
                    .id()
                    .as_str()
                    .to_owned()
            })
        };

        assert_eq!(
            with(IdentifierImage::from_text(b"wan-0")).as_deref(),
            Ok("wan-0")
        );

        // A zeroed slot: what a peer that wrote nothing leaves, and what the
        // proptest oracle's own walk over the bytes calls `Empty`.
        assert_eq!(
            with(IdentifierImage::ZERO),
            Err(ConfigImageError::InterfaceIdNotAnIdentifier {
                index: 0,
                fault: TextFault::Empty,
            })
        );
        // A length naming more bytes than the storage holds.
        assert_eq!(
            with(IdentifierImage {
                bytes: [b'a'; LOG_IDENTIFIER_BYTES],
                len: (LOG_IDENTIFIER_BYTES + 1) as u8,
                _pad: [0; 3],
            }),
            Err(ConfigImageError::InterfaceIdNotAnIdentifier {
                index: 0,
                fault: TextFault::TooLong {
                    len: LOG_IDENTIFIER_BYTES + 1
                },
            })
        );
        // And a byte outside the alphabet, at the position it sits at. An upper
        // case letter and a quote are both refused: the second is the one that
        // would end a label value early and let a document's text become a label
        // name of its own on the metric surface.
        for (text, offset) in [(&b"waN"[..], 2), (b"a\"b", 1), (b"a b", 1)] {
            assert_eq!(
                with(IdentifierImage::from_text(text)),
                Err(ConfigImageError::InterfaceIdNotAnIdentifier {
                    index: 0,
                    fault: TextFault::NotInAlphabet { offset },
                })
            );
        }
    }

    /// Exactly the length bound, from both sides.
    #[test]
    fn the_longest_admissible_id_crosses_and_one_byte_more_does_not() {
        let mut raw = image(1, 0);
        raw.interfaces[0].id = IdentifierImage::from_text(&[b'a'; LOG_IDENTIFIER_BYTES]);
        let checked = resealed(&mut raw).check(PORTS).expect("sixteen bytes fit");
        assert_eq!(
            checked.interfaces().next().expect("one").id().len(),
            LOG_IDENTIFIER_BYTES
        );

        raw.interfaces[0].id = IdentifierImage::from_text(&[b'a'; LOG_IDENTIFIER_BYTES + 1]);
        assert!(
            resealed(&mut raw).check(PORTS).is_err(),
            "`from_text` truncates the bytes and keeps the stated length, so the reader refuses it"
        );
    }

    /// Boxed, as every entry strategy below is: a 32-element array of the
    /// unboxed value trees is a stack frame the unoptimized test binary
    /// overflows on.
    fn any_interface_image() -> BoxedStrategy<InterfaceImage> {
        (
            any::<[u8; 4]>(),
            any::<[u8; 6]>(),
            any::<[u8; 2]>(),
            any::<[u8; 4]>(),
            // The id is the peer's too, bytes and stated length alike.
            (
                any::<[u8; LOG_IDENTIFIER_BYTES]>(),
                any::<u8>(),
                any::<[u8; 3]>(),
            ),
        )
            .prop_map(
                |(
                    [port, enabled, prefix_length, pad],
                    mac,
                    pad2,
                    address,
                    (id_bytes, id_len, id_pad),
                )| InterfaceImage {
                    port,
                    enabled,
                    prefix_length,
                    _pad: [pad; 1],
                    mac,
                    _pad2: pad2,
                    address,
                    id: TextImage {
                        bytes: id_bytes,
                        len: id_len,
                        _pad: id_pad,
                    },
                },
            )
            .boxed()
    }

    fn any_management_image() -> BoxedStrategy<ManagementImage> {
        (
            any::<[u8; 4]>(),
            any::<[u8; 6]>(),
            any::<[u8; 2]>(),
            any::<[u8; 4]>(),
            any::<[u8; 4]>(),
        )
            .prop_map(
                |([enabled, prefix_length, gateway_stated, pad0], mac, pad2, address, gateway)| {
                    ManagementImage {
                        enabled,
                        prefix_length,
                        gateway_stated,
                        _pad: [pad0],
                        mac,
                        _pad2: pad2,
                        address,
                        gateway,
                    }
                },
            )
            .boxed()
    }

    /// As [`plausible_interface_image`], for the management entry: weighted so
    /// the enabled path — the one with three rules behind it — is reached as
    /// often as the disabled one.
    fn plausible_management_image() -> BoxedStrategy<ManagementImage> {
        (
            prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
            prop_oneof![9 => 0u8..=MAX_PREFIX_LENGTH, 1 => any::<u8>()],
            plausible_mac(),
            // Usually a host address on a prefix no interface here claims, so
            // the two rules that hold the management port apart from the
            // dataplane admit it as often as they refuse it.
            prop_oneof![7 => Just([192, 168, 42, 15]), 3 => any::<[u8; 4]>()],
        )
            .prop_map(|(enabled, prefix_length, mac, address)| ManagementImage {
                enabled,
                prefix_length,
                mac,
                address,
                ..ManagementImage::ZERO
            })
            .boxed()
    }

    fn any_neighbour_image() -> BoxedStrategy<NeighbourImage> {
        (
            any::<u8>(),
            any::<[u8; 3]>(),
            any::<[u8; 6]>(),
            any::<[u8; 2]>(),
            any::<[u8; 4]>(),
        )
            .prop_map(|(port, pad, mac, pad2, address)| NeighbourImage {
                port,
                _pad: pad,
                mac,
                _pad2: pad2,
                address,
            })
            .boxed()
    }

    /// A MAC that is usually unicast: the group bit cleared and the
    /// locally-administered bit set, which is also what makes it non-zero.
    fn plausible_mac() -> impl Strategy<Value = [u8; 6]> {
        prop_oneof![
            9 => any::<[u8; 6]>().prop_map(|[a, b, c, d, e, f]| [(a & 0xfe) | 0x02, b, c, d, e, f]),
            1 => any::<[u8; 6]>(),
        ]
    }

    /// An entry whose every field is usually the kind of value a well-behaved
    /// writer produces, and occasionally anything at all.
    ///
    /// Uniform bytes are not enough on their own: an arbitrary `enabled` byte
    /// is 0 or 1 twice in 256, so an image of even one interface is refused
    /// almost always and the accepted path — where the rules about what is
    /// *yielded* live — is never reached. The low-weight arms keep the whole
    /// input space in range.
    fn plausible_interface_image() -> BoxedStrategy<InterfaceImage> {
        (
            prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
            prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
            prop_oneof![9 => 0u8..=MAX_PREFIX_LENGTH, 1 => any::<u8>()],
            plausible_mac(),
            any::<[u8; 4]>(),
            plausible_identifier_image(),
        )
            .prop_map(
                |(port, enabled, prefix_length, mac, address, id)| InterfaceImage {
                    port,
                    enabled,
                    prefix_length,
                    mac,
                    address,
                    id,
                    ..InterfaceImage::ZERO
                },
            )
            .boxed()
    }

    /// Mostly one the document could hold, sometimes one no reader will take: each
    /// of the three faults is reachable.
    fn plausible_identifier_image() -> BoxedStrategy<IdentifierImage> {
        prop_oneof![
            8 => prop::collection::vec(
                prop_oneof![Just(b'a'), Just(b'z'), Just(b'0'), Just(b'9'), Just(b'-')],
                1..=LOG_IDENTIFIER_BYTES,
            )
            .prop_map(|bytes| IdentifierImage::from_text(&bytes)),
            1 => Just(IdentifierImage::ZERO),
            1 => (any::<[u8; LOG_IDENTIFIER_BYTES]>(), any::<u8>()).prop_map(
                |(bytes, len)| IdentifierImage {
                    bytes,
                    len,
                    _pad: [0; 3],
                }
            ),
        ]
        .boxed()
    }

    /// The alphabet and length rule, as the oracle's own walk over the bytes.
    fn identifier_fault(raw: &IdentifierImage) -> Option<TextFault> {
        let len = usize::from(raw.len);
        let Some(value) = raw.bytes.get(..len) else {
            return Some(TextFault::TooLong { len });
        };
        if value.is_empty() {
            return Some(TextFault::Empty);
        }
        value
            .iter()
            .position(|byte| !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
            .map(|offset| TextFault::NotInAlphabet { offset })
    }

    /// As [`plausible_interface_image`], for a neighbour.
    fn plausible_neighbour_image() -> BoxedStrategy<NeighbourImage> {
        (
            prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
            plausible_mac(),
            any::<[u8; 4]>(),
        )
            .prop_map(|(port, mac, address)| NeighbourImage {
                port,
                mac,
                address,
                ..NeighbourImage::ZERO
            })
            .boxed()
    }

    /// An image built from whatever entries the given strategies produce. The
    /// counts are left at zero for the caller to set, because what a count says
    /// against what the arrays hold is the property under test.
    fn config_image(
        interfaces: BoxedStrategy<InterfaceImage>,
        neighbours: BoxedStrategy<NeighbourImage>,
        management: BoxedStrategy<ManagementImage>,
    ) -> impl Strategy<Value = ConfigImage> {
        (
            any::<u32>(),
            proptest::array::uniform8(interfaces),
            proptest::array::uniform32(neighbours),
            management,
        )
            .prop_map(
                |(generation, interfaces, neighbours, management)| ConfigImage {
                    generation,
                    interfaces,
                    neighbours,
                    management,
                    ..ConfigImage::ZERO
                },
            )
    }

    /// As [`config_image`], with the entries usually made mutually consistent —
    /// one port, one MAC, one prefix and one id apiece, derived from the slot
    /// index — and sometimes left exactly as drawn.
    ///
    /// The first arm is why the accepted path is reachable at all for an image
    /// of more than one entry: the rules between two entries refuse almost
    /// every independently drawn pair, so without it the assertions about what
    /// an *accepted* multi-entry image yields would never run. The second arm
    /// is why that costs nothing: every image the unspread strategies can
    /// produce is still produced, so no rule becomes unreachable.
    fn consistent_config_image() -> impl Strategy<Value = ConfigImage> {
        (
            config_image(
                plausible_interface_image(),
                plausible_neighbour_image(),
                plausible_management_image(),
            ),
            prop_oneof![6 => Just(true), 4 => Just(false)],
        )
            .prop_map(|(image, spread)| if spread { spread_entries(image) } else { image })
    }

    /// Give every slot its own port, MAC, prefix and id, and put every
    /// neighbour at a host address inside the prefix of the interface its port
    /// names. What the entry strategies drew is kept wherever a rule does not
    /// compare two entries — `enabled`, the prefix length, the padding.
    fn spread_entries(mut image: ConfigImage) -> ConfigImage {
        for (index, slot) in image.interfaces.iter_mut().enumerate() {
            let port = index as u8;
            slot.port = port;
            slot.mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x50 + port];
            slot.address = [10, 0, port, 1];
            slot.id = IdentifierImage::from_text(&[b'd', b'p', b'0' + port]);
        }
        for (index, slot) in image.neighbours.iter_mut().enumerate() {
            let port = (index % MAX_INTERFACES) as u8;
            slot.port = port;
            slot.address = [10, 0, port, 2 + (index / MAX_INTERFACES) as u8];
        }
        image
    }

    /// Counts weighted low, then to the capacity boundary, then anywhere at
    /// all. A count drawn uniformly over `u32` exceeds capacity in every
    /// practical case, so on its own it would prove only that the reader
    /// refuses — the low arm is what makes the accepted path reachable often
    /// enough to assert anything about what is yielded.
    fn any_plausible_count() -> impl Strategy<Value = u32> {
        prop_oneof![
            4 => 0u32..=3,
            2 => 0u32..=40,
            1 => any::<u32>(),
        ]
    }

    /// The rules restated independently of the reader, in the order the reader
    /// applies them, so the property below pins totality and not merely
    /// agreement about which inputs are bad.
    fn expected_refusal(image: &ConfigImage, port_count: u8) -> Option<ConfigImageError> {
        let interface_count = image.interface_count as usize;
        if interface_count > MAX_INTERFACES {
            return Some(ConfigImageError::InterfaceCountExceedsCapacity {
                count: image.interface_count,
            });
        }
        let neighbour_count = image.neighbour_count as usize;
        if neighbour_count > MAX_NEIGHBOURS {
            return Some(ConfigImageError::NeighbourCountExceedsCapacity {
                count: image.neighbour_count,
            });
        }
        let named = |slice: &[InterfaceImage]| -> Vec<InterfaceImage> {
            slice.iter().copied().take(interface_count).collect()
        };
        let interfaces = named(&image.interfaces);

        for (index, raw) in interfaces.iter().enumerate() {
            if raw.enabled > 1 {
                return Some(ConfigImageError::InterfaceEnabledNotBoolean {
                    index,
                    enabled: raw.enabled,
                });
            }
            if raw.port >= port_count {
                return Some(ConfigImageError::InterfacePortUnknown {
                    index,
                    port: raw.port,
                });
            }
            if raw.prefix_length > MAX_PREFIX_LENGTH {
                return Some(ConfigImageError::InterfacePrefixLengthTooLong {
                    index,
                    prefix_length: raw.prefix_length,
                });
            }
            if !is_unicast(raw.mac) {
                return Some(ConfigImageError::InterfaceMacNotUnicast {
                    index,
                    mac: raw.mac,
                });
            }
            if !is_unicast_address(raw.address) {
                return Some(ConfigImageError::InterfaceAddressNotUnicast {
                    index,
                    address: raw.address,
                });
            }
            if !is_host_address(raw.address, raw.prefix_length) {
                return Some(ConfigImageError::InterfaceAddressNotAHostAddress {
                    index,
                    address: raw.address,
                });
            }
            if let Some(fault) = identifier_fault(&raw.id) {
                return Some(ConfigImageError::InterfaceIdNotAnIdentifier { index, fault });
            }
        }

        for (index, raw) in interfaces.iter().enumerate() {
            for (other, earlier) in interfaces.iter().enumerate().take(index) {
                if identifier_text(&earlier.id) == identifier_text(&raw.id) {
                    return Some(ConfigImageError::InterfaceIdDuplicated { index, other });
                }
                if earlier.port == raw.port {
                    return Some(ConfigImageError::InterfacePortDuplicated {
                        index,
                        other,
                        port: raw.port,
                    });
                }
                if earlier.mac == raw.mac {
                    return Some(ConfigImageError::InterfaceMacDuplicated {
                        index,
                        other,
                        mac: raw.mac,
                    });
                }
                if prefixes_overlap(
                    earlier.address,
                    earlier.prefix_length,
                    raw.address,
                    raw.prefix_length,
                ) {
                    return Some(ConfigImageError::InterfacePrefixesOverlap { index, other });
                }
            }
        }

        let neighbours: Vec<NeighbourImage> = image
            .neighbours
            .iter()
            .copied()
            .take(neighbour_count)
            .collect();
        for (index, raw) in neighbours.iter().enumerate() {
            if raw.port >= port_count {
                return Some(ConfigImageError::NeighbourPortUnknown {
                    index,
                    port: raw.port,
                });
            }
            if !is_unicast(raw.mac) {
                return Some(ConfigImageError::NeighbourMacNotUnicast {
                    index,
                    mac: raw.mac,
                });
            }
            if !is_unicast_address(raw.address) {
                return Some(ConfigImageError::NeighbourAddressNotUnicast {
                    index,
                    address: raw.address,
                });
            }
            let Some(interface) = interfaces.iter().find(|entry| entry.port == raw.port) else {
                return Some(ConfigImageError::NeighbourPortUnconfigured {
                    index,
                    port: raw.port,
                });
            };
            if raw.address == interface.address {
                return Some(ConfigImageError::NeighbourIsInterfaceAddress {
                    index,
                    address: raw.address,
                });
            }
            if !inside_prefix(raw.address, interface.address, interface.prefix_length) {
                return Some(ConfigImageError::NeighbourOutsidePrefix {
                    index,
                    address: raw.address,
                });
            }
            if !is_host_address(raw.address, interface.prefix_length) {
                return Some(ConfigImageError::NeighbourAddressNotAHostAddress {
                    index,
                    address: raw.address,
                });
            }
        }
        for (index, raw) in neighbours.iter().enumerate() {
            for (other, earlier) in neighbours.iter().enumerate().take(index) {
                if earlier.port == raw.port && earlier.address == raw.address {
                    return Some(ConfigImageError::NeighbourAddressDuplicated { index, other });
                }
            }
        }

        let management = image.management;
        if management.enabled > 1 {
            return Some(ConfigImageError::ManagementEnabledNotBoolean {
                enabled: management.enabled,
            });
        }
        if management.enabled == 1 {
            if management.prefix_length > MAX_PREFIX_LENGTH {
                return Some(ConfigImageError::ManagementPrefixLengthTooLong {
                    prefix_length: management.prefix_length,
                });
            }
            if !is_unicast(management.mac) {
                return Some(ConfigImageError::ManagementMacNotUnicast {
                    mac: management.mac,
                });
            }
            if !is_unicast_address(management.address) {
                return Some(ConfigImageError::ManagementAddressNotUnicast {
                    address: management.address,
                });
            }
            if !is_host_address(management.address, management.prefix_length) {
                return Some(ConfigImageError::ManagementAddressNotAHostAddress {
                    address: management.address,
                });
            }
            for (index, interface) in interfaces.iter().enumerate() {
                if prefixes_overlap(
                    interface.address,
                    interface.prefix_length,
                    management.address,
                    management.prefix_length,
                ) {
                    return Some(ConfigImageError::ManagementPrefixCollidesWithInterface { index });
                }
                if interface.mac == management.mac {
                    return Some(ConfigImageError::ManagementMacCollidesWithInterface { index });
                }
            }
            if management.gateway_stated > 1 {
                return Some(ConfigImageError::ManagementGatewayStatedNotBoolean {
                    stated: management.gateway_stated,
                });
            }
            if management.gateway_stated == 1 {
                if !is_unicast_address(management.gateway) {
                    return Some(ConfigImageError::ManagementGatewayNotUnicast {
                        gateway: management.gateway,
                    });
                }
                if management.gateway == management.address {
                    return Some(ConfigImageError::ManagementGatewayIsTheAddress {
                        gateway: management.gateway,
                    });
                }
                if !inside_prefix(
                    management.gateway,
                    management.address,
                    management.prefix_length,
                ) {
                    return Some(ConfigImageError::ManagementGatewayOffLink {
                        gateway: management.gateway,
                    });
                }
            }
        }
        None
    }

    /// The bytes an id names, for the oracle's own duplicate comparison. Only
    /// reached once [`identifier_fault`] has admitted both, so the stated length
    /// is inside the storage.
    fn identifier_text(raw: &IdentifierImage) -> &[u8] {
        raw.bytes.get(..usize::from(raw.len)).unwrap_or_default()
    }

    proptest! {
        /// The byzantine-writer property over the region's whole input space:
        /// every field independently arbitrary, every byte of it a value the
        /// writer picked. The reader returns rather than panics, never yields
        /// more entries than the arrays hold nor more than the count named, and
        /// every entry it yields satisfies every rule.
        #[test]
        fn a_wholly_arbitrary_region_is_read_without_panicking_and_stays_bounded(
            mut image in config_image(
                any_interface_image(),
                any_neighbour_image(),
                any_management_image(),
            ),
            interface_count in any_plausible_count(),
            neighbour_count in any_plausible_count(),
            port_count in any::<u8>(),
            // A writer that seals what it wrote and one that does not: the
            // second is the byzantine case the digest exists for, and excluding
            // it would drop the whole adversarial half of this property.
            seal in any::<bool>(),
        ) {
            image.interface_count = interface_count;
            image.neighbour_count = neighbour_count;
            if seal {
                image.seal();
            }

            let Ok(checked) = image.check(port_count) else {
                return Ok(());
            };
            // An unsealed region reaches here only where the arbitrary digest
            // happened to be the right one, which is the whole of what the check
            // claims: nothing is accepted whose bytes it does not cover.
            prop_assert_eq!(image.digest, image.computed_digest());
            prop_assert!(checked.interface_count() <= MAX_INTERFACES);
            prop_assert!(checked.neighbour_count() <= MAX_NEIGHBOURS);
            prop_assert_eq!(checked.interface_count(), interface_count as usize);
            prop_assert_eq!(checked.neighbour_count(), neighbour_count as usize);
            for entry in checked.interfaces() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(entry.prefix_length() <= MAX_PREFIX_LENGTH);
                prop_assert!(is_unicast(entry.mac()));
                // Every byte renderable as a label value and a console field.
                let id = entry.id();
                prop_assert!(!id.is_empty() && id.len() <= LOG_IDENTIFIER_BYTES);
                prop_assert!(
                    id.as_bytes()
                        .iter()
                        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
                );
            }
            for entry in checked.neighbours() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(is_unicast(entry.mac()));
            }
        }

        /// The same region, with each field weighted towards a value a
        /// well-behaved writer would produce so the accepted path is reached as
        /// often as the refused one. Beyond the bounds above it pins totality:
        /// the reader refuses exactly the images a rule refuses, with exactly
        /// the error that rule names, so nothing is accepted by omission and no
        /// refusal is attributed to the wrong field.
        #[test]
        fn an_arbitrary_region_is_read_totally_and_yields_only_valid_entries(
            mut image in consistent_config_image(),
            interface_count in any_plausible_count(),
            neighbour_count in any_plausible_count(),
            port_count in 1u8..=4,
        ) {
            image.interface_count = interface_count;
            image.neighbour_count = neighbour_count;
            // Sealed last, so the property is about the fields it varies rather
            // than about the digest refusing every one of them.
            image.seal();

            let outcome = image.check(port_count);
            prop_assert_eq!(outcome.err(), expected_refusal(&image, port_count));

            let Ok(checked) = image.check(port_count) else {
                return Ok(());
            };
            prop_assert!(checked.interface_count() <= MAX_INTERFACES);
            prop_assert!(checked.neighbour_count() <= MAX_NEIGHBOURS);
            prop_assert_eq!(checked.interface_count(), interface_count as usize);
            prop_assert_eq!(checked.neighbour_count(), neighbour_count as usize);
            prop_assert_eq!(checked.generation(), image.generation);

            for entry in checked.interfaces() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(entry.prefix_length() <= MAX_PREFIX_LENGTH);
                prop_assert!(is_unicast(entry.mac()));
                // Every byte renderable as a label value and a console field.
                let id = entry.id();
                prop_assert!(!id.is_empty() && id.len() <= LOG_IDENTIFIER_BYTES);
                prop_assert!(
                    id.as_bytes()
                        .iter()
                        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
                );
            }
            // Every rule between two interfaces holds of what came out, which
            // is the claim the forwarding domain's own lookups rest on.
            for (index, entry) in checked.interfaces().enumerate() {
                prop_assert!(is_unicast_address(entry.address()));
                prop_assert!(is_host_address(entry.address(), entry.prefix_length()));
                for earlier in checked.interfaces().take(index) {
                    prop_assert_ne!(earlier.port(), entry.port());
                    prop_assert_ne!(earlier.mac(), entry.mac());
                    prop_assert_ne!(earlier.id(), entry.id());
                    prop_assert!(!prefixes_overlap(
                        earlier.address(),
                        earlier.prefix_length(),
                        entry.address(),
                        entry.prefix_length(),
                    ));
                }
            }
            for (index, entry) in checked.neighbours().enumerate() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(is_unicast(entry.mac()));
                prop_assert!(is_unicast_address(entry.address()));
                // On a link this configuration addresses, and a host on it.
                let interface = checked
                    .interfaces()
                    .find(|candidate| candidate.port() == entry.port())
                    .expect("an accepted neighbour sits on a configured port");
                prop_assert_ne!(entry.address(), interface.address());
                prop_assert!(inside_prefix(
                    entry.address(),
                    interface.address(),
                    interface.prefix_length(),
                ));
                prop_assert!(is_host_address(entry.address(), interface.prefix_length()));
                for earlier in checked.neighbours().take(index) {
                    prop_assert!(
                        earlier.port() != entry.port() || earlier.address() != entry.address()
                    );
                }
            }
            match checked.management() {
                Some(management) => {
                    prop_assert_eq!(image.management.enabled, 1);
                    prop_assert!(management.prefix_length() <= MAX_PREFIX_LENGTH);
                    prop_assert!(is_unicast(management.mac()));
                    prop_assert!(is_unicast_address(management.address()));
                    prop_assert!(is_host_address(
                        management.address(),
                        management.prefix_length()
                    ));
                    prop_assert_eq!(management.address(), image.management.address);
                    // Neither reachable by routing nor answering under a
                    // dataplane port's L2 address.
                    for entry in checked.interfaces() {
                        prop_assert!(!prefixes_overlap(
                            entry.address(),
                            entry.prefix_length(),
                            management.address(),
                            management.prefix_length(),
                        ));
                        prop_assert_ne!(entry.mac(), management.mac());
                    }
                }
                None => prop_assert_eq!(image.management.enabled, 0),
            }
        }

        /// A count the writer inflates cannot make the reader read a slot the
        /// arrays do not have: the bound is the capacity, not the count.
        #[test]
        fn a_count_beyond_capacity_is_refused_for_being_one(
            interface_count in (MAX_INTERFACES as u32 + 1)..=u32::MAX,
            neighbour_count in (MAX_NEIGHBOURS as u32 + 1)..=u32::MAX,
        ) {
            let mut inflated = image(MAX_INTERFACES, MAX_NEIGHBOURS);
            inflated.interface_count = interface_count;
            prop_assert_eq!(
                resealed(&mut inflated).check(PORTS),
                Err(ConfigImageError::InterfaceCountExceedsCapacity { count: interface_count })
            );

            let mut inflated = image(MAX_INTERFACES, MAX_NEIGHBOURS);
            inflated.neighbour_count = neighbour_count;
            prop_assert_eq!(
                resealed(&mut inflated).check(PORTS),
                Err(ConfigImageError::NeighbourCountExceedsCapacity { count: neighbour_count })
            );
        }

        /// Every byte of an arbitrary image survives the region unchanged,
        /// padding included: the atomic image moves an image and rules on none
        /// of it, so a writer's bytes are the reader's bytes whatever they say.
        #[test]
        fn an_arbitrary_image_round_trips_through_the_region(
            mut written in config_image(
                any_interface_image(),
                any_neighbour_image(),
                any_management_image(),
            ),
            interface_count in any::<u32>(),
            neighbour_count in any::<u32>(),
        ) {
            written.interface_count = interface_count;
            written.neighbour_count = neighbour_count;

            let slot = ConfigSlot::zero();
            slot.store(&written);
            prop_assert_eq!(slot.load(), written);

            // And again over an already-written region, so no field is left
            // holding what the previous generation put there.
            slot.store(&ConfigImage::ZERO);
            prop_assert_eq!(slot.load(), ConfigImage::ZERO);
            slot.store(&written);
            prop_assert_eq!(slot.load(), written);

            let handover = ConfigHandover::zero();
            handover.publish(&written);
            prop_assert_eq!(loaded(&handover), written);
            prop_assert_eq!(handover.offered_generation(), written.generation);
        }

        /// A generation published on either region is read back as itself, and
        /// the two words on a region do not disturb each other.
        #[test]
        fn published_generations_are_independent(offered in any::<u32>(), committed in any::<u32>()) {
            let handover = ConfigHandover::zero();
            handover.publish(&ConfigImage { generation: offered, ..ConfigImage::ZERO });
            handover.publish_committed(committed);
            prop_assert_eq!(handover.offered_generation(), offered);
            prop_assert_eq!(handover.committed_generation(), committed);

            let ack = ConfigAck::zero();
            ack.publish_staged(offered);
            ack.publish_running(committed);
            prop_assert_eq!(ack.staged_generation(), offered);
            prop_assert_eq!(ack.running_generation(), committed);
        }
    }
}
