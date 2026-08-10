//! The TLS relay channel: a one-item-in-flight window through which the domain
//! that owns the network moves an onboarding connection's **opaque record bytes**
//! to the domain that terminates TLS, and carries that domain's answer back onto
//! the wire.
//!
//! Faces the byzantine neighbour protection domain from both sides, and behind
//! the network end it faces an **unauthenticated administrator-or-attacker**:
//! every byte a request carries was chosen by whoever reached the onboarding
//! port. Nothing here interprets one. This channel does not know what a TLS
//! record is, does not judge a handshake, and never sees a plaintext — the whole
//! of what it does is move a bounded run of bytes in one direction, a bounded run
//! back, and say when the connection is over.
//!
//! # Why the channel exists at all
//!
//! TLS terminates in the domain that holds the keys, and the network stays in the
//! domain that holds the frame pipelines. Those are two domains because a
//! protocol implementation that both parses adversarial records and owns a device
//! is one compromise away from everything; and they are the two they are because
//! neither may hold the other's authority. So the ciphertext crosses instead:
//! **what the network end can read is what it is about to put on the wire**, and
//! what the terminating end holds — the arena, the private key, the session
//! secrets, every decrypted byte — reaches no region either domain shares.
//!
//! # It is asynchronous, and that is a scheduling fact rather than a preference
//!
//! Both domains sit at the same priority and both are event-driven. So neither
//! spins for the other: a side writes its direction, signals, and returns to its
//! event loop, and the answer arrives as a wakeup. A synchronous handshake
//! between two equal-priority domains is precisely what this shape avoids — the
//! asking side would burn its slice waiting for a domain the scheduler has no
//! reason to run — which is why [`RelayRequester::poll`] looks **once** and hands
//! the pending handle back rather than looping.
//!
//! # Two regions, because a region is the unit of grant
//!
//! [`RelayRequest`] is the network end's to write and the terminating end's to
//! read; [`RelayReply`] is the reverse. [`crate::SignRequest`]'s split, and the
//! asymmetry carries the same weight: a domain that could write the reply could
//! put bytes of its own choosing on the wire *as though the terminating end had
//! produced them*, which for a session under the appliance's own identity is a
//! forgery rather than a wrong answer.
//!
//! # What this ABI cannot express
//!
//! Three things, and each is a property of the type rather than a rule a caller
//! keeps.
//!
//! * **A second connection.** There is no connection identifier anywhere in
//!   either direction — not a handle, not an index, not a generation. Every
//!   operation names *the* connection, and [`RelayOperation::Open`] is the only
//!   thing that begins one. Two concurrent connections would need two names and
//!   there is nowhere to put one, so a network end that is wrong, confused or
//!   compromised cannot ask this channel to carry two. The onboarding server
//!   serves an administrator and not a fleet, and that bound is here rather than
//!   in the caller that must not exceed it.
//! * **A disagreement about which session is running.** An
//!   [`RelayOperation::Open`] **is** the beginning of a new session, and it ends
//!   whatever session the terminating end still believed in. There is no refusal
//!   for an open against a session already open, because a channel that cannot
//!   name two connections cannot have two: the near end is the only end that
//!   opens one, so its open is the newer fact and the older belief is stale by
//!   construction. That is what makes the two ends' agreement structural rather
//!   than something a reconciliation exchange has to re-establish — an answer the
//!   near end dropped, and every other way it can stop talking about a session
//!   without saying so, costs the session it was about and nothing after it. What
//!   the terminating end owes on such an open is the account of the session it
//!   gave up, which is [`RelayEnding::Forgotten`]'s case exactly: neither end
//!   said the session was over.
//! * **A request for plaintext.** [`RelayOperation`] has four values and none of
//!   them asks for decrypted bytes. The network end can hand records over, ask
//!   what to send, and say the connection ended; there is no word it can write
//!   that means "give me what the peer said".
//! * **A key.** There is no field a private scalar fits in, in either direction —
//!   [`crate::SignRequest`]'s property, for the same reason and with the same
//!   caveat: an ABI that could carry one would carry it through perfectly correct
//!   grants, so the grants are the other half of the claim and neither half
//!   stands alone.
//!
//! # The sequence number is the whole correlation
//!
//! Nothing else says a reply belongs to a request. The requester increments the
//! number and the responder echoes it, and a reply carrying any other number is
//! **ignored entirely**. Zero is reserved for *no request*, so a zeroed pair of
//! regions is a channel with nothing outstanding.
//!
//! [`PendingRelay`] is what makes that hard to get wrong: it is not `Copy`, only
//! [`RelayRequester::request`] mints one, and [`RelayRequester::poll`] takes it by
//! value — so a reply cannot be looked at without giving up the handle. And the
//! requester refuses to mint a second while one is outstanding
//! ([`RelayBusy`]), so *one item in flight* is enforced here rather than
//! remembered there.
//!
//! # The reply carries the operation it answers
//!
//! A run of records to send and an acknowledgement that a connection closed are
//! different answers, and a channel whose reply said only "here are some bytes"
//! would leave the caller to remember which question was outstanding. So the
//! operation travels back with the answer and a mismatch is a fault: answering
//! the wrong question is the responder's error and not the requester's
//! obligation.
//!
//! # One item in flight, which is what makes a single fence enough
//!
//! The responder publishes the bytes and then the sequence, `Release`; the
//! requester reads the sequence and then the bytes, `Acquire`. That suffices for
//! [`crate::SignRequest`]'s reason exactly: the responder writes only in answer to
//! a demand it took, and cannot take another until the requester issues one.
//!
//! # Every bound is first-party, and passing one refuses rather than panics
//!
//! [`MAX_RELAY_PAYLOAD`] is a constant of this file, sized so one maximal TLS
//! record crosses whole. A payload longer than it is **truncated in the region and
//! reported at its true length**, so the responder sees a length it must refuse
//! rather than a short run it would happily feed to a protocol — the one failure
//! here that would look like success on both sides. A stated length past the
//! region is [`RelayRefusal::PayloadTooLong`] in one direction and
//! [`RelayFault::LenPastPayload`] in the other, and both are values a caller acts
//! on by ending the connection. Nothing here indexes without a bound and nothing
//! here can panic.

use core::{
    mem::size_of,
    sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
};

use crate::{LOG_ONBOARD_END_COUNT, MAPPING_ALIGN};

/// Bytes of opaque record data one item may carry, in either direction.
///
/// 16 648: a TLS record is a five-byte header in front of at most 2^14 bytes of
/// content plus 256 bytes of expansion — 16 645 — so a maximal one crosses in a
/// single item and neither end has to hold a partial record while the other is
/// asked for the rest. Rounded up to eight, which is the wider region's
/// alignment, so neither type carries tail padding a reader has to account for.
///
/// One constant for both directions rather than two, because the two regions then
/// have one shape and a reader has one number to hold.
pub const MAX_RELAY_PAYLOAD: usize = 16_648;

/// Bytes the system description reserves for the request region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const RELAY_REQUEST_REGION_SIZE: usize =
    size_of::<RelayRequest>().next_multiple_of(MAPPING_ALIGN);

/// As [`RELAY_REQUEST_REGION_SIZE`], for the direction carrying the answer.
pub const RELAY_REPLY_REGION_SIZE: usize = size_of::<RelayReply>().next_multiple_of(MAPPING_ALIGN);

/// How a session ended at the network end, travelling with the
/// [`RelayOperation::Close`] that says it is over.
///
/// **The whole reason a close carries one**: the terminating end reports every
/// session it held, and a close that said only *that* the session was over would
/// make a session the transport forgot indistinguishable from one the peer hung
/// up on. Those are two different things to go and look at — one is a reset, an
/// eviction or a reaping, the other is an administrator finishing — so the
/// distinction is carried rather than guessed at by the end that cannot see the
/// wire.
///
/// Four values, mirroring `lfw_log::OnboardEnd`'s parties and in its order, so
/// the two domains' accounts of one session are read in one vocabulary. The
/// mirror is checked rather than asserted in prose: the count below is held to
/// [`LOG_ONBOARD_END_COUNT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayEnding {
    /// The peer on the network closed its half.
    Peer,
    /// The terminating end said the session was over. It is in the vocabulary
    /// because the vocabulary is *how a session ended* and this is one of the
    /// ways; a network end whose far end has already closed a session owes it no
    /// close, so a well-behaved one has no occasion to write this word.
    Consumer,
    /// The connection stopped existing while neither end had said anything: a
    /// reset, an eviction under table pressure, a reaping. Also what an
    /// [`RelayOperation::Open`] implies about the session it supersedes.
    Forgotten,
    /// The network end ended the session itself, because the channel carrying it
    /// answered something that could not be believed or acted on.
    Refused,
}

impl RelayEnding {
    /// Endings this vocabulary has.
    pub const COUNT: usize = 4;

    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Peer => 0,
            Self::Consumer => 1,
            Self::Forgotten => 2,
            Self::Refused => 3,
        }
    }

    /// `None` for every other bit pattern, on [`RelayOperation::from_bits`]'s
    /// terms — and reached through it, an ending being readable only out of a
    /// close.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Peer),
            1 => Some(Self::Consumer),
            2 => Some(Self::Forgotten),
            3 => Some(Self::Refused),
            _ => None,
        }
    }
}

/// Which connection a session runs on: an administrator dialling *in* to an
/// appliance nobody owns, or an owned appliance dialling *out* to the plane that
/// owns it. **Told rather than worked out**: the two are opposite ends of a TLS
/// handshake, only the domain that owns the network knows which transport took the
/// connection, and a terminating end deciding for itself could disagree — answering
/// an inbound connection with a client half.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Half {
    /// The connection an administrator opened to an appliance nobody owns.
    Onboarding,
    /// The connection this appliance dialled to its management plane.
    Channel,
}

/// What a request asks the terminating end to do with *the* connection.
///
/// Four operations, and the set is closed deliberately: it is the whole vocabulary
/// a network end has, and no member of it asks for a plaintext byte. Two carry a
/// value and are the only two that could: an ending exists where a session ends, a
/// half where one begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayOperation {
    /// A connection was accepted on the named half; begin a session over it. The
    /// only thing that starts one, and the reason this ABI needs no identifier:
    /// there is one session, this is where it comes from, and the half named here is
    /// that session's for life. It also **ends** any session the terminating end
    /// holds — see this module's header on why that keeps the two ends from
    /// disagreeing about which is running.
    Open(Half),
    /// Here are the bytes the peer sent. The payload is whatever arrived and is
    /// not required to be a whole record — the terminating end reassembles,
    /// because it is the end that knows what a record is.
    Deliver,
    /// Nothing arrived; hand over whatever there is to send. This is what carries
    /// a handshake forward across wakeups without the network end having to
    /// invent a reason to ask.
    Poll,
    /// The connection ended at the network end, the way the [`RelayEnding`] says.
    /// The session is over whatever the reply says.
    Close(RelayEnding),
}

impl RelayOperation {
    /// The words before a close's own encoding: an open per half, a deliver, a poll.
    const CLOSE_BASE: u32 = 4;

    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Open(Half::Onboarding) => 0,
            Self::Open(Half::Channel) => 1,
            Self::Deliver => 2,
            Self::Poll => 3,
            Self::Close(ending) => Self::CLOSE_BASE + ending.to_bits(),
        }
    }

    /// `None` for every other bit pattern, on [`crate::SignOperation::from_bits`]'s
    /// terms: the field is peer-written, so an undecodable value is input to
    /// reject rather than one to coerce. The responder answers such a request
    /// with [`RelayRefusal::NoSuchOperation`] rather than ignoring it, because a
    /// requester left waiting cannot tell a refusal from a hang. A close whose
    /// ending cannot be read is such a word: it is not a close this end has, and
    /// coercing one would invent the fact the ending carries — as would defaulting
    /// an open's half.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Open(Half::Onboarding)),
            1 => Some(Self::Open(Half::Channel)),
            2 => Some(Self::Deliver),
            3 => Some(Self::Poll),
            _ => match RelayEnding::from_bits(bits.wrapping_sub(Self::CLOSE_BASE)) {
                Some(ending) => Some(Self::Close(ending)),
                None => None,
            },
        }
    }
}

/// The status word of a reply, as it appears in the region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayStatus {
    /// The reply holds what was asked for.
    Ok,
    /// An operation naming a session, with none open. Distinct from every other
    /// refusal because it is the one an operator reads as a protocol mistake at
    /// the *network* end rather than as anything the peer did.
    ///
    /// It is **not** reachable through [`RelayOperation::Open`], which opens a
    /// session rather than naming one — there is deliberately no status for an
    /// open against a session already running, for the reason this module's
    /// header gives.
    NoConnection,
    /// The request's payload length is past what a request may carry, so there is
    /// nothing well-defined to hand to the protocol.
    PayloadTooLong,
    /// The request named an operation this responder has none of.
    NoSuchOperation,
    /// The terminating end gave up on the session. What went wrong is that end's
    /// to report; what the network end does with it is close.
    SessionFailed,
}

impl RelayStatus {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::NoConnection => 1,
            Self::PayloadTooLong => 2,
            Self::NoSuchOperation => 3,
            Self::SessionFailed => 4,
        }
    }

    /// `None` for every other bit pattern. There is deliberately no value that
    /// means "assume it worked".
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Ok),
            1 => Some(Self::NoConnection),
            2 => Some(Self::PayloadTooLong),
            3 => Some(Self::NoSuchOperation),
            4 => Some(Self::SessionFailed),
            _ => None,
        }
    }
}

/// [`RelayStatus`] without its success, which is what a refusal can be.
///
/// Every variant ends the connection at the network end. That is not a
/// convention this type can enforce, but it is why there is no "try again"
/// among them: a channel with one session and one item in flight has no state a
/// retry could be distinguished from a repeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRefusal {
    NoConnection,
    PayloadTooLong,
    NoSuchOperation,
    SessionFailed,
}

impl RelayRefusal {
    #[must_use]
    pub const fn to_status(self) -> RelayStatus {
        match self {
            Self::NoConnection => RelayStatus::NoConnection,
            Self::PayloadTooLong => RelayStatus::PayloadTooLong,
            Self::NoSuchOperation => RelayStatus::NoSuchOperation,
            Self::SessionFailed => RelayStatus::SessionFailed,
        }
    }

    /// `None` for [`RelayStatus::Ok`], which is the point of the type.
    #[must_use]
    pub const fn from_status(status: RelayStatus) -> Option<Self> {
        match status {
            RelayStatus::Ok => None,
            RelayStatus::NoConnection => Some(Self::NoConnection),
            RelayStatus::PayloadTooLong => Some(Self::PayloadTooLong),
            RelayStatus::NoSuchOperation => Some(Self::NoSuchOperation),
            RelayStatus::SessionFailed => Some(Self::SessionFailed),
        }
    }
}

/// The request region: what is being asked and the bytes it carries. The network
/// end maps this read-write and the terminating end read-only.
///
/// Every field is private and no accessor reaches one, so the ordering each word
/// carries is a property of this type rather than a convention its two domains
/// are asked to keep.
#[repr(C)]
pub struct RelayRequest {
    sequence: AtomicU32,
    operation: AtomicU32,
    len: AtomicU32,
    /// Alignment only. Nothing is placed here and nothing reads it.
    _pad: AtomicU32,
    /// One atomic per byte rather than packed into words, on
    /// [`crate::SignRequest`]'s terms: these are record bytes, so packing them
    /// would make the byte order of the region a thing this crate chooses.
    payload: [AtomicU8; MAX_RELAY_PAYLOAD],
}

impl RelayRequest {
    /// A zeroed region, which is what the kernel hands a domain that maps one:
    /// sequence zero is *no request*, so nothing is outstanding and no session is
    /// open.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            operation: AtomicU32::new(0),
            len: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
            payload: [const { AtomicU8::new(0) }; MAX_RELAY_PAYLOAD],
        }
    }

    /// Take the network end's handle: this region to write, the terminating end's
    /// reply to read.
    ///
    /// Take it **once** per channel and keep it, on [`crate::LogRecords::writer`]'s
    /// terms: a second restarts at sequence zero and would reuse numbers the first
    /// has outstanding.
    #[must_use]
    pub const fn requester<'chan>(&'chan self, reply: &'chan RelayReply) -> RelayRequester<'chan> {
        RelayRequester {
            request: self,
            reply: PeerReply::new(reply),
            sequence: 0,
            outstanding: false,
            faults: 0,
        }
    }
}

impl Default for RelayRequest {
    fn default() -> Self {
        Self::zero()
    }
}

/// The reply region: the answer, what to make of it, and whether the session is
/// over. The terminating end maps this read-write and the network end read-only.
#[repr(C)]
pub struct RelayReply {
    sequence: AtomicU32,
    status: AtomicU32,
    operation: AtomicU32,
    len: AtomicU32,
    /// Items this responder has answered since it started, so an operator can see
    /// the relay working without a record byte reaching a surface.
    answered: AtomicU64,
    /// One where the terminating end considers the session over, zero where it
    /// does not, and a fault for anything else — see [`RelayFault::ClosedUnknown`].
    /// A word rather than a status, because a successful answer can carry the
    /// last bytes of a session *and* say it has ended, and a status able to mean
    /// both would be a status a caller had to decode twice.
    closed: AtomicU32,
    /// One where the protocol behind this end has **agreed a greeting** with the
    /// peer at some point in this session, zero where it has not, and a fault for
    /// anything else — see [`RelayFault::AgreedUnknown`].
    ///
    /// Its own word beside [`Self::closed`] rather than a status, for that
    /// word's reason and one more of its own. A session can carry its last bytes
    /// *and* be over, and it can agree a greeting on an item that carries bytes
    /// too — so neither fact fits in a status. And the two say opposite things:
    /// one ends a session, and this one is the only evidence the network end has
    /// that a session became worth anything. It is what the redial schedule is
    /// reset on, and nothing else may reset it: a peer that accepts a connection
    /// and closes it must not be able to shorten the wait, so a word carried by
    /// the transport rather than by the protocol above it would be exactly the
    /// wrong signal.
    ///
    /// **Latching, and stated on every answer after the first that sets it.** The
    /// network end reads it as a level rather than an edge, so an answer whose
    /// wakeup was coalesced with another cannot lose the fact.
    agreed: AtomicU32,
    payload: [AtomicU8; MAX_RELAY_PAYLOAD],
}

impl RelayReply {
    /// As [`RelayRequest::zero`]. Sequence zero answers no request, so a zeroed
    /// reply is never mistaken for one.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            status: AtomicU32::new(0),
            operation: AtomicU32::new(0),
            len: AtomicU32::new(0),
            answered: AtomicU64::new(0),
            closed: AtomicU32::new(0),
            agreed: AtomicU32::new(0),
            payload: [const { AtomicU8::new(0) }; MAX_RELAY_PAYLOAD],
        }
    }

    /// Take the terminating end's handle, on [`RelayRequest::requester`]'s terms.
    #[must_use]
    pub const fn responder<'chan>(
        &'chan self,
        request: &'chan RelayRequest,
    ) -> RelayResponder<'chan> {
        RelayResponder {
            reply: self,
            request: PeerRequest::new(request),
            served: 0,
            answered: 0,
        }
    }
}

impl Default for RelayReply {
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

    use super::{RelayReply, RelayRequest};

    /// The reply region as the network end holds it: loads only.
    pub(super) struct PeerReply<'chan>(&'chan RelayReply);

    impl<'chan> PeerReply<'chan> {
        pub(super) const fn new(reply: &'chan RelayReply) -> Self {
            Self(reply)
        }

        /// Acquire, and read *first*: everything the responder stored before it
        /// released this word must be visible before this side reads any of it.
        pub(super) fn sequence(&self) -> u32 {
            self.0.sequence.load(Ordering::Acquire)
        }

        pub(super) fn status(&self) -> u32 {
            self.0.status.load(Ordering::Relaxed)
        }

        pub(super) fn operation(&self) -> u32 {
            self.0.operation.load(Ordering::Relaxed)
        }

        pub(super) fn len(&self) -> u32 {
            self.0.len.load(Ordering::Relaxed)
        }

        pub(super) fn closed(&self) -> u32 {
            self.0.closed.load(Ordering::Relaxed)
        }

        pub(super) fn agreed(&self) -> u32 {
            self.0.agreed.load(Ordering::Relaxed)
        }

        pub(super) fn answered(&self) -> u64 {
            self.0.answered.load(Ordering::Relaxed)
        }

        /// Bounded by `into`, which the caller obtained from the reply's own
        /// length: `zip` walks the shorter of the two, so no index is taken.
        pub(super) fn copy_payload(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.payload) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }
    }

    /// The request region as the terminating end holds it, on [`PeerReply`]'s
    /// terms.
    pub(super) struct PeerRequest<'chan>(&'chan RelayRequest);

    impl<'chan> PeerRequest<'chan> {
        pub(super) const fn new(request: &'chan RelayRequest) -> Self {
            Self(request)
        }

        /// Acquire, and read first, for [`PeerReply::sequence`]'s reason with the
        /// directions exchanged.
        pub(super) fn sequence(&self) -> u32 {
            self.0.sequence.load(Ordering::Acquire)
        }

        pub(super) fn operation(&self) -> u32 {
            self.0.operation.load(Ordering::Relaxed)
        }

        pub(super) fn len(&self) -> u32 {
            self.0.len.load(Ordering::Relaxed)
        }

        pub(super) fn copy_payload(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.payload) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }
    }
}

use peer::{PeerReply, PeerRequest};

/// An item the requester has issued and not yet had answered.
///
/// Neither `Copy` nor `Clone`, and produced only by [`RelayRequester::request`]:
/// the sequence number a reply must match cannot be conjured, duplicated, or kept
/// across an answer.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an item nothing polls is a connection that never advances"]
pub struct PendingRelay {
    sequence: u32,
    /// What was asked, so a reply answering something else can be refused.
    operation: RelayOperation,
}

impl PendingRelay {
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn operation(&self) -> RelayOperation {
        self.operation
    }
}

/// A second item refused while the first is unanswered, naming the sequence still
/// outstanding.
///
/// The whole of "one item in flight": a caller cannot overwrite a request the
/// responder has not read, because the type will not let it. Without this the
/// window would be a rule kept by the one domain that must not be trusted to keep
/// it — the network end being the side an unauthenticated peer drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayBusy {
    pub sequence: u32,
    pub operation: RelayOperation,
}

/// A reply the responder's bytes cannot be. Each one consumes the
/// [`PendingRelay`] it was raised against: a peer that answered with nonsense
/// will not answer better on a second look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayFault {
    /// A status word outside [`RelayStatus`].
    StatusUnknown { status: u32 },
    /// An operation word outside [`RelayOperation`].
    OperationUnknown { operation: u32 },
    /// The reply answers a different question from the one that was asked.
    WrongOperation {
        asked: RelayOperation,
        answered: RelayOperation,
    },
    /// More payload bytes claimed than the region holds. The one fault that would
    /// be a read past the region if it were believed.
    LenPastPayload { len: u32 },
    /// A refusal carrying bytes, which no refusal means.
    BytesOnRefusal { status: RelayStatus, len: u32 },
    /// The closed word is neither zero nor one, so whether the session is over
    /// cannot be read out of it — and guessing either way is a connection left
    /// open or a connection cut.
    ClosedUnknown { closed: u32 },
    /// The agreed word is neither zero nor one. Its own fault rather than
    /// [`Self::ClosedUnknown`]'s, because guessing costs something different:
    /// read as agreed it would reset a redial schedule a peer never earned, and
    /// read as not it would leave an appliance whose channel is up backing off as
    /// though it were down.
    AgreedUnknown { agreed: u32 },
}

/// What [`RelayRequester::poll`] found.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the pending item is returned inside this and is lost if dropped"]
pub enum RelayPoll<'buf> {
    /// No reply to *this* item yet. The handle comes back so the caller can poll
    /// again on a later wakeup; this is one attempt, and a caller that spins on it
    /// has written the loop this channel is asynchronous to avoid.
    Outstanding(PendingRelay),
    /// The terminating end answered. `records` is what goes on the wire — empty
    /// where there was nothing to send, which is the ordinary answer to a
    /// [`RelayOperation::Poll`] that found the protocol waiting.
    Answered {
        records: &'buf [u8],
        /// The terminating end considers the session over. The network end
        /// finishes sending `records` and then closes.
        closed: bool,
        /// The protocol behind the terminating end has agreed a greeting with
        /// the peer. Latched, so this stays true for the rest of the session.
        agreed: bool,
        /// Items this responder has answered, so a caller can report the relay
        /// working without a record byte reaching a surface.
        answered: u64,
    },
    /// The terminating end answered and produced nothing, saying why. Every
    /// refusal ends the connection.
    Refused(RelayRefusal),
    /// The reply carried this item's sequence and could not be believed.
    Faulted(RelayFault),
}

/// The network end, holding its own sequence, window and fault tally in private
/// memory.
pub struct RelayRequester<'chan> {
    request: &'chan RelayRequest,
    reply: PeerReply<'chan>,
    /// Private, and never read back from the region: a number this side read out
    /// of shared memory could be walked backwards by the peer, which would let an
    /// old reply match a new item.
    sequence: u32,
    /// Whether the one slot this channel has is taken. Held here rather than
    /// inferred from the regions for the same reason.
    outstanding: bool,
    faults: u32,
}

impl RelayRequester<'_> {
    /// Ask for `operation` over `payload`, and take the handle the answer must be
    /// claimed with.
    ///
    /// A payload longer than [`MAX_RELAY_PAYLOAD`] is **truncated in the region
    /// and reported as its true length**, so the responder sees a length it must
    /// refuse rather than a short run it would happily feed to a protocol.
    /// Handing a silently shortened record to a TLS implementation is the one
    /// failure here that would look like success on both sides.
    ///
    /// # Errors
    /// [`RelayBusy`] where an item is already outstanding. The caller polls that
    /// one first: this channel has a window of one, and a second write would
    /// overwrite bytes the responder may be mid-read of.
    pub fn request(
        &mut self,
        operation: RelayOperation,
        payload: &[u8],
    ) -> Result<PendingRelay, RelayBusy> {
        if self.outstanding {
            return Err(RelayBusy {
                sequence: self.sequence,
                operation,
            });
        }
        for (cell, byte) in self.request.payload.iter().zip(payload) {
            cell.store(*byte, Ordering::Relaxed);
        }
        // Zero is *no request*, so it is stepped over rather than used.
        self.sequence = match self.sequence.wrapping_add(1) {
            0 => 1,
            next => next,
        };
        self.request
            .operation
            .store(operation.to_bits(), Ordering::Relaxed);
        self.request
            .len
            .store(clamp_u32(payload.len()), Ordering::Relaxed);
        // Release, and last: the words above must be visible to the terminating
        // end before the sequence that makes them a request is.
        self.request
            .sequence
            .store(self.sequence, Ordering::Release);
        self.outstanding = true;
        Ok(PendingRelay {
            sequence: self.sequence,
            operation,
        })
    }

    /// Look **once** for the answer to `pending`, copying any records into `into`.
    ///
    /// The sequence is read before anything else and with `Acquire`, which is what
    /// makes the responder's bytes visible before they are copied; a mismatch
    /// returns the handle and reads nothing at all.
    pub fn poll<'buf>(
        &mut self,
        pending: PendingRelay,
        into: &'buf mut [u8; MAX_RELAY_PAYLOAD],
    ) -> RelayPoll<'buf> {
        if self.reply.sequence() != pending.sequence {
            return RelayPoll::Outstanding(pending);
        }
        let raw_status = self.reply.status();
        let raw_operation = self.reply.operation();
        let raw_closed = self.reply.closed();
        let raw_agreed = self.reply.agreed();
        let len = self.reply.len();
        // The window is free from here on: every path below is an answer to this
        // item, and a caller holding a fault or a refusal is a caller that must be
        // able to say the next thing — which for every one of them is `Close`.
        self.outstanding = false;

        let Some(status) = RelayStatus::from_bits(raw_status) else {
            return self.fault(RelayFault::StatusUnknown { status: raw_status });
        };
        // The refusal is read BEFORE the operation echo, and that order is
        // load-bearing rather than tidy. A refusal's correlation is its sequence;
        // its echoed operation is decoration. And one refusal exists precisely
        // because the operation word could not be decoded — reading the echo
        // first would report `NoSuchOperation` as a mismatched echo and send an
        // operator after the wrong fault. Nothing is copied on this path, and a
        // refusal that carried bytes is caught here rather than believed.
        if let Some(reason) = RelayRefusal::from_status(status) {
            if len != 0 {
                return self.fault(RelayFault::BytesOnRefusal { status, len });
            }
            return RelayPoll::Refused(reason);
        }
        let Some(answered) = RelayOperation::from_bits(raw_operation) else {
            return self.fault(RelayFault::OperationUnknown {
                operation: raw_operation,
            });
        };
        if answered != pending.operation {
            return self.fault(RelayFault::WrongOperation {
                asked: pending.operation,
                answered,
            });
        }
        // The region bound and the copy's destination are one operation, so the
        // check cannot drift from the slice it protects.
        let Some(target) = into.get_mut(..len as usize) else {
            return self.fault(RelayFault::LenPastPayload { len });
        };
        let closed = match raw_closed {
            0 => false,
            1 => true,
            other => return self.fault(RelayFault::ClosedUnknown { closed: other }),
        };
        let agreed = match raw_agreed {
            0 => false,
            1 => true,
            other => return self.fault(RelayFault::AgreedUnknown { agreed: other }),
        };
        self.reply.copy_payload(target);
        RelayPoll::Answered {
            records: target,
            closed,
            agreed,
            answered: self.reply.answered(),
        }
    }

    /// Give up on `pending` without an answer, freeing the window.
    ///
    /// The **only** way an item ends unanswered, and it exists because the
    /// alternative is a dead channel: a caller that dropped the handle instead
    /// would leave this channel's one slot taken for the life of the domain, and
    /// every later session refused for a window nothing will ever free. That is
    /// why [`PendingRelay`] is `#[must_use]` and why this takes it by value —
    /// an item given up on must not be pollable afterwards.
    ///
    /// What it does **not** do is move the sequence. A reply that lands later
    /// carries a number no future item will be issued under, so
    /// [`Self::poll`] reads it as no answer at all rather than as the next
    /// item's — which is what makes abandoning safe rather than a way to have an
    /// old answer believed.
    pub fn abandon(&mut self, pending: PendingRelay) {
        // Consumed rather than read: the handle's value is that it cannot be
        // used again, and there is nothing in it this side has to look at.
        let PendingRelay { .. } = pending;
        self.outstanding = false;
    }

    /// Whether the one slot this channel has is taken.
    #[must_use]
    pub const fn outstanding(&self) -> bool {
        self.outstanding
    }

    /// Replies this requester refused, saturating at [`u32::MAX`] rather than
    /// wrapping: a wrap would turn a sustained flood back into a small number.
    #[must_use]
    pub const fn faults(&self) -> u32 {
        self.faults
    }

    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    fn fault<'buf>(&mut self, fault: RelayFault) -> RelayPoll<'buf> {
        self.faults = self.faults.saturating_add(1);
        RelayPoll::Faulted(fault)
    }
}

/// An item the terminating end has taken and not yet answered.
///
/// Consumed by every answering method, so one demand produces exactly one reply.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a demand nothing answers leaves the network end waiting"]
pub struct RelayDemand {
    sequence: u32,
    operation: Option<RelayOperation>,
    len: u32,
}

impl RelayDemand {
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Which operation was asked for, or `None` where the word named none this
    /// responder has — which is answered with [`RelayRefusal::NoSuchOperation`]
    /// rather than ignored.
    #[must_use]
    pub const fn operation(&self) -> Option<RelayOperation> {
        self.operation
    }

    /// The payload length the requester stated, **unclamped**: a length past
    /// [`MAX_RELAY_PAYLOAD`] is a request to refuse and not one to shorten, so it
    /// arrives as what was claimed.
    #[must_use]
    pub const fn stated_len(&self) -> u32 {
        self.len
    }

    /// The payload, copied into `into`, or `None` where the stated length is past
    /// what a request can hold — which is the [`RelayRefusal::PayloadTooLong`]
    /// case and the whole reason this returns an `Option` rather than a slice.
    ///
    /// Copied out of the shared region before anything is made of it, so a peer
    /// cannot rewrite the bytes between the length check and the protocol.
    pub fn payload<'buf>(
        &self,
        responder: &RelayResponder<'_>,
        into: &'buf mut [u8; MAX_RELAY_PAYLOAD],
    ) -> Option<&'buf [u8]> {
        let target = into.get_mut(..self.len as usize)?;
        responder.request.copy_payload(target);
        Some(target)
    }
}

/// The terminating end, holding the last sequence it served in private memory.
pub struct RelayResponder<'chan> {
    reply: &'chan RelayReply,
    request: PeerRequest<'chan>,
    /// Private, on [`RelayRequester::sequence`]'s terms: a peer that could rewind
    /// this would have the terminating end process one run of bytes twice.
    served: u32,
    answered: u64,
}

impl RelayResponder<'_> {
    /// Take the outstanding item, if there is one this responder has not already
    /// answered.
    ///
    /// `None` covers both "nothing was ever asked" — sequence zero, which is what
    /// a zeroed region holds — and "the number has not moved since the last
    /// demand". A peer that rewrites the sequence to an arbitrary value produces
    /// **at most one demand per change**, so a request storm costs one reply each
    /// and never an unbounded loop.
    ///
    /// The number is recorded here rather than when the answer is published,
    /// which is what makes that a property of this type rather than of a caller
    /// that remembers to answer before taking again. What it obliges instead is
    /// that a demand taken is a demand answered: every answering method consumes
    /// one, and a `RelayDemand` dropped unanswered leaves the network end polling
    /// a sequence nothing will publish. `#[must_use]` on the demand is what makes
    /// dropping one visible.
    pub fn take(&mut self) -> Option<RelayDemand> {
        let sequence = self.request.sequence();
        if sequence == 0 || sequence == self.served {
            return None;
        }
        self.served = sequence;
        Some(RelayDemand {
            sequence,
            operation: RelayOperation::from_bits(self.request.operation()),
            len: self.request.len(),
        })
    }

    /// Answer `demand` with `records` to put on the wire, saying whether the
    /// session is over.
    ///
    /// `records` is truncated to what the region holds, and the published length
    /// is what was actually stored — so a responder handing over more than fits
    /// publishes only what it wrote. Answers how many bytes that was.
    pub fn answered(
        &mut self,
        demand: RelayDemand,
        records: &[u8],
        closed: bool,
        agreed: bool,
    ) -> usize {
        let mut published = 0_u32;
        for (cell, byte) in self.reply.payload.iter().zip(records) {
            cell.store(*byte, Ordering::Relaxed);
            published += 1;
        }
        let operation = demand.operation.unwrap_or(RelayOperation::Poll);
        self.answered = self.answered.saturating_add(1);
        self.reply.answered.store(self.answered, Ordering::Relaxed);
        self.publish(
            demand,
            operation,
            RelayStatus::Ok,
            published,
            closed,
            agreed,
        );
        published as usize
    }

    /// Answer `demand` with nothing, saying why. Publishes a zero length, which is
    /// what makes [`RelayFault::BytesOnRefusal`] a fault the network end can raise
    /// against a responder that does otherwise, and a closed word of one, because
    /// every refusal ends the session.
    pub fn refuse(&mut self, demand: RelayDemand, reason: RelayRefusal) {
        // The operation echoed on a refusal is the one that was asked for, where
        // the word named one; where it named none the encoding falls back to the
        // zero word, there being no operation to echo. The requester does not
        // judge either — see [`RelayRequester::poll`] on why a refusal's echo is
        // decoration, which is also why the half in that fallback says nothing.
        let operation = demand
            .operation
            .unwrap_or(RelayOperation::Open(Half::Onboarding));
        self.answered = self.answered.saturating_add(1);
        self.reply.answered.store(self.answered, Ordering::Relaxed);
        // Nothing is agreed on a refusal: a refusal is this end saying it never
        // had a session to speak a protocol over.
        self.publish(demand, operation, reason.to_status(), 0, true, false);
    }

    /// Items this responder has answered, refusals included.
    #[must_use]
    pub const fn answers(&self) -> u64 {
        self.answered
    }

    #[must_use]
    pub const fn served(&self) -> u32 {
        self.served
    }

    fn publish(
        &mut self,
        demand: RelayDemand,
        operation: RelayOperation,
        status: RelayStatus,
        len: u32,
        closed: bool,
        agreed: bool,
    ) {
        self.reply.status.store(status.to_bits(), Ordering::Relaxed);
        self.reply
            .operation
            .store(operation.to_bits(), Ordering::Relaxed);
        self.reply.len.store(len, Ordering::Relaxed);
        self.reply
            .closed
            .store(u32::from(closed), Ordering::Relaxed);
        self.reply
            .agreed
            .store(u32::from(agreed), Ordering::Relaxed);
        // Release, and last: the bytes and the five words above must be visible to
        // the network end before the sequence that claims them as this item's
        // answer is.
        self.reply
            .sequence
            .store(demand.sequence, Ordering::Release);
    }
}

/// A length as a `u32`, saturating rather than truncating: a truncated length
/// would understate a payload and let a responder consume a prefix of it as
/// though it were the whole.
const fn clamp_u32(len: usize) -> u32 {
    if len > u32::MAX as usize {
        u32::MAX
    } else {
        len as u32
    }
}

// Two cross-PD shared-memory ABIs: pin both layouts so a field reorder or a size
// change is a compile error rather than a silently corrupted mapping.
const _: () = {
    use core::mem::{align_of, offset_of};

    assert!(size_of::<usize>() >= size_of::<u32>());
    assert!(MAX_RELAY_PAYLOAD > 0 && MAX_RELAY_PAYLOAD <= u32::MAX as usize);
    // A maximal TLS record crosses whole: a five-byte header, 2^14 of content
    // and 256 of expansion.
    assert!(MAX_RELAY_PAYLOAD >= 5 + (1 << 14) + 256);
    // A zeroed pair of regions is the valid idle state: sequence zero is no
    // request and answers none, so neither side acts on what the kernel handed
    // it, and the closed word reads as a session that is not over.
    assert!(RelayStatus::Ok.to_bits() == 0);
    assert!(RelayOperation::Open(Half::Onboarding).to_bits() == 0);
    assert!(RelayRefusal::from_status(RelayStatus::Ok).is_none());
    assert!(RelayStatus::from_bits(5).is_none());
    // A close's four endings occupy the words after the four before them, so the
    // vocabulary ends exactly there.
    assert!(RelayEnding::COUNT == LOG_ONBOARD_END_COUNT as usize);
    assert!(RelayOperation::CLOSE_BASE as usize + RelayEnding::COUNT == 8);
    assert!(RelayOperation::from_bits(7).is_some());
    assert!(RelayOperation::from_bits(8).is_none());
    assert!(RelayEnding::from_bits(RelayEnding::COUNT as u32).is_none());

    assert!(offset_of!(RelayRequest, sequence) == 0);
    assert!(offset_of!(RelayRequest, operation) == 4);
    assert!(offset_of!(RelayRequest, len) == 8);
    assert!(offset_of!(RelayRequest, _pad) == 12);
    assert!(offset_of!(RelayRequest, payload) == 16);
    assert!(align_of::<RelayRequest>() == 4);
    assert!(size_of::<RelayRequest>() == 16 + MAX_RELAY_PAYLOAD);

    assert!(offset_of!(RelayReply, sequence) == 0);
    assert!(offset_of!(RelayReply, status) == 4);
    assert!(offset_of!(RelayReply, operation) == 8);
    assert!(offset_of!(RelayReply, len) == 12);
    assert!(offset_of!(RelayReply, answered) == 16);
    assert!(offset_of!(RelayReply, closed) == 24);
    assert!(offset_of!(RelayReply, agreed) == 28);
    assert!(offset_of!(RelayReply, payload) == 32);
    assert!(align_of::<RelayReply>() == 8);
    // Naturally aligned, which is what makes the tally a single access rather
    // than two a reader could tear across.
    assert!(offset_of!(RelayReply, answered).is_multiple_of(align_of::<u64>()));

    // Each region must hold its type and be mappable.
    assert!(RELAY_REQUEST_REGION_SIZE >= size_of::<RelayRequest>());
    assert!(RELAY_REQUEST_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(RELAY_REPLY_REGION_SIZE >= size_of::<RelayReply>());
    assert!(RELAY_REPLY_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
