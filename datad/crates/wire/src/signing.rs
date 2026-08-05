//! The signing delegation channel: a one-outstanding-request window through
//! which the domain that authenticates to the network asks the domain that holds
//! the device key to sign, without ever holding the key.
//!
//! Faces the byzantine neighbour protection domain from both sides. Nothing here
//! judges a signature — whether one verifies is a question for the cryptography a
//! caller already has, asked of a public key and not of a region.
//!
//! # Why the channel exists at all
//!
//! The device private key belongs to the domain that owns the medium it is
//! written on, because only one domain can own a virtio-blk device and a key that
//! left that domain would be a key in two places. The domain that terminates a
//! mutually-authenticated session needs a signature under that key on every
//! handshake, and needs the public half and the identifier to present a
//! certificate at all. So the private operation is delegated: the request carries
//! a message, the reply carries a signature, and **no region either side maps
//! carries the scalar**. That is a property of what this ABI can express rather
//! than a rule somebody keeps — there is no field for a key here, in either
//! direction.
//!
//! # Two regions, because a region is the unit of grant
//!
//! [`SignRequest`] is the asking domain's to write and the holding domain's to
//! read; [`SignReply`] is the reverse. [`crate::DownloadRequest`]'s split, and
//! here the asymmetry is what keeps the asking domain from writing a signature
//! into the region it then reads back — a domain that could forge a reply could
//! make a handshake succeed under a signature the key never produced.
//!
//! # The sequence number is the whole correlation
//!
//! Nothing else says a reply belongs to a request. The requester increments the
//! number and the responder echoes it, and a reply carrying any other number is
//! **ignored entirely**. Zero is reserved for *no request*, so a zeroed pair of
//! regions is a channel with nothing outstanding.
//!
//! [`PendingSignature`] is what makes that hard to get wrong: it is not `Copy`,
//! only [`SignRequester::request`] mints one, and [`SignRequester::poll`] takes it
//! by value — so a reply cannot be looked at without giving up the handle.
//!
//! # The reply carries the operation it answers
//!
//! A signature and a public key are different shapes, and a channel whose reply
//! said only "here are some bytes" would leave the caller to remember which
//! question was outstanding. So the operation travels back with the answer and a
//! mismatch is a fault: answering the wrong question is the responder's error and
//! not the requester's obligation.
//!
//! # One request in flight, which is what makes a single fence enough
//!
//! The responder publishes the bytes and then the sequence, `Release`; the
//! requester reads the sequence and then the bytes, `Acquire`. That suffices
//! because the protocol admits one outstanding request, on
//! [`crate::DownloadRequest`]'s terms exactly: the responder writes only in answer
//! to a demand it took, and cannot take another until the requester issues one.

use core::{
    mem::size_of,
    sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
};

use crate::MAPPING_ALIGN;

/// Bytes of message one signing request may carry.
///
/// 256, which is comfortably above what the one caller signs: a TLS 1.3
/// certificate-verify input is 64 bytes of padding, a context string, a separator
/// and a 32-byte transcript hash — under 140 — and rounding up leaves room for a
/// context string this appliance does not yet use without moving an offset the
/// protocol is stated in.
pub const MAX_SIGN_MESSAGE: usize = 256;

/// Bytes of signature one reply may carry: the longest DER-encoded ECDSA P-256
/// signature, which is a `SEQUENCE` header and two at-most-33-byte integers.
/// `lfw_crypto::P256_MAX_SIGNATURE_LEN` is the same number, and this crate
/// declines to depend on the cryptography for one integer — the protection domain
/// that sees both is where they are held equal.
pub const MAX_SIGNATURE_LEN: usize = 72;

/// Bytes of the uncompressed SEC1 public point a [`SignOperation::PublicKey`]
/// answer carries.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Bytes of the device identifier that answer carries beside it: 128 bits, before
/// anything renders it.
pub const DEVICE_ID_LEN: usize = 16;

/// Bytes the system description reserves for the request region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const SIGN_REQUEST_REGION_SIZE: usize =
    size_of::<SignRequest>().next_multiple_of(MAPPING_ALIGN);

/// As [`SIGN_REQUEST_REGION_SIZE`], for the direction carrying the answer.
pub const SIGN_REPLY_REGION_SIZE: usize = size_of::<SignReply>().next_multiple_of(MAPPING_ALIGN);

/// What a request asks the key holder to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignOperation {
    /// Sign the message the request carries, under the device key, with the one
    /// algorithm the certificate profile fixes.
    Sign,
    /// Answer the device's public key and identifier. Not a signature and not a
    /// secret: it is what a caller needs to present a certificate, and it travels
    /// this channel rather than a second one because it is the same authority —
    /// "tell me about the key you hold" — asked in the other tense.
    PublicKey,
}

impl SignOperation {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Sign => 0,
            Self::PublicKey => 1,
        }
    }

    /// `None` for every other bit pattern, on [`crate::DownloadSink::from_bits`]'s
    /// terms: the field is peer-written, so an undecodable value is input to
    /// reject rather than one to coerce. The responder answers such a request with
    /// [`SignRefusal::NoSuchOperation`] rather than ignoring it, because a
    /// requester left waiting cannot tell a refusal from a hang.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Sign),
            1 => Some(Self::PublicKey),
            _ => None,
        }
    }
}

/// The status word of a reply, as it appears in the region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignStatus {
    /// The reply holds what was asked for.
    Ok,
    /// The key holder has no identity yet: its medium has not been read, or it
    /// refused at start-up. Distinct from a refusal to sign, because an operator
    /// acts on the two differently — one is a node still coming up, the other a
    /// node that cannot use the key it has.
    NoIdentity,
    /// The signing operation itself failed.
    SigningFailed,
    /// The request named an operation this responder has none of.
    NoSuchOperation,
    /// The request's message length is past what a request may carry, so there is
    /// nothing well-defined to sign.
    MessageTooLong,
}

impl SignStatus {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::NoIdentity => 1,
            Self::SigningFailed => 2,
            Self::NoSuchOperation => 3,
            Self::MessageTooLong => 4,
        }
    }

    /// `None` for every other bit pattern. There is deliberately no value that
    /// means "assume it worked".
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Ok),
            1 => Some(Self::NoIdentity),
            2 => Some(Self::SigningFailed),
            3 => Some(Self::NoSuchOperation),
            4 => Some(Self::MessageTooLong),
            _ => None,
        }
    }
}

/// [`SignStatus`] without its success, which is what a refusal can be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignRefusal {
    NoIdentity,
    SigningFailed,
    NoSuchOperation,
    MessageTooLong,
}

impl SignRefusal {
    #[must_use]
    pub const fn to_status(self) -> SignStatus {
        match self {
            Self::NoIdentity => SignStatus::NoIdentity,
            Self::SigningFailed => SignStatus::SigningFailed,
            Self::NoSuchOperation => SignStatus::NoSuchOperation,
            Self::MessageTooLong => SignStatus::MessageTooLong,
        }
    }

    /// `None` for [`SignStatus::Ok`], which is the point of the type.
    #[must_use]
    pub const fn from_status(status: SignStatus) -> Option<Self> {
        match status {
            SignStatus::Ok => None,
            SignStatus::NoIdentity => Some(Self::NoIdentity),
            SignStatus::SigningFailed => Some(Self::SigningFailed),
            SignStatus::NoSuchOperation => Some(Self::NoSuchOperation),
            SignStatus::MessageTooLong => Some(Self::MessageTooLong),
        }
    }
}

/// The request region: what is being asked. The asking domain maps this
/// read-write and the key holder read-only.
///
/// Every field is private and no accessor reaches one, so the ordering each word
/// carries is a property of this type rather than a convention its two domains are
/// asked to keep.
#[repr(C)]
pub struct SignRequest {
    sequence: AtomicU32,
    operation: AtomicU32,
    len: AtomicU32,
    /// Alignment only. Nothing is placed here and nothing reads it.
    _pad: AtomicU32,
    /// One atomic per byte rather than packed into words, on
    /// [`crate::DownloadReply`]'s terms: these are message bytes, so packing them
    /// would make the byte order of the region a thing this crate chooses.
    message: [AtomicU8; MAX_SIGN_MESSAGE],
}

impl SignRequest {
    /// A zeroed region, which is what the kernel hands a domain that maps one:
    /// sequence zero is *no request*, so nothing is outstanding.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            operation: AtomicU32::new(0),
            len: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
            message: [const { AtomicU8::new(0) }; MAX_SIGN_MESSAGE],
        }
    }

    /// Take the asking side's handle: this region to write, the holder's reply to
    /// read.
    ///
    /// Take it **once** per channel and keep it, on [`crate::LogRecords::writer`]'s
    /// terms: a second restarts at sequence zero and would reuse numbers the first
    /// has outstanding.
    #[must_use]
    pub const fn requester<'chan>(&'chan self, reply: &'chan SignReply) -> SignRequester<'chan> {
        SignRequester {
            request: self,
            reply: PeerReply::new(reply),
            sequence: 0,
            faults: 0,
        }
    }
}

impl Default for SignRequest {
    fn default() -> Self {
        Self::zero()
    }
}

/// The reply region: the answer and what to make of it. The key holder maps this
/// read-write and the asking domain read-only.
#[repr(C)]
pub struct SignReply {
    sequence: AtomicU32,
    status: AtomicU32,
    operation: AtomicU32,
    len: AtomicU32,
    /// Signatures this responder has produced since it started, so an operator
    /// can see the delegation working without a signature reaching a surface.
    signed: AtomicU64,
    signature: [AtomicU8; MAX_SIGNATURE_LEN],
    public_key: [AtomicU8; PUBLIC_KEY_LEN],
    device_id: [AtomicU8; DEVICE_ID_LEN],
}

impl SignReply {
    /// As [`SignRequest::zero`]. Sequence zero answers no request, so a zeroed
    /// reply is never mistaken for one.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            status: AtomicU32::new(0),
            operation: AtomicU32::new(0),
            len: AtomicU32::new(0),
            signed: AtomicU64::new(0),
            signature: [const { AtomicU8::new(0) }; MAX_SIGNATURE_LEN],
            public_key: [const { AtomicU8::new(0) }; PUBLIC_KEY_LEN],
            device_id: [const { AtomicU8::new(0) }; DEVICE_ID_LEN],
        }
    }

    /// Take the answering side's handle, on [`SignRequest::requester`]'s terms.
    #[must_use]
    pub const fn responder<'chan>(
        &'chan self,
        request: &'chan SignRequest,
    ) -> SignResponder<'chan> {
        SignResponder {
            reply: self,
            request: PeerRequest::new(request),
            served: 0,
            signed: 0,
        }
    }
}

impl Default for SignReply {
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

    use super::{SignReply, SignRequest};

    /// The reply region as the asking domain holds it: loads only.
    pub(super) struct PeerReply<'chan>(&'chan SignReply);

    impl<'chan> PeerReply<'chan> {
        pub(super) const fn new(reply: &'chan SignReply) -> Self {
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

        pub(super) fn signed(&self) -> u64 {
            self.0.signed.load(Ordering::Relaxed)
        }

        /// Bounded by `into`, which the caller obtained from the reply's own
        /// length: `zip` walks the shorter of the two, so no index is taken.
        pub(super) fn copy_signature(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.signature) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }

        pub(super) fn public_key(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.public_key) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }

        pub(super) fn device_id(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.device_id) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }
    }

    /// The request region as the key holder holds it, on [`PeerReply`]'s terms.
    pub(super) struct PeerRequest<'chan>(&'chan SignRequest);

    impl<'chan> PeerRequest<'chan> {
        pub(super) const fn new(request: &'chan SignRequest) -> Self {
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

        pub(super) fn copy_message(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.message) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }
    }
}

use peer::{PeerReply, PeerRequest};

/// A request the requester has issued and not yet had answered.
///
/// Neither `Copy` nor `Clone`, and produced only by [`SignRequester::request`]:
/// the sequence number a reply must match cannot be conjured, duplicated, or kept
/// across an answer.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a request nothing polls is a signature that never arrives"]
pub struct PendingSignature {
    sequence: u32,
    /// What was asked, so a reply answering something else can be refused.
    operation: SignOperation,
}

impl PendingSignature {
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn operation(&self) -> SignOperation {
        self.operation
    }
}

/// A reply the responder's bytes cannot be. Each one consumes the
/// [`PendingSignature`] it was raised against: a peer that answered with nonsense
/// will not answer better on a second look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignFault {
    /// A status word outside [`SignStatus`].
    StatusUnknown { status: u32 },
    /// An operation word outside [`SignOperation`].
    OperationUnknown { operation: u32 },
    /// The reply answers a different question from the one that was asked.
    WrongOperation {
        asked: SignOperation,
        answered: SignOperation,
    },
    /// More signature bytes claimed than the region holds. The one fault that
    /// would be a read past the region if it were believed.
    LenPastSignature { len: u32 },
    /// A refusal carrying bytes, which no answer means.
    BytesOnRefusal { status: SignStatus, len: u32 },
    /// A signature of zero length under a success, which is not a signature.
    EmptySignature,
}

/// What a [`SignOperation::PublicKey`] request was answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub device_id: [u8; DEVICE_ID_LEN],
}

/// What [`SignRequester::poll`] found.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the pending request is returned inside this and is lost if dropped"]
pub enum SignPoll<'buf> {
    /// No reply to *this* request yet. The handle comes back so the caller can
    /// poll again; this is one attempt, and a caller that spins on it has written
    /// the unbounded loop the single attempt exists to avoid.
    Outstanding(PendingSignature),
    /// The holder signed. `signature` is the DER encoding, bounded by the region.
    Signed {
        signature: &'buf [u8],
        /// Signatures this holder has produced, so a caller can report the
        /// delegation working without a signature reaching a surface.
        signed: u64,
    },
    /// The holder answered which key it holds.
    Identity(DeviceIdentity),
    /// The holder answered and produced nothing, saying why.
    Refused(SignRefusal),
    /// The reply carried this request's sequence and could not be believed.
    Faulted(SignFault),
}

/// The asking side, holding its own sequence and fault tally in private memory.
pub struct SignRequester<'chan> {
    request: &'chan SignRequest,
    reply: PeerReply<'chan>,
    /// Private, and never read back from the region: a number this side read out
    /// of shared memory could be walked backwards by the peer, which would let an
    /// old reply match a new request.
    sequence: u32,
    faults: u32,
}

impl SignRequester<'_> {
    /// Ask for `operation` over `message`, and take the handle the answer must be
    /// claimed with.
    ///
    /// A message longer than [`MAX_SIGN_MESSAGE`] is **truncated in the region and
    /// reported as its true length**, so the responder sees a length it must
    /// refuse rather than a short message it would happily sign. Signing a
    /// silently shortened message is the one failure here that would look like
    /// success on both sides.
    pub fn request(&mut self, operation: SignOperation, message: &[u8]) -> PendingSignature {
        for (cell, byte) in self.request.message.iter().zip(message) {
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
            .store(clamp_u32(message.len()), Ordering::Relaxed);
        // Release, and last: the words above must be visible to the holder before
        // the sequence that makes them a request is.
        self.request
            .sequence
            .store(self.sequence, Ordering::Release);
        PendingSignature {
            sequence: self.sequence,
            operation,
        }
    }

    /// Look once for the answer to `pending`, copying any signature into `into`.
    ///
    /// The sequence is read **before** anything else and with `Acquire`, which is
    /// what makes the responder's bytes visible before they are copied; a mismatch
    /// returns the handle and reads nothing at all.
    pub fn poll<'buf>(
        &mut self,
        pending: PendingSignature,
        into: &'buf mut [u8; MAX_SIGNATURE_LEN],
    ) -> SignPoll<'buf> {
        if self.reply.sequence() != pending.sequence {
            return SignPoll::Outstanding(pending);
        }
        let raw_status = self.reply.status();
        let raw_operation = self.reply.operation();
        let len = self.reply.len();

        let Some(status) = SignStatus::from_bits(raw_status) else {
            return self.fault(SignFault::StatusUnknown { status: raw_status });
        };
        let Some(answered) = SignOperation::from_bits(raw_operation) else {
            return self.fault(SignFault::OperationUnknown {
                operation: raw_operation,
            });
        };
        if answered != pending.operation {
            return self.fault(SignFault::WrongOperation {
                asked: pending.operation,
                answered,
            });
        }
        // The region bound and the copy's destination are one operation, so the
        // check cannot drift from the slice it protects.
        let Some(target) = into.get_mut(..len as usize) else {
            return self.fault(SignFault::LenPastSignature { len });
        };
        if let Some(reason) = SignRefusal::from_status(status) {
            if len != 0 {
                return self.fault(SignFault::BytesOnRefusal { status, len });
            }
            return SignPoll::Refused(reason);
        }
        match answered {
            SignOperation::Sign => {
                if len == 0 {
                    return self.fault(SignFault::EmptySignature);
                }
                self.reply.copy_signature(target);
                SignPoll::Signed {
                    signature: target,
                    signed: self.reply.signed(),
                }
            }
            SignOperation::PublicKey => {
                let mut public_key = [0_u8; PUBLIC_KEY_LEN];
                let mut device_id = [0_u8; DEVICE_ID_LEN];
                self.reply.public_key(&mut public_key);
                self.reply.device_id(&mut device_id);
                SignPoll::Identity(DeviceIdentity {
                    public_key,
                    device_id,
                })
            }
        }
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

    fn fault<'buf>(&mut self, fault: SignFault) -> SignPoll<'buf> {
        self.faults = self.faults.saturating_add(1);
        SignPoll::Faulted(fault)
    }
}

/// A request the key holder has taken and not yet answered.
///
/// Consumed by every answering method, so one demand produces exactly one reply.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a demand nothing answers leaves the requester waiting"]
pub struct SignDemand {
    sequence: u32,
    operation: Option<SignOperation>,
    len: u32,
}

impl SignDemand {
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Which operation was asked for, or `None` where the word named none this
    /// holder has — which is answered with [`SignRefusal::NoSuchOperation`] rather
    /// than ignored.
    #[must_use]
    pub const fn operation(&self) -> Option<SignOperation> {
        self.operation
    }

    /// The message length the requester stated, **unclamped**: a length past
    /// [`MAX_SIGN_MESSAGE`] is a request to refuse and not one to shorten, so it
    /// arrives as what was claimed.
    #[must_use]
    pub const fn stated_len(&self) -> u32 {
        self.len
    }

    /// The message, copied into `into`, or `None` where the stated length is past
    /// what a request can hold — which is the [`SignRefusal::MessageTooLong`]
    /// case and the whole reason this returns an `Option` rather than a slice.
    pub fn message<'buf>(
        &self,
        responder: &SignResponder<'_>,
        into: &'buf mut [u8; MAX_SIGN_MESSAGE],
    ) -> Option<&'buf [u8]> {
        let target = into.get_mut(..self.len as usize)?;
        responder.request.copy_message(target);
        Some(target)
    }
}

/// The answering side, holding the last sequence it served in private memory.
pub struct SignResponder<'chan> {
    reply: &'chan SignReply,
    request: PeerRequest<'chan>,
    /// Private, on [`SignRequester::sequence`]'s terms: a peer that could rewind
    /// this would have the holder sign one message twice.
    served: u32,
    signed: u64,
}

impl SignResponder<'_> {
    /// Take the outstanding request, if there is one this responder has not
    /// already answered.
    ///
    /// `None` covers both "nothing was ever asked" — sequence zero, which is what
    /// a zeroed region holds — and "the number has not moved since the last
    /// demand". A peer that rewrites the sequence to an arbitrary value produces
    /// **at most one demand per change**, so a request storm costs one reply each
    /// and never an unbounded loop.
    ///
    /// The number is recorded here rather than when the answer is published, which
    /// is what makes that a property of this type rather than of a caller that
    /// remembers to answer before taking again. What it obliges instead is that a
    /// demand taken is a demand answered: every answering method consumes one, and
    /// a `SignDemand` dropped unanswered leaves the requester polling a sequence
    /// nothing will publish. `#[must_use]` on the demand is what makes dropping
    /// one visible.
    pub fn take(&mut self) -> Option<SignDemand> {
        let sequence = self.request.sequence();
        if sequence == 0 || sequence == self.served {
            return None;
        }
        self.served = sequence;
        Some(SignDemand {
            sequence,
            operation: SignOperation::from_bits(self.request.operation()),
            len: self.request.len(),
        })
    }

    /// Answer `demand` with a signature.
    ///
    /// `signature` is truncated to what the region holds, and the published length
    /// is what was actually stored — so a holder handing over more than fits
    /// publishes only what it wrote.
    pub fn signed(&mut self, demand: SignDemand, signature: &[u8]) -> usize {
        let mut published = 0_u32;
        for (cell, byte) in self.reply.signature.iter().zip(signature) {
            cell.store(*byte, Ordering::Relaxed);
            published += 1;
        }
        self.signed = self.signed.saturating_add(1);
        self.reply.signed.store(self.signed, Ordering::Relaxed);
        self.publish(demand, SignOperation::Sign, SignStatus::Ok, published);
        published as usize
    }

    /// Answer `demand` with the identity of the key this holder has.
    pub fn identity(&mut self, demand: SignDemand, identity: &DeviceIdentity) {
        for (cell, byte) in self.reply.public_key.iter().zip(identity.public_key) {
            cell.store(byte, Ordering::Relaxed);
        }
        for (cell, byte) in self.reply.device_id.iter().zip(identity.device_id) {
            cell.store(byte, Ordering::Relaxed);
        }
        self.publish(demand, SignOperation::PublicKey, SignStatus::Ok, 0);
    }

    /// Answer `demand` with nothing, saying why. Publishes a zero length, which is
    /// what makes [`SignFault::BytesOnRefusal`] a fault the requester can raise
    /// against a peer that does otherwise.
    pub fn refuse(&mut self, demand: SignDemand, reason: SignRefusal) {
        // The operation echoed on a refusal is the one that was asked for, so a
        // requester can still tell its own question was the one refused. Where the
        // word named nothing there is no operation to echo and the refusal itself
        // is what says so, so the encoding falls back to `Sign`'s zero — which the
        // requester never mistakes for an answer, `NoSuchOperation` carrying no
        // bytes.
        let operation = demand.operation.unwrap_or(SignOperation::Sign);
        self.publish(demand, operation, reason.to_status(), 0);
    }

    /// Signatures this responder has produced.
    #[must_use]
    pub const fn signatures(&self) -> u64 {
        self.signed
    }

    #[must_use]
    pub const fn served(&self) -> u32 {
        self.served
    }

    fn publish(
        &mut self,
        demand: SignDemand,
        operation: SignOperation,
        status: SignStatus,
        len: u32,
    ) {
        self.reply.status.store(status.to_bits(), Ordering::Relaxed);
        self.reply
            .operation
            .store(operation.to_bits(), Ordering::Relaxed);
        self.reply.len.store(len, Ordering::Relaxed);
        // Release, and last: the bytes and the three words above must be visible
        // to the requester before the sequence that claims them as this request's
        // answer is.
        self.reply
            .sequence
            .store(demand.sequence, Ordering::Release);
    }
}

/// A length as a `u32`, saturating rather than truncating: a truncated length
/// would understate a message and let a responder sign a prefix of it.
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
    assert!(MAX_SIGN_MESSAGE > 0 && MAX_SIGN_MESSAGE <= u32::MAX as usize);
    assert!(MAX_SIGNATURE_LEN > 0 && MAX_SIGNATURE_LEN <= u32::MAX as usize);
    // A zeroed pair of regions is the valid idle state: sequence zero is no
    // request and answers none, so neither side acts on what the kernel handed
    // it.
    assert!(SignStatus::Ok.to_bits() == 0);
    assert!(SignOperation::Sign.to_bits() == 0);
    assert!(SignRefusal::from_status(SignStatus::Ok).is_none());
    assert!(SignStatus::from_bits(5).is_none());
    assert!(SignOperation::from_bits(2).is_none());

    assert!(offset_of!(SignRequest, sequence) == 0);
    assert!(offset_of!(SignRequest, operation) == 4);
    assert!(offset_of!(SignRequest, len) == 8);
    assert!(offset_of!(SignRequest, _pad) == 12);
    assert!(offset_of!(SignRequest, message) == 16);
    assert!(align_of::<SignRequest>() == 4);
    assert!(size_of::<SignRequest>() == 16 + MAX_SIGN_MESSAGE);

    assert!(offset_of!(SignReply, sequence) == 0);
    assert!(offset_of!(SignReply, status) == 4);
    assert!(offset_of!(SignReply, operation) == 8);
    assert!(offset_of!(SignReply, len) == 12);
    assert!(offset_of!(SignReply, signed) == 16);
    assert!(offset_of!(SignReply, signature) == 24);
    assert!(align_of::<SignReply>() == 8);
    // Naturally aligned, which is what makes the counter a single access rather
    // than two a reader could tear across.
    assert!(offset_of!(SignReply, signed).is_multiple_of(align_of::<u64>()));

    // Each region must hold its type and be mappable.
    assert!(SIGN_REQUEST_REGION_SIZE >= size_of::<SignRequest>());
    assert!(SIGN_REQUEST_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(SIGN_REPLY_REGION_SIZE >= size_of::<SignReply>());
    assert!(SIGN_REPLY_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
