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
//! handshake, and needs the public half, the identifier and the appliance's own
//! certificate to present an identity at all. So the private operation is
//! delegated: the request carries a message, the reply carries a signature, and
//! **no region either side maps carries the scalar**. That is a property of what
//! this ABI can express rather than a rule somebody keeps — there is no field for
//! a key here, in either direction.
//!
//! # What the reply *can* carry, and why none of it is a secret
//!
//! Five things, and each is public by construction. A **signature**, which is
//! what a private key produces and not what it is. A **public point** and a
//! **device identifier**, which are the two values a peer is told. A
//! **certificate**, which is the artifact a peer validates that point out of —
//! it is published to every party the appliance ever talks to, so a channel that
//! moves it moves nothing an adversary could not have asked the appliance for.
//! And a **trust anchor**, the certificate of the authority a management plane
//! delivered when it took this appliance: the peer this appliance will dial holds
//! it already, being the party that issues under it, so moving it reveals nothing
//! to the adversary it is used against.
//!
//! The scalar is absent from all five, and neither certificate weakens that: a
//! certificate is a signed statement *about* a public key, and its encoding has
//! no place a private one goes. The claim this ABI makes is unchanged and is
//! still structural — every field is one of those five shapes, and none of them
//! is 32 bytes of private scalar under any interpretation.
//!
//! **The anchor is the one answer whose absence is normal.** An appliance nobody
//! has taken has no anchor, and the holder says so by name
//! ([`SignRefusal::NoAnchor`]) rather than answering an empty byte string: zero
//! bytes under a success would be a caller free to read "nothing was delivered"
//! as "an anchor of no length", and whom this appliance trusts is not a question
//! to answer ambiguously.
//!
//! # What the reply *cannot* carry, which one operation's answer settles
//!
//! [`SignOperation::Install`] asks the holder to take ownership of the appliance
//! out of an archive staged in [`crate::InstallStaging`], and its answer is **the
//! status word and nothing else**: installed, or refused. No field is added for
//! it, which is the measurement that decided the shape — the reply used 946 of
//! the 4096 bytes its region grants when that was decided and uses 1714 now, so a
//! byte string would have been free then and is free still, and is refused
//! either way.
//!
//! It is refused because the vocabulary that would go in one is not this ABI's.
//! **Which rule** refused a package is the holder's own catalogue of the package
//! contract, and it reaches an operator on the console of the domain that made
//! the decision, where the facts that place it are. A word here spelling the same
//! catalogue would be a second copy of it crossing a region — one that a
//! byzantine holder could spell wrongly and that would have to be kept in step
//! with the first for as long as both existed. So what crosses is the verdict,
//! which is the part the asking domain acts on, and the reason stays where it was
//! decided.
//!
//! The archive itself never crosses this pair at all. It sits in a region of its
//! own that the asking domain writes and the holder reads, and the request states
//! only how many bytes of it there are — so the delegation keeps carrying words
//! and small fixed fields, and the one large object in this handover is somewhere
//! neither side has to reassemble.
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
//! A signature, a public key, a certificate, an anchor and an install verdict are
//! different shapes — three of them are variable-length byte strings and one
//! carries no bytes at all — so a channel whose reply said only "here are some
//! bytes" would leave the caller to remember which question was outstanding *and*
//! which bound to hold the length to. Two of the three share a bound and are
//! still separate fields with separate faults, because they are statements about
//! different keys and a caller told only that "a length was overrun" would not
//! know which answer to go and look at. So the operation travels back with the
//! answer and a mismatch is a fault: answering the wrong question is the
//! responder's error and not the requester's obligation.
//!
//! The stated length is then ranged **against the operation that was answered**,
//! which is why [`SignAnswerBuffer`] carries one destination per shape rather than
//! one buffer for all of them: a length is bounded by the same slice it is about
//! to be used to copy into, so the check cannot drift from what it protects.
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

use crate::{MAPPING_ALIGN, install::StagedUpload};

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

/// The ownership word of a [`SignOperation::PublicKey`] answer: this appliance
/// has no owner.
///
/// Zero, which is what a zeroed region holds — so a channel nothing has answered
/// on reads as an appliance still to be onboarded, which is the state that keeps
/// the onboarding surface open and is therefore the one a holder must say
/// something to move away from.
const NOT_OWNED: u8 = 0;

/// The same word saying it has one.
const OWNED: u8 = 1;

/// Bytes of certificate a [`SignOperation::Certificate`] answer may carry, and so
/// the widest thing this channel moves.
///
/// Seven hundred and sixty-eight, which is what the certificate profile bounds one
/// at and what the state record reserves for one: `lfw_x509::MAX_CERTIFICATE_LEN`
/// and `lfw_store`'s `MAX_STORED_CERTIFICATE` are the same number. This crate
/// declines to depend on either for one integer on [`MAX_SIGNATURE_LEN`]'s terms —
/// the two protection domains that see this constant beside one of those are where
/// they are held equal.
pub const MAX_CERTIFICATE_LEN: usize = 768;

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
    /// Answer the appliance's own certificate over the key this holder signs
    /// under.
    ///
    /// A **public** artifact: it is the statement every peer is handed and
    /// validates the public point out of, so moving it here reveals nothing an
    /// adversary could not obtain by connecting. It travels this channel for
    /// [`Self::PublicKey`]'s reason and one more: the certificate is part of the
    /// identity the holder established and persisted, and a caller that issued an
    /// equivalent one for itself would leave the appliance with two certificates
    /// over one key and no domain able to say which one a peer saw.
    Certificate,
    /// Install the onboarding package staged in [`crate::InstallStaging`], and
    /// say whether it was installed.
    ///
    /// The one operation whose subject is not in this pair of regions: the
    /// request states how many bytes of the staging region hold the archive, and
    /// **that number is a claim** — it is the asking domain's, it is not clamped
    /// on the way in, and the holder ranges it against its own region rather
    /// than believing it.
    ///
    /// It travels this channel because installing is what the holder of the
    /// device key does with a package: the archive's device certificate must
    /// bind *that* key, and the appliance's ownership is state on the medium
    /// only this holder can write. A domain that installed elsewhere would be
    /// deciding whose the appliance is without being able to see whose key it
    /// holds.
    Install,
    /// Answer the trust anchor a management plane delivered when it took this
    /// appliance.
    ///
    /// A **public** artifact on [`Self::Certificate`]'s terms and for one more
    /// reason: it is the certificate of the authority a management server is
    /// about to present a certificate under, so the peer this appliance is going
    /// to dial holds it already. What it decides is what this appliance will
    /// accept, and nothing about it is a secret from the party it is used
    /// against.
    ///
    /// It travels this channel because the holder is where a delivered anchor
    /// lives: it arrived inside an onboarding package, this holder judged that
    /// package and made the anchor durable, and it is one field of the very
    /// record the other three answers come out of. A domain that kept its own
    /// copy would be a second answer to the question of whom this appliance
    /// trusts, with no domain able to say which one a session was validated
    /// against.
    ///
    /// **An appliance nobody owns has none**, and that is not a fault: the holder
    /// refuses [`SignRefusal::NoAnchor`] by name rather than answering an empty
    /// byte string, so a caller is told there is nothing to trust yet instead of
    /// being handed zero bytes it might read as an anchor.
    Anchor,
    /// Record the configuration document staged in [`crate::InstallStaging`] as
    /// the running version, under the generation the request names.
    ///
    /// [`Self::Install`]'s shape with a different subject, reusing that region for
    /// the same reasons and carrying both its disclaimers: the stated length is
    /// **a claim**, and the answer is the status word alone.
    ///
    /// The generation travels in the message field as eight little-endian bytes,
    /// read by [`SignDemand::config_generation`] at a fixed width. It is the
    /// **deciding domain's** number, a holder that minted its own leaving the
    /// appliance with two answers to "which version is running" — and the holder
    /// still refuses one that does not advance past its array, which is a replay.
    ///
    /// **Nothing here reaches the trust anchor or the management endpoint**: the
    /// holder writes a slot and the table naming it and no other field.
    RecordConfig,
}

impl SignOperation {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Sign => 0,
            Self::PublicKey => 1,
            Self::Certificate => 2,
            Self::Install => 3,
            Self::Anchor => 4,
            Self::RecordConfig => 5,
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
            2 => Some(Self::Certificate),
            3 => Some(Self::Install),
            4 => Some(Self::Anchor),
            5 => Some(Self::RecordConfig),
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
    /// The holder looked at the staged archive and did not install it.
    ///
    /// The one value here that is a **verdict about the request's subject**
    /// rather than about this channel or about the holder's own state: nothing
    /// went wrong, a package was judged and refused. It rides the refusal shape
    /// because it produces no bytes, and which rule refused it is on the holder's
    /// console rather than in this word — see the header on what this reply
    /// deliberately cannot carry.
    InstallRefused,
    /// The holder has an identity and no delivered trust anchor: an appliance no
    /// management plane has taken.
    ///
    /// Its own value rather than [`Self::NoIdentity`], which would say the holder
    /// is still coming up, and rather than a success carrying zero bytes, which a
    /// caller could read as an anchor of no length. **This is the fail-closed
    /// answer to "whom does this appliance trust", and it is a positive
    /// statement**: nobody yet, said by the one domain that can know.
    NoAnchor,
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
            Self::InstallRefused => 5,
            Self::NoAnchor => 6,
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
            5 => Some(Self::InstallRefused),
            6 => Some(Self::NoAnchor),
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
    InstallRefused,
    NoAnchor,
}

impl SignRefusal {
    #[must_use]
    pub const fn to_status(self) -> SignStatus {
        match self {
            Self::NoIdentity => SignStatus::NoIdentity,
            Self::SigningFailed => SignStatus::SigningFailed,
            Self::NoSuchOperation => SignStatus::NoSuchOperation,
            Self::MessageTooLong => SignStatus::MessageTooLong,
            Self::InstallRefused => SignStatus::InstallRefused,
            Self::NoAnchor => SignStatus::NoAnchor,
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
            SignStatus::InstallRefused => Some(Self::InstallRefused),
            SignStatus::NoAnchor => Some(Self::NoAnchor),
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
    /// Last, and widest: the appliance's certificate. Appended rather than
    /// inserted, so every offset above it is the one it was, and placed here
    /// because it is the only field whose length is stated rather than fixed by
    /// its type.
    certificate: [AtomicU8; MAX_CERTIFICATE_LEN],
    /// Whether the holder's record says this appliance has an owner, published
    /// beside the identity the same record produced.
    ///
    /// Appended after the certificate on that field's own terms, and it costs
    /// the region nothing: the reply is eight-byte aligned and the certificate
    /// ended seven bytes short of a multiple of eight, so this byte lands in
    /// padding that was already there — which the size assertion at the foot of
    /// this file states rather than leaves to be noticed.
    owned: AtomicU8,
    /// Last, and the second field whose length is stated rather than fixed: the
    /// trust anchor a management plane delivered.
    ///
    /// Appended after the ownership word on the certificate's own terms, so every
    /// offset above it is the one it was. **This one is not free** — it is a
    /// second certificate's worth of region — and what makes it affordable is
    /// measured rather than assumed: the reply grows past 952 bytes and stays
    /// inside the single page the system description grants, which the assertion
    /// at the foot of this file holds it to. A field that pushed the type onto a
    /// second page would widen a capability, and it fails there first.
    ///
    /// It is its own field rather than a second use of `certificate`, because the
    /// two are different statements about different keys and a holder answering
    /// one out of the other's storage would be one buffer with two meanings.
    anchor: [AtomicU8; MAX_CERTIFICATE_LEN],
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
            certificate: [const { AtomicU8::new(0) }; MAX_CERTIFICATE_LEN],
            owned: AtomicU8::new(NOT_OWNED),
            anchor: [const { AtomicU8::new(0) }; MAX_CERTIFICATE_LEN],
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

        /// Bounded by `into` on [`Self::copy_signature`]'s terms, against the
        /// certificate's own field rather than the signature's.
        pub(super) fn copy_certificate(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.certificate) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }

        pub(super) fn owned(&self) -> u8 {
            self.0.owned.load(Ordering::Relaxed)
        }

        /// Bounded by `into` on [`Self::copy_signature`]'s terms, against the
        /// anchor's own field rather than the certificate's.
        pub(super) fn copy_anchor(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.anchor) {
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
    /// More signature bytes claimed than the region holds. One of the two faults
    /// that would be a read past a field if it were believed.
    LenPastSignature { len: u32 },
    /// More certificate bytes claimed than the region holds, which is the other.
    /// Its own variant rather than [`Self::LenPastSignature`] with a wider bound,
    /// because the two fields have different lengths and a single fault would
    /// leave a reader unable to tell which bound was exceeded.
    LenPastCertificate { len: u32 },
    /// A refusal carrying bytes, which no answer means.
    BytesOnRefusal { status: SignStatus, len: u32 },
    /// A recorded-configuration answer stating a length, which nothing there is a
    /// length of. Its own variant rather than [`Self::BytesOnInstall`].
    BytesOnConfigRecord { len: u32 },
    /// A signature of zero length under a success, which is not a signature.
    EmptySignature,
    /// A certificate of zero length under a success, which is not a certificate.
    /// A holder with no certificate to give refuses by name instead.
    EmptyCertificate,
    /// More anchor bytes claimed than the region holds, which is the third. Its
    /// own variant rather than [`Self::LenPastCertificate`] even though the two
    /// bounds are equal: the fields are separate, and a shared fault would leave
    /// an operator unable to tell which answer the holder overran.
    LenPastAnchor { len: u32 },
    /// An anchor of zero length under a success, which is not an anchor. A holder
    /// with none to give refuses [`SignRefusal::NoAnchor`] by name instead, which
    /// is what keeps "nobody has taken this appliance" apart from "the domain
    /// holding the anchor answered with nothing".
    EmptyAnchor,
    /// An identity answer stating a length. The public point and the identifier
    /// are fixed-width fields, so a length there is a claim about nothing — and a
    /// responder making one is not this protocol's, which is worth saying rather
    /// than ignoring.
    BytesOnIdentity { len: u32 },
    /// An install answer stating a length, on [`Self::BytesOnIdentity`]'s terms
    /// and for a stronger reason: the answer to an install is the status word
    /// alone, so there is no field a length could be about at all.
    BytesOnInstall { len: u32 },
    /// An ownership word outside the two this field has meanings for.
    ///
    /// Refused rather than read as "anything but zero is owned", on
    /// [`SignOperation::from_bits`]'s terms: the field is peer-written, and a
    /// coercion here would be this side deciding what a holder meant. The
    /// caller loses the whole identity answer, which is the fail-closed
    /// outcome — an appliance that cannot learn whether it has an owner
    /// presents no identity at all rather than guessing.
    OwnershipUnknown { owned: u8 },
}

/// Where one poll copies an answer's bytes.
///
/// One field per answer that carries a variable-length byte string, each exactly
/// its operation's bound. That is the whole point of the type rather than an
/// arrangement of it: [`SignRequester::poll`] ranges the stated length by slicing
/// the very buffer it is about to copy into, so the bound and its destination are
/// one operation and cannot drift apart. A single buffer sized to the larger of
/// the two would make the signature's bound a number written twice.
///
/// Nothing here is shared memory. A caller holds one, hands it to a poll, and the
/// slice that comes back borrows it — which is what keeps the region itself out of
/// every caller above.
pub struct SignAnswerBuffer {
    signature: [u8; MAX_SIGNATURE_LEN],
    certificate: [u8; MAX_CERTIFICATE_LEN],
    anchor: [u8; MAX_CERTIFICATE_LEN],
}

impl SignAnswerBuffer {
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            signature: [0; MAX_SIGNATURE_LEN],
            certificate: [0; MAX_CERTIFICATE_LEN],
            anchor: [0; MAX_CERTIFICATE_LEN],
        }
    }
}

impl Default for SignAnswerBuffer {
    fn default() -> Self {
        Self::zero()
    }
}

/// What a [`SignOperation::PublicKey`] request was answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Whether this appliance already has an owner, as the record on the
    /// holder's medium says.
    ///
    /// It rides the identity answer because it is a fact about the same record
    /// the other two come out of, read on the same boot by the domain that read
    /// them — and because the domain that asks needs it before it answers its
    /// first request. An onboarding surface is closed for good once an appliance
    /// is owned, and the *durability* of that close is exactly this word: the
    /// close is not a flag some domain sets and loses at the next boot, it is
    /// what the medium says, asked again every time the appliance starts.
    ///
    /// Not a secret and not a key. It is one bit about whether a certificate the
    /// appliance already publishes exists, which is a thing any peer learns by
    /// connecting to the port and being told the surface is gone.
    pub owned: bool,
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
    /// The holder answered with the appliance's certificate over that key.
    /// `certificate` is the DER encoding, bounded by the region.
    Certificate { certificate: &'buf [u8] },
    /// The holder answered with the trust anchor a management plane delivered.
    /// `anchor` is the DER encoding, bounded by the region.
    ///
    /// Never empty: an appliance with no anchor comes back as
    /// [`SignRefusal::NoAnchor`], so a caller reaching this arm holds bytes
    /// somebody really delivered.
    Anchor { anchor: &'buf [u8] },
    /// The holder installed the staged package: this appliance now has an owner,
    /// and the record that says so is durable.
    ///
    /// It carries nothing, and the absence is the answer's whole shape — the
    /// facts about what was installed reach an operator on the holder's console,
    /// where they were decided. A refusal comes back as
    /// [`SignRefusal::InstallRefused`] rather than as a variant here, so a caller
    /// that forgets to handle one gets the refusal arm it already has.
    Installed,
    /// The holder wrote the staged configuration document to a slot and made the
    /// record naming it durable. It carries nothing on [`Self::Installed`]'s terms.
    ConfigRecorded,
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

    /// Ask the holder to install the archive `staged` names.
    ///
    /// It consumes the token [`crate::UploadCursor::finish`] minted, so the
    /// length this request states is the length that staging really produced and
    /// not a number a caller carried alongside it. That is a convenience of this
    /// side and **not a defence**: the holder is answering a byzantine
    /// neighbour, so it ranges the stated length against its own region whatever
    /// wrote it — see [`SignOperation::Install`].
    ///
    /// The request carries no message. Its bytes are in the staging region, and
    /// the `Release` store of the sequence below is what makes them visible to
    /// the holder before the demand that names them is.
    pub fn install(&mut self, staged: StagedUpload) -> PendingSignature {
        // Zero is *no request*, on `request`'s terms.
        self.sequence = match self.sequence.wrapping_add(1) {
            0 => 1,
            next => next,
        };
        self.request
            .operation
            .store(SignOperation::Install.to_bits(), Ordering::Relaxed);
        self.request.len.store(staged.len(), Ordering::Relaxed);
        self.request
            .sequence
            .store(self.sequence, Ordering::Release);
        PendingSignature {
            sequence: self.sequence,
            operation: SignOperation::Install,
        }
    }

    /// Ask the holder to record the configuration document `staged` names as the
    /// running version, under `generation`.
    ///
    /// [`Self::install`]'s shape and its disclaimer. The generation goes in the
    /// message field and the stated length stays the staging region's, which lets
    /// the holder range the two separately.
    pub fn record_config(&mut self, generation: u64, staged: StagedUpload) -> PendingSignature {
        for (cell, byte) in self
            .request
            .message
            .iter()
            .zip(generation.to_le_bytes().iter())
        {
            cell.store(*byte, Ordering::Relaxed);
        }
        // Zero is *no request*, on `request`'s terms.
        self.sequence = match self.sequence.wrapping_add(1) {
            0 => 1,
            next => next,
        };
        self.request
            .operation
            .store(SignOperation::RecordConfig.to_bits(), Ordering::Relaxed);
        self.request.len.store(staged.len(), Ordering::Relaxed);
        self.request
            .sequence
            .store(self.sequence, Ordering::Release);
        PendingSignature {
            sequence: self.sequence,
            operation: SignOperation::RecordConfig,
        }
    }

    /// Look once for the answer to `pending`, copying any byte string it carries
    /// into `into`.
    ///
    /// The sequence is read **before** anything else and with `Acquire`, which is
    /// what makes the responder's bytes visible before they are copied; a mismatch
    /// returns the handle and reads nothing at all.
    pub fn poll<'buf>(
        &mut self,
        pending: PendingSignature,
        into: &'buf mut SignAnswerBuffer,
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
        if let Some(reason) = SignRefusal::from_status(status) {
            if len != 0 {
                return self.fault(SignFault::BytesOnRefusal { status, len });
            }
            return SignPoll::Refused(reason);
        }
        // The length is ranged per operation, and in every arm the bound and the
        // copy's destination are one operation — so the check cannot drift from the
        // slice it protects, and no arm holds the other's bound.
        match answered {
            SignOperation::Sign => {
                let Some(target) = into.signature.get_mut(..len as usize) else {
                    return self.fault(SignFault::LenPastSignature { len });
                };
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
                if len != 0 {
                    return self.fault(SignFault::BytesOnIdentity { len });
                }
                let raw_owned = self.reply.owned();
                let owned = match raw_owned {
                    NOT_OWNED => false,
                    OWNED => true,
                    other => return self.fault(SignFault::OwnershipUnknown { owned: other }),
                };
                let mut public_key = [0_u8; PUBLIC_KEY_LEN];
                let mut device_id = [0_u8; DEVICE_ID_LEN];
                self.reply.public_key(&mut public_key);
                self.reply.device_id(&mut device_id);
                SignPoll::Identity(DeviceIdentity {
                    public_key,
                    device_id,
                    owned,
                })
            }
            SignOperation::Certificate => {
                let Some(target) = into.certificate.get_mut(..len as usize) else {
                    return self.fault(SignFault::LenPastCertificate { len });
                };
                if len == 0 {
                    return self.fault(SignFault::EmptyCertificate);
                }
                self.reply.copy_certificate(target);
                SignPoll::Certificate {
                    certificate: target,
                }
            }
            SignOperation::Install => {
                if len != 0 {
                    return self.fault(SignFault::BytesOnInstall { len });
                }
                SignPoll::Installed
            }
            SignOperation::Anchor => {
                let Some(target) = into.anchor.get_mut(..len as usize) else {
                    return self.fault(SignFault::LenPastAnchor { len });
                };
                if len == 0 {
                    return self.fault(SignFault::EmptyAnchor);
                }
                self.reply.copy_anchor(target);
                SignPoll::Anchor { anchor: target }
            }
            SignOperation::RecordConfig => {
                if len != 0 {
                    return self.fault(SignFault::BytesOnConfigRecord { len });
                }
                SignPoll::ConfigRecorded
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

    /// The length the requester stated, **unclamped**: a length past what the
    /// operation admits is a request to refuse and not one to shorten, so it
    /// arrives as what was claimed.
    ///
    /// What it is a length *of* is the operation's. For [`SignOperation::Sign`]
    /// it is the message this request carries, and [`Self::message`] is what
    /// ranges it. For [`SignOperation::Install`] it is bytes of the staging
    /// region, which this pair of regions cannot see at all — so the holder
    /// ranges it against that region itself, and this is the raw claim it starts
    /// from.
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

    /// The configuration generation a [`SignOperation::RecordConfig`] request
    /// names, read at a **fixed** eight bytes out of the message field.
    ///
    /// It does not consult the stated length, which is why it is a method of its
    /// own: that length is about the staging region here, so ranging the message
    /// by it would refuse a document larger than a message.
    pub fn config_generation(&self, responder: &SignResponder<'_>) -> u64 {
        let mut bytes = [0_u8; size_of::<u64>()];
        responder.request.copy_message(&mut bytes);
        u64::from_le_bytes(bytes)
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

    /// Answer `demand` with the identity of the key this holder has, and with
    /// whether the record that key came out of says the appliance has an owner.
    pub fn identity(&mut self, demand: SignDemand, identity: &DeviceIdentity) {
        for (cell, byte) in self.reply.public_key.iter().zip(identity.public_key) {
            cell.store(byte, Ordering::Relaxed);
        }
        for (cell, byte) in self.reply.device_id.iter().zip(identity.device_id) {
            cell.store(byte, Ordering::Relaxed);
        }
        self.reply.owned.store(
            if identity.owned { OWNED } else { NOT_OWNED },
            Ordering::Relaxed,
        );
        self.publish(demand, SignOperation::PublicKey, SignStatus::Ok, 0);
    }

    /// Answer `demand` with the appliance's certificate over the key this holder
    /// signs under, on [`Self::signed`]'s terms: truncated to what the region
    /// holds, and the published length is what was actually stored.
    ///
    /// An empty `certificate` publishes a zero length, which the requester reads as
    /// [`SignFault::EmptyCertificate`] — so a holder with none to give must refuse
    /// by name rather than answer with nothing.
    pub fn certificate(&mut self, demand: SignDemand, certificate: &[u8]) -> usize {
        let mut published = 0_u32;
        for (cell, byte) in self.reply.certificate.iter().zip(certificate) {
            cell.store(*byte, Ordering::Relaxed);
            published += 1;
        }
        self.publish(
            demand,
            SignOperation::Certificate,
            SignStatus::Ok,
            published,
        );
        published as usize
    }

    /// Answer `demand` with the trust anchor a management plane delivered, on
    /// [`Self::certificate`]'s terms exactly: truncated to what the region holds,
    /// and the published length is what was actually stored.
    ///
    /// An empty `anchor` publishes a zero length, which the requester reads as
    /// [`SignFault::EmptyAnchor`] — so a holder that has none, which is every
    /// appliance nobody has taken, must refuse [`SignRefusal::NoAnchor`] rather
    /// than answer with nothing.
    pub fn anchor(&mut self, demand: SignDemand, anchor: &[u8]) -> usize {
        let mut published = 0_u32;
        for (cell, byte) in self.reply.anchor.iter().zip(anchor) {
            cell.store(*byte, Ordering::Relaxed);
            published += 1;
        }
        self.publish(demand, SignOperation::Anchor, SignStatus::Ok, published);
        published as usize
    }

    /// Answer `demand` with the fact that the staged package was installed.
    ///
    /// Publishes a zero length, and there is nothing else to publish: the answer
    /// to an install is the status word, so a length here would be a claim about
    /// a field that does not exist — which the requester raises as
    /// [`SignFault::BytesOnInstall`].
    pub fn installed(&mut self, demand: SignDemand) {
        self.publish(demand, SignOperation::Install, SignStatus::Ok, 0);
    }

    /// Answer `demand` with the verdict that the staged document is now a slot.
    pub fn config_recorded(&mut self, demand: SignDemand) {
        self.publish(demand, SignOperation::RecordConfig, SignStatus::Ok, 0);
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
    assert!(MAX_CERTIFICATE_LEN > 0 && MAX_CERTIFICATE_LEN <= u32::MAX as usize);
    // A zeroed pair of regions is the valid idle state: sequence zero is no
    // request and answers none, so neither side acts on what the kernel handed
    // it.
    assert!(SignStatus::Ok.to_bits() == 0);
    assert!(SignOperation::Sign.to_bits() == 0);
    assert!(SignRefusal::from_status(SignStatus::Ok).is_none());
    assert!(SignStatus::from_bits(7).is_none());
    assert!(SignOperation::from_bits(6).is_none());
    // `config_generation` reads bytes that are there whatever a length says.
    assert!(size_of::<u64>() <= MAX_SIGN_MESSAGE);

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
    // Every field after the signature is pinned too, the certificate having been
    // appended after them: an offset that moved would be a mapping both domains
    // read differently, and the four bounds below are the only thing that makes
    // "appended, never inserted" a compile-time claim.
    assert!(offset_of!(SignReply, public_key) == 24 + MAX_SIGNATURE_LEN);
    assert!(offset_of!(SignReply, device_id) == 24 + MAX_SIGNATURE_LEN + PUBLIC_KEY_LEN);
    assert!(
        offset_of!(SignReply, certificate)
            == 24 + MAX_SIGNATURE_LEN + PUBLIC_KEY_LEN + DEVICE_ID_LEN
    );
    assert!(
        offset_of!(SignReply, owned)
            == 24 + MAX_SIGNATURE_LEN + PUBLIC_KEY_LEN + DEVICE_ID_LEN + MAX_CERTIFICATE_LEN
    );
    assert!(
        offset_of!(SignReply, anchor)
            == 25 + MAX_SIGNATURE_LEN + PUBLIC_KEY_LEN + DEVICE_ID_LEN + MAX_CERTIFICATE_LEN
    );
    assert!(align_of::<SignReply>() == 8);
    assert!(
        size_of::<SignReply>()
            == (25
                + MAX_SIGNATURE_LEN
                + PUBLIC_KEY_LEN
                + DEVICE_ID_LEN
                + MAX_CERTIFICATE_LEN
                + MAX_CERTIFICATE_LEN)
                .next_multiple_of(align_of::<SignReply>())
    );
    // WHAT THE ANCHOR COSTS THE REGION, stated as the number rather than left to
    // be derived. The ownership word before it was free — the certificate ended
    // inside tail padding an eight-byte alignment had already reserved — and this
    // field is not: 946 bytes were used of the 4096 a page grants, and a second
    // certificate's worth takes that to 1714, padded to 1720. It fits, with 2376
    // bytes of the page still unspoken for, so no grant moves and the region stays
    // one page. A field that pushed the type past the page would widen a
    // capability in a diff nobody was reading, and the assertion below that pins
    // the region to one page is what stops it — but the arithmetic is written here
    // so the next person adding a field can see how much room is left.
    assert!(size_of::<SignReply>() == 1720);
    assert!(size_of::<SignReply>() < MAPPING_ALIGN);
    // A zeroed reply says the appliance has no owner, which is the state that
    // keeps the onboarding surface open — so a holder that never answered
    // cannot close it, and the close is a thing a holder has to say.
    assert!(NOT_OWNED == 0);
    assert!(OWNED != NOT_OWNED);
    // Naturally aligned, which is what makes the counter a single access rather
    // than two a reader could tear across.
    assert!(offset_of!(SignReply, signed).is_multiple_of(align_of::<u64>()));

    // Each region must hold its type and be mappable.
    assert!(SIGN_REQUEST_REGION_SIZE >= size_of::<SignRequest>());
    assert!(SIGN_REQUEST_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(SIGN_REPLY_REGION_SIZE >= size_of::<SignReply>());
    assert!(SIGN_REPLY_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));

    // And each is still exactly ONE mapping page, which is the size the system
    // description grants. Pinned rather than left derived, because a field that
    // pushed a region onto a second page would widen a capability without anything
    // saying so: the grant would follow the constant and the topology would change
    // in a diff nobody was reading. A type that outgrows a page is a change to
    // argue for, so it fails here first.
    assert!(SIGN_REQUEST_REGION_SIZE == MAPPING_ALIGN);
    assert!(SIGN_REPLY_REGION_SIZE == MAPPING_ALIGN);
};

#[cfg(test)]
mod tests;
