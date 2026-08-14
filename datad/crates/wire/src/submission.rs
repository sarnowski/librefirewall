//! The configuration submission channel: the one-outstanding-request window an
//! operator's document travels from the management domain to the domain that
//! decides on it, and the running document travels back through.
//!
//! Faces the byzantine neighbour protection domain from both sides, and behind
//! the requester the **management-plane attacker**: the bytes in the request
//! region arrived on a TCP connection to the management port, so every one of
//! them is that party's choice. Nothing on this side reads them — whether they
//! are a configuration is the deciding domain's question, asked of a copy it
//! took.
//!
//! # Why the channel exists at all
//!
//! The management domain is the one an attacker reaches first, and it holds two
//! frame pipelines. The configuration domain holds no device, no pool and no
//! dataplane ring, which is what makes it the domain an attacker's XML may be
//! parsed in. Handing management a parser instead would put the reader of a
//! hostile document in the same domain as a frame buffer, which is the single
//! grant that split exists to withhold. So management carries bytes and decides
//! nothing, and the direction of trust runs one way: **management hands on,
//! config decides.**
//!
//! # Two regions, because a region is the unit of grant
//!
//! [`ConfigRequest`] is management's to write and the config domain's to read;
//! [`ConfigReply`] is the reverse. [`crate::DownloadRequest`]'s split, and here
//! the asymmetry carries more: a management domain that could write the reply
//! could answer `GET /config` with a document the appliance is not running,
//! which is a fabricated statement about the policy in force rather than merely
//! a wrong answer. Each side reaches the other's region only through a view with
//! no store on it.
//!
//! # The sequence number is the whole correlation
//!
//! Nothing else says a reply belongs to a request, on
//! [`crate::DownloadRequest`]'s terms exactly: the requester increments, the
//! responder echoes, a reply carrying any other number is ignored entirely, and
//! zero is reserved for *no request* so a zeroed pair is an idle channel.
//! [`PendingConfigRequest`] is what makes that hard to get wrong — not `Copy`,
//! minted only by [`ConfigRequester::submit`] and [`ConfigRequester::read`], and
//! taken by [`ConfigRequester::poll`] by value.
//!
//! It also carries which **operation** was asked, and the poll checks the answer
//! against it: a responder answering a submission with a document, or a document
//! read with a generation, is a fault rather than something a caller has to
//! remember not to believe.
//!
//! # One request in flight, which is what makes a single fence enough
//!
//! [`crate::DownloadReply`]'s argument, unchanged: the responder writes only in
//! answer to a demand it took and cannot take another until the requester issues
//! one, so between the sequence becoming visible and the reader finishing its
//! copy there is, from a peer keeping to the protocol, no second write. It is
//! also why the running document is *asked for* rather than published
//! continuously — a region a peer rewrote whenever it liked would need a seqlock,
//! and a document read is an operator action rather than a hot path.
//!
//! # What each side still achieves against the other
//!
//! * **A hostile requester wastes the deciding domain's time and nothing else.**
//!   Its operation word is read as a claim and its length is clamped to the
//!   region by [`ConfigDemand::len`] before anything can size a copy from it. The
//!   bytes behind it are an arbitrary byte string, which is what the reader was
//!   written against in the first place.
//! * **A hostile responder cannot make management read past the region**, cannot
//!   have it believe a document it did not ask for, and cannot report a status
//!   outside the closed set: there is no value of the word that means "assume it
//!   worked".

use core::{
    mem::size_of,
    sync::atomic::{AtomicU8, AtomicU32, Ordering},
};

use crate::MAPPING_ALIGN;

/// Bytes of configuration document this appliance will read, and so the whole of
/// the storage each direction of this channel carries.
///
/// It is the bound the document reader enforces and the bound a submitted body is
/// refused against, and it is stated here because it is what sizes both regions:
/// a number two protection domains and a system description have to agree on is
/// an ABI, whichever crate first needed it.
///
/// 64 KiB holds a policy of the [`crate::MAX_RULES`] rules the handover image
/// admits, written out with every criterion spelled, and refuses anything a
/// document that describes one appliance would ever be.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// Bytes the system description reserves for the request region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const CONFIG_REQUEST_REGION_SIZE: usize =
    size_of::<ConfigRequest>().next_multiple_of(MAPPING_ALIGN);

/// As [`CONFIG_REQUEST_REGION_SIZE`], for the direction carrying the answer.
pub const CONFIG_REPLY_REGION_SIZE: usize =
    size_of::<ConfigReply>().next_multiple_of(MAPPING_ALIGN);

/// What a request asks the deciding domain to do.
///
/// Six operations across two transaction models. [`Self::Submit`] is one step —
/// stage, validate and commit — because the requester behind it holds a client on
/// a TCP connection. The four below it are those steps taken apart, for the
/// requester that can hold a decision open: a management channel stages, reads
/// the result, commits, and confirms. What each may be answered with is
/// [`ConfigStatus::answers`], the whole of the cross-field rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigOperation {
    /// The region holds a document to become the candidate, be validated and be
    /// committed.
    Submit,
    /// Answer with the document the appliance is running.
    Read,
    /// The region holds a document to become the candidate and be validated,
    /// committing nothing. What is running is untouched whichever way it goes.
    Stage,
    /// Commit the candidate, which must be the generation
    /// [`ConfigDemand::generation`] names. **Provisional**: the configuration
    /// replaced is kept until the commit is confirmed or rolled back, so an
    /// operator that loses its way to this appliance gets the previous one back.
    Commit,
    /// Keep the provisional commit [`ConfigDemand::generation`] names, giving up
    /// the configuration it replaced.
    Confirm,
    /// Put the configuration a provisional commit replaced back in force, under a
    /// generation of its own.
    ///
    /// It carries no generation to name: there is one provisional commit at a
    /// time and the restored configuration is whichever one that displaced, so a
    /// number here would be a second statement of a fact the store already holds
    /// — and one a requester could get wrong.
    Rollback,
}

impl ConfigOperation {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Submit => 0,
            Self::Read => 1,
            Self::Stage => 2,
            Self::Commit => 3,
            Self::Confirm => 4,
            Self::Rollback => 5,
        }
    }

    /// Whether this operation reads the request region's document bytes. The
    /// requester clears the length for every one that does not, so a stale length
    /// cannot have the deciding domain copy out bytes no request put there.
    #[must_use]
    pub const fn carries_a_document(self) -> bool {
        matches!(self, Self::Submit | Self::Stage)
    }

    /// Whether this operation names a generation in [`ConfigDemand::generation`]:
    /// the two that act on a commit already made do, and every other publishes
    /// zero, so a number left over from a previous request names nothing.
    #[must_use]
    pub const fn names_a_generation(self) -> bool {
        matches!(self, Self::Commit | Self::Confirm)
    }

    /// `None` for every other bit pattern, on [`crate::Verdict::from_bits`]'s
    /// terms: the field is peer-written, so an undecodable value is input to
    /// reject rather than one to coerce. The deciding domain answers such a
    /// request with [`ConfigStatus::NoSuchOperation`] rather than ignoring it,
    /// because a requester left waiting cannot tell a refusal from a hang.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Submit),
            1 => Some(Self::Read),
            2 => Some(Self::Stage),
            3 => Some(Self::Commit),
            4 => Some(Self::Confirm),
            5 => Some(Self::Rollback),
            _ => None,
        }
    }

    /// Every operation this channel has, in the order the word numbers them.
    ///
    /// Exposed so a caller that must cover the vocabulary — a test, a fuzz
    /// harness — enumerates it rather than restating it.
    pub const ALL: [Self; 6] = [
        Self::Submit,
        Self::Read,
        Self::Stage,
        Self::Commit,
        Self::Confirm,
        Self::Rollback,
    ];
}

/// The status word of a reply, as it appears in the region.
///
/// The decoded form is [`ConfigPoll`], which splits this into the case that
/// carries a document and the cases that cannot. This enum is the wire encoding
/// and exists in the public surface because an implementation of either side
/// needs the numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigStatus {
    /// The document committed and the generation moved.
    Applied,
    /// The document committed and was the configuration already running, so no
    /// generation was assigned: a commit is keyed by content.
    Unchanged,
    /// The document was refused. `reason` names the rule it broke and `detail`
    /// locates it, in the vocabulary a console line speaks.
    Rejected,
    /// The document passed every rule and the generation counter has no successor
    /// to assign it. Distinct from [`Self::Rejected`] because nothing about the
    /// document is wrong and there is no reason token to name.
    Exhausted,
    /// The region holds the document the appliance is running.
    Document,
    /// The request named no operation this appliance has.
    NoSuchOperation,
    /// The document passed every rule and is held as the candidate. `generation`
    /// is the one a commit of it would assign — which is what the requester names
    /// when it commits, so the two ends cannot disagree about which candidate a
    /// commit is for.
    Staged,
    /// The provisional commit is kept and the configuration it replaced is given
    /// up. `generation` is the one now permanently in force.
    Confirmed,
    /// The configuration a provisional commit replaced is in force again, under
    /// `generation` — a new one rather than the old number, because a
    /// configuration going back into force is a change the dataplane takes like
    /// any other and generations do not run backwards.
    RolledBack,
    /// A commit with nothing staged. Distinct from [`Self::Rejected`] because no
    /// document was judged: there is no reason token and no offset to name.
    NoCandidate,
    /// A confirmation or a rollback with no provisional commit outstanding —
    /// either none was made, or one already was confirmed or rolled back.
    NotProvisional,
    /// The generation the request named is not the one the operation would act
    /// on. `generation` is the one the appliance holds, so a requester that has
    /// lost track is told where it actually is rather than left to guess.
    GenerationMismatch,
}

impl ConfigStatus {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Applied => 0,
            Self::Unchanged => 1,
            Self::Rejected => 2,
            Self::Exhausted => 3,
            Self::Document => 4,
            Self::NoSuchOperation => 5,
            Self::Staged => 6,
            Self::Confirmed => 7,
            Self::RolledBack => 8,
            Self::NoCandidate => 9,
            Self::NotProvisional => 10,
            Self::GenerationMismatch => 11,
        }
    }

    /// `None` for every other bit pattern, on [`ConfigOperation::from_bits`]'s
    /// terms.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Applied),
            1 => Some(Self::Unchanged),
            2 => Some(Self::Rejected),
            3 => Some(Self::Exhausted),
            4 => Some(Self::Document),
            5 => Some(Self::NoSuchOperation),
            6 => Some(Self::Staged),
            7 => Some(Self::Confirmed),
            8 => Some(Self::RolledBack),
            9 => Some(Self::NoCandidate),
            10 => Some(Self::NotProvisional),
            11 => Some(Self::GenerationMismatch),
            _ => None,
        }
    }

    /// Whether an answer of this shape belongs to `operation`.
    ///
    /// The one cross-field rule of the protocol: a document answers a read and a
    /// generation answers a submission, and a responder that crosses them is
    /// answering a question nobody asked.
    /// [`ConfigStatus::NoSuchOperation`] belongs to no operation, being what an
    /// undecodable operation word is answered with.
    ///
    /// Several statuses answer more than one operation, and that is the two
    /// transaction models meeting: a one-step submission and a separate commit
    /// both end in a generation applied, unchanged or with none left to assign,
    /// and both a staging and a submission can refuse a document by name. What no
    /// status does is answer an operation it says nothing about — a confirmation
    /// reported as a staging is a fault, whichever way round.
    #[must_use]
    pub const fn answers(self, operation: ConfigOperation) -> bool {
        match self {
            Self::Applied | Self::Unchanged | Self::Exhausted => {
                matches!(operation, ConfigOperation::Submit | ConfigOperation::Commit)
            }
            Self::Rejected => {
                matches!(operation, ConfigOperation::Submit | ConfigOperation::Stage)
            }
            Self::Document => matches!(operation, ConfigOperation::Read),
            Self::Staged => matches!(operation, ConfigOperation::Stage),
            Self::Confirmed => matches!(operation, ConfigOperation::Confirm),
            Self::RolledBack => matches!(operation, ConfigOperation::Rollback),
            Self::NoCandidate => matches!(operation, ConfigOperation::Commit),
            Self::NotProvisional => matches!(
                operation,
                ConfigOperation::Confirm | ConfigOperation::Rollback
            ),
            Self::GenerationMismatch => matches!(
                operation,
                ConfigOperation::Commit | ConfigOperation::Confirm
            ),
            Self::NoSuchOperation => false,
        }
    }

    /// Every status this channel has, in the order the word numbers them.
    ///
    /// Exposed on [`ConfigOperation::ALL`]'s terms.
    pub const ALL: [Self; 12] = [
        Self::Applied,
        Self::Unchanged,
        Self::Rejected,
        Self::Exhausted,
        Self::Document,
        Self::NoSuchOperation,
        Self::Staged,
        Self::Confirmed,
        Self::RolledBack,
        Self::NoCandidate,
        Self::NotProvisional,
        Self::GenerationMismatch,
    ];
}

/// The request region: the document management is submitting, or the demand that
/// it be told what is running. Management maps this read-write and the
/// configuration domain read-only.
///
/// Every field is private and no accessor reaches one, so the ordering each word
/// carries is a property of this type rather than a convention its two domains
/// are asked to keep.
#[repr(C)]
pub struct ConfigRequest {
    sequence: AtomicU32,
    operation: AtomicU32,
    len: AtomicU32,
    /// The generation the request acts on, meaningful for exactly the operations
    /// [`ConfigOperation::names_a_generation`] admits and published as zero for
    /// every other.
    ///
    /// It occupies what was alignment padding, so naming a generation costs this
    /// region nothing. One omitted where it counts is answered with
    /// [`ConfigStatus::GenerationMismatch`] rather than having zero read as a
    /// generation — zero being no configuration at all.
    generation: AtomicU32,
    /// One atomic per byte rather than packed into words, for the tap ring's
    /// reason: these are bytes off a network, so packing them would make the byte
    /// order of the region a thing this crate chooses rather than one it mirrors.
    document: [AtomicU8; MAX_DOCUMENT_BYTES],
}

impl ConfigRequest {
    /// A zeroed region, which is what the kernel hands a domain that maps one:
    /// sequence zero is *no request*, so nothing is outstanding.
    ///
    /// A function rather than a `const`, on [`crate::DownloadRequest::zero`]'s
    /// terms.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            operation: AtomicU32::new(0),
            len: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            document: [const { AtomicU8::new(0) }; MAX_DOCUMENT_BYTES],
        }
    }

    /// Take the asking side's handle: this region to write, the deciding domain's
    /// reply to read.
    ///
    /// Take it **once** per channel and keep it: a second restarts at sequence
    /// zero and would reuse numbers the first has outstanding. No type stops it,
    /// for [`crate::LogRecords::writer`]'s reason.
    #[must_use]
    pub const fn requester<'chan>(
        &'chan self,
        reply: &'chan ConfigReply,
    ) -> ConfigRequester<'chan> {
        ConfigRequester {
            request: self,
            reply: PeerReply::new(reply),
            sequence: 0,
            faults: 0,
        }
    }
}

impl Default for ConfigRequest {
    fn default() -> Self {
        Self::zero()
    }
}

/// The reply region: what became of a submission, or the running document. The
/// configuration domain maps this read-write and management read-only.
///
/// Private for [`ConfigRequest`]'s reason.
#[repr(C)]
pub struct ConfigReply {
    sequence: AtomicU32,
    status: AtomicU32,
    /// The generation in force after the operation, whatever the operation was.
    generation: AtomicU32,
    /// The reject reason's own bits, meaningful only under
    /// [`ConfigStatus::Rejected`].
    reason: AtomicU32,
    /// The number `reason` names — a byte position in the document, or an object's
    /// index.
    detail: AtomicU32,
    /// Values a commit moved, meaningful only under [`ConfigStatus::Applied`].
    changes: AtomicU32,
    len: AtomicU32,
    /// Alignment only, on [`ConfigRequest::_pad`]'s terms.
    _pad: AtomicU32,
    document: [AtomicU8; MAX_DOCUMENT_BYTES],
}

impl ConfigReply {
    /// As [`ConfigRequest::zero`]. Sequence zero answers no request, so a zeroed
    /// reply is never mistaken for one.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            status: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            reason: AtomicU32::new(0),
            detail: AtomicU32::new(0),
            changes: AtomicU32::new(0),
            len: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
            document: [const { AtomicU8::new(0) }; MAX_DOCUMENT_BYTES],
        }
    }

    /// Take the answering side's handle: this region to write, management's
    /// request to read. On [`ConfigRequest::requester`]'s terms.
    #[must_use]
    pub const fn responder<'chan>(
        &'chan self,
        request: &'chan ConfigRequest,
    ) -> ConfigResponder<'chan> {
        ConfigResponder {
            reply: self,
            request: PeerRequest::new(request),
            served: 0,
        }
    }
}

impl Default for ConfigReply {
    fn default() -> Self {
        Self::zero()
    }
}

/// Each side's view of the region it reads and may not write.
///
/// A module of their own, on [`crate::download`]'s terms: the borrow each view
/// wraps is private to it, so nothing outside — including the two handles in the
/// parent — can reach past a view to the region behind it.
mod peer {
    use core::sync::atomic::Ordering;

    use super::{ConfigReply, ConfigRequest};

    /// The reply region as management holds it: loads only.
    pub(super) struct PeerReply<'chan>(&'chan ConfigReply);

    impl<'chan> PeerReply<'chan> {
        pub(super) const fn new(reply: &'chan ConfigReply) -> Self {
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

        pub(super) fn generation(&self) -> u32 {
            self.0.generation.load(Ordering::Relaxed)
        }

        pub(super) fn reason(&self) -> u32 {
            self.0.reason.load(Ordering::Relaxed)
        }

        pub(super) fn detail(&self) -> u32 {
            self.0.detail.load(Ordering::Relaxed)
        }

        pub(super) fn changes(&self) -> u32 {
            self.0.changes.load(Ordering::Relaxed)
        }

        pub(super) fn len(&self) -> u32 {
            self.0.len.load(Ordering::Relaxed)
        }

        /// Bounded by `into`, whose length the caller took from the published
        /// length after checking it against the region: `zip` walks the shorter
        /// of the two, so no index is taken.
        pub(super) fn copy_into(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.document) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }
    }

    /// The request region as the deciding domain holds it, on [`PeerReply`]'s
    /// terms.
    pub(super) struct PeerRequest<'chan>(&'chan ConfigRequest);

    impl<'chan> PeerRequest<'chan> {
        pub(super) const fn new(request: &'chan ConfigRequest) -> Self {
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

        pub(super) fn generation(&self) -> u32 {
            self.0.generation.load(Ordering::Relaxed)
        }

        pub(super) fn copy_into(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.document) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }
    }
}

use peer::{PeerReply, PeerRequest};

/// A request the requester has issued and not yet had answered.
///
/// Neither `Copy` nor `Clone`, and produced only by [`ConfigRequester::submit`]
/// and [`ConfigRequester::read`]: the sequence number a reply must match cannot
/// be conjured, duplicated, or kept across an answer, so "believe only the reply
/// to the request you made" is a property of the type rather than a discipline.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a request nothing polls is a submission that never completes"]
pub struct PendingConfigRequest {
    sequence: u32,
    operation: ConfigOperation,
}

impl PendingConfigRequest {
    /// The number the reply must echo. For an operator report; nothing decides
    /// under it, because the deciding is [`ConfigRequester::poll`]'s.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// What was asked, so an answer of the wrong shape is a fault rather than a
    /// value.
    #[must_use]
    pub const fn operation(&self) -> ConfigOperation {
        self.operation
    }
}

/// A reply the responder's bytes cannot be. Each one consumes the
/// [`PendingConfigRequest`] it was raised against: a peer that answered with
/// nonsense will not answer better on a second look, and the request has to be
/// made again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigFault {
    /// A status word outside [`ConfigStatus`].
    StatusUnknown { status: u32 },
    /// More bytes claimed than the region holds. The one fault that would be a
    /// read past the region if it were believed.
    LenPastRegion { len: u32 },
    /// A status that carries no document, carrying bytes.
    BytesWithoutADocument { status: ConfigStatus, len: u32 },
    /// A document answering a submission, or a generation answering a read: an
    /// answer to a question nobody asked.
    AnswersAnotherOperation {
        status: ConfigStatus,
        operation: ConfigOperation,
    },
}

/// What [`ConfigRequester::poll`] found.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the pending request is returned inside this and is lost if dropped"]
pub enum ConfigPoll<'buf> {
    /// No reply to *this* request yet — either the deciding domain has not
    /// answered or what is in the region answers something else. The handle comes
    /// back so the caller can poll again; this is one attempt, and a caller that
    /// spins on it has written the unbounded loop the single attempt exists to
    /// avoid.
    Outstanding(PendingConfigRequest),
    /// The document committed and the configuration moved to `generation`.
    Applied { generation: u32, changes: u32 },
    /// The document committed and was already running, so `generation` is the one
    /// that was already in force.
    Unchanged { generation: u32 },
    /// The document was refused and `generation` is still running.
    Rejected {
        generation: u32,
        /// The reject reason's own bits. Left undecoded here because the
        /// vocabulary is the log crate's and this one lays out regions; the
        /// caller that renders a token is the caller that has it.
        reason: u32,
        detail: u32,
    },
    /// Every rule passed and there was no generation left to assign.
    Exhausted { generation: u32 },
    /// The running document, already bounded by what the region holds.
    Document { generation: u32, bytes: &'buf [u8] },
    /// The document passed every rule and is the candidate; `generation` is what a
    /// commit of it would assign.
    Staged { generation: u32 },
    /// The provisional commit is permanent and `generation` is in force.
    Confirmed { generation: u32 },
    /// What the provisional commit replaced is in force again, under
    /// `generation`.
    RolledBack { generation: u32 },
    /// A commit with nothing staged; `generation` is still running.
    NoCandidate { generation: u32 },
    /// A confirmation or a rollback with no provisional commit outstanding;
    /// `generation` is still running.
    NotProvisional { generation: u32 },
    /// The generation the request named is not the one the operation acts on;
    /// `generation` is the one the appliance holds.
    GenerationMismatch { generation: u32 },
    /// The operation word named no operation.
    NoSuchOperation,
    /// The reply carried this request's sequence and could not be believed.
    Faulted(ConfigFault),
}

/// The asking side, holding its own sequence and fault tally in private memory.
pub struct ConfigRequester<'chan> {
    request: &'chan ConfigRequest,
    reply: PeerReply<'chan>,
    /// Private, and never read back from the region, on
    /// [`crate::DownloadRequester`]'s terms: a number this side read out of
    /// shared memory could be walked backwards by the peer, which would let an
    /// old reply match a new request.
    sequence: u32,
    faults: u32,
}

impl ConfigRequester<'_> {
    /// Bytes one request or one reply can carry, whatever is asked for.
    #[must_use]
    pub const fn document_capacity(&self) -> usize {
        MAX_DOCUMENT_BYTES
    }

    /// Submit `document` and take the handle its answer must be claimed with.
    ///
    /// `document` is **truncated** to [`MAX_DOCUMENT_BYTES`] rather than refused,
    /// and that is safe rather than lossy: the deciding domain refuses a document
    /// it cannot read, and the caller has already refused a body longer than this
    /// before a byte of it was accepted. Truncating here is what keeps the region
    /// bound the memory-safety one and leaves the protocol bound where the client
    /// is answered.
    ///
    /// Issuing a second request abandons the first, on
    /// [`crate::DownloadRequester::request`]'s terms.
    pub fn submit(&mut self, document: &[u8]) -> PendingConfigRequest {
        self.issue_document(ConfigOperation::Submit, document)
    }

    /// Ask for the running document.
    ///
    /// The length word is cleared rather than left as the previous request's: the
    /// deciding domain reads it whatever the operation, and a stale length would
    /// have it copy out bytes no request put there.
    pub fn read(&mut self) -> PendingConfigRequest {
        self.issue(ConfigOperation::Read, 0)
    }

    /// Hold `document` as the candidate and validate it, committing nothing.
    ///
    /// Truncated to the region on [`Self::submit`]'s terms.
    pub fn stage(&mut self, document: &[u8]) -> PendingConfigRequest {
        self.issue_document(ConfigOperation::Stage, document)
    }

    /// Commit the candidate `generation` names, provisionally.
    pub fn commit(&mut self, generation: u32) -> PendingConfigRequest {
        self.issue(ConfigOperation::Commit, generation)
    }

    /// Keep the provisional commit `generation` names.
    pub fn confirm(&mut self, generation: u32) -> PendingConfigRequest {
        self.issue(ConfigOperation::Confirm, generation)
    }

    /// Put back whatever the outstanding provisional commit replaced.
    pub fn roll_back(&mut self) -> PendingConfigRequest {
        self.issue(ConfigOperation::Rollback, 0)
    }

    /// Publish `document` and issue `operation` over it.
    fn issue_document(
        &mut self,
        operation: ConfigOperation,
        document: &[u8],
    ) -> PendingConfigRequest {
        let published = self.publish_document(document);
        self.request.len.store(published, Ordering::Relaxed);
        self.issue(operation, 0)
    }

    /// Look once for the answer to `pending`, copying any document into `into`.
    ///
    /// The sequence is read **before** anything else and with `Acquire`, which is
    /// what makes the responder's bytes visible before they are copied; a
    /// mismatch returns the handle and reads nothing at all, so a reply to
    /// another request cannot be partially believed.
    ///
    /// `into` is a whole region-length array rather than a slice, which removes a
    /// "buffer too small" case from the signature: the only length that can be
    /// wrong is the peer's, and it is refused by the slicing that bounds the
    /// copy.
    pub fn poll<'buf>(
        &mut self,
        pending: PendingConfigRequest,
        into: &'buf mut [u8; MAX_DOCUMENT_BYTES],
    ) -> ConfigPoll<'buf> {
        if self.reply.sequence() != pending.sequence {
            return ConfigPoll::Outstanding(pending);
        }
        let raw_status = self.reply.status();
        let Some(status) = ConfigStatus::from_bits(raw_status) else {
            return self.fault(ConfigFault::StatusUnknown { status: raw_status });
        };
        let len = self.reply.len();
        // The region bound and the copy's destination are one operation, so the
        // check cannot drift from the slice it protects.
        let Some(target) = into.get_mut(..len as usize) else {
            return self.fault(ConfigFault::LenPastRegion { len });
        };
        if status == ConfigStatus::NoSuchOperation {
            if len != 0 {
                return self.fault(ConfigFault::BytesWithoutADocument { status, len });
            }
            return ConfigPoll::NoSuchOperation;
        }
        if !status.answers(pending.operation) {
            return self.fault(ConfigFault::AnswersAnotherOperation {
                status,
                operation: pending.operation,
            });
        }
        let generation = self.reply.generation();
        if status == ConfigStatus::Document {
            self.reply.copy_into(target);
            return ConfigPoll::Document {
                generation,
                bytes: target,
            };
        }
        if len != 0 {
            return self.fault(ConfigFault::BytesWithoutADocument { status, len });
        }
        match status {
            ConfigStatus::Applied => ConfigPoll::Applied {
                generation,
                changes: self.reply.changes(),
            },
            ConfigStatus::Unchanged => ConfigPoll::Unchanged { generation },
            ConfigStatus::Rejected => ConfigPoll::Rejected {
                generation,
                reason: self.reply.reason(),
                detail: self.reply.detail(),
            },
            ConfigStatus::Exhausted => ConfigPoll::Exhausted { generation },
            ConfigStatus::Staged => ConfigPoll::Staged { generation },
            ConfigStatus::Confirmed => ConfigPoll::Confirmed { generation },
            ConfigStatus::RolledBack => ConfigPoll::RolledBack { generation },
            ConfigStatus::NoCandidate => ConfigPoll::NoCandidate { generation },
            ConfigStatus::NotProvisional => ConfigPoll::NotProvisional { generation },
            ConfigStatus::GenerationMismatch => ConfigPoll::GenerationMismatch { generation },
            // Unreachable: both are decided above, and `answers` has already
            // refused a `Document` answering anything but a read.
            ConfigStatus::Document | ConfigStatus::NoSuchOperation => {
                self.fault(ConfigFault::AnswersAnotherOperation {
                    status,
                    operation: pending.operation,
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

    /// The number the outstanding request carries, or the last one issued.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Copy at most [`MAX_DOCUMENT_BYTES`] of `document` into the region and
    /// answer how many crossed. `zip` walks the shorter of the two, so no index
    /// is taken.
    fn publish_document(&self, document: &[u8]) -> u32 {
        let mut published = 0u32;
        for (cell, byte) in self.request.document.iter().zip(document) {
            cell.store(*byte, Ordering::Relaxed);
            published = published.saturating_add(1);
        }
        published
    }

    fn issue(&mut self, operation: ConfigOperation, generation: u32) -> PendingConfigRequest {
        // Zero is *no request*, so it is stepped over rather than used: a wrapped
        // sequence must still name a request the responder can answer.
        self.sequence = match self.sequence.wrapping_add(1) {
            0 => 1,
            next => next,
        };
        // Cleared for every operation that reads no document, so a length left
        // over from the last request cannot have the deciding domain copy out
        // bytes this one did not put there.
        if !operation.carries_a_document() {
            self.request.len.store(0, Ordering::Relaxed);
        }
        self.request.generation.store(generation, Ordering::Relaxed);
        self.request
            .operation
            .store(operation.to_bits(), Ordering::Relaxed);
        // Release, and last: the document and the two words above it must be
        // visible to the deciding domain before the sequence that makes them a
        // request is.
        self.request
            .sequence
            .store(self.sequence, Ordering::Release);
        PendingConfigRequest {
            sequence: self.sequence,
            operation,
        }
    }

    fn fault<'buf>(&mut self, fault: ConfigFault) -> ConfigPoll<'buf> {
        self.faults = self.faults.saturating_add(1);
        ConfigPoll::Faulted(fault)
    }
}

/// A request the deciding domain has taken and not yet answered.
///
/// Consumed by every one of [`ConfigResponder`]'s answers, so one demand produces
/// exactly one reply: a second answer would publish under a sequence the
/// requester has already read.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a demand nothing answers leaves the requester waiting"]
pub struct ConfigDemand {
    sequence: u32,
    operation: Option<ConfigOperation>,
    len: u32,
    generation: u32,
}

impl ConfigDemand {
    /// The number this demand must be answered under.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// What was asked, or `None` where the word named no operation this appliance
    /// has — which is answered with [`ConfigStatus::NoSuchOperation`] rather than
    /// ignored, so a requester is never left unable to tell a refusal from a
    /// hang.
    #[must_use]
    pub const fn operation(&self) -> Option<ConfigOperation> {
        self.operation
    }

    /// Bytes of document the request claims, already clamped to
    /// [`MAX_DOCUMENT_BYTES`], so no request can size a copy beyond the region.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The generation this request acts on, meaningful for exactly the operations
    /// [`ConfigOperation::names_a_generation`] admits.
    ///
    /// An arbitrary number rather than a checked one: which generation the
    /// appliance would act on is the deciding domain's to know, so this is the
    /// claim and never the decision.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }
}

/// What a submission became, as the deciding domain reports it.
///
/// A type rather than four publish calls, so a status and the numbers that go
/// with it cannot be published apart: nothing here can put a reject reason on an
/// applied generation or a change count on a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigAnswer {
    Applied {
        generation: u32,
        changes: u32,
    },
    Unchanged {
        generation: u32,
    },
    Rejected {
        generation: u32,
        /// The reject reason's own bits, on [`ConfigPoll::Rejected`]'s terms.
        reason: u32,
        detail: u32,
    },
    Exhausted {
        generation: u32,
    },
    /// The document is the candidate and `generation` is what committing it would
    /// assign.
    Staged {
        generation: u32,
    },
    Confirmed {
        generation: u32,
    },
    RolledBack {
        generation: u32,
    },
    NoCandidate {
        generation: u32,
    },
    NotProvisional {
        generation: u32,
    },
    GenerationMismatch {
        generation: u32,
    },
    NoSuchOperation,
}

impl ConfigAnswer {
    #[must_use]
    const fn status(self) -> ConfigStatus {
        match self {
            Self::Applied { .. } => ConfigStatus::Applied,
            Self::Staged { .. } => ConfigStatus::Staged,
            Self::Confirmed { .. } => ConfigStatus::Confirmed,
            Self::RolledBack { .. } => ConfigStatus::RolledBack,
            Self::NoCandidate { .. } => ConfigStatus::NoCandidate,
            Self::NotProvisional { .. } => ConfigStatus::NotProvisional,
            Self::GenerationMismatch { .. } => ConfigStatus::GenerationMismatch,
            Self::Unchanged { .. } => ConfigStatus::Unchanged,
            Self::Rejected { .. } => ConfigStatus::Rejected,
            Self::Exhausted { .. } => ConfigStatus::Exhausted,
            Self::NoSuchOperation => ConfigStatus::NoSuchOperation,
        }
    }

    #[must_use]
    const fn generation(self) -> u32 {
        match self {
            Self::Applied { generation, .. }
            | Self::Unchanged { generation }
            | Self::Rejected { generation, .. }
            | Self::Exhausted { generation }
            | Self::Staged { generation }
            | Self::Confirmed { generation }
            | Self::RolledBack { generation }
            | Self::NoCandidate { generation }
            | Self::NotProvisional { generation }
            | Self::GenerationMismatch { generation } => generation,
            Self::NoSuchOperation => 0,
        }
    }

    #[must_use]
    const fn reason(self) -> u32 {
        match self {
            Self::Rejected { reason, .. } => reason,
            _ => 0,
        }
    }

    #[must_use]
    const fn detail(self) -> u32 {
        match self {
            Self::Rejected { detail, .. } => detail,
            _ => 0,
        }
    }

    #[must_use]
    const fn changes(self) -> u32 {
        match self {
            Self::Applied { changes, .. } => changes,
            _ => 0,
        }
    }
}

/// The answering side, holding the last sequence it served in private memory.
pub struct ConfigResponder<'chan> {
    reply: &'chan ConfigReply,
    request: PeerRequest<'chan>,
    /// Private, on [`ConfigRequester::sequence`]'s terms: a peer that could
    /// rewind this would have the deciding domain serve one request twice.
    served: u32,
}

impl ConfigResponder<'_> {
    /// Take the outstanding request, if there is one this responder has not
    /// already answered.
    ///
    /// `None` covers both "nothing was ever asked" — sequence zero, which is what
    /// a zeroed region holds — and "the number has not moved since the last
    /// answer". A peer that rewrites the sequence to an arbitrary value produces
    /// at most one demand per change, so a request storm costs one reply each and
    /// never an unbounded loop.
    pub fn take(&mut self) -> Option<ConfigDemand> {
        let sequence = self.request.sequence();
        if sequence == 0 || sequence == self.served {
            return None;
        }
        let raw_len = self.request.len();
        let len = if (raw_len as usize) < MAX_DOCUMENT_BYTES {
            raw_len
        } else {
            // Lossless: the bound is a `usize` constant far inside a `u32`, which
            // the assertion at the end of this module holds.
            MAX_DOCUMENT_BYTES as u32
        };
        Some(ConfigDemand {
            sequence,
            operation: ConfigOperation::from_bits(self.request.operation()),
            len,
            generation: self.request.generation(),
        })
    }

    /// Copy the submitted document out of the region, answering the prefix of
    /// `into` it filled.
    ///
    /// Copied rather than borrowed, and that is the whole of why this exists: the
    /// region is peer-written and may change under a reader, so a decision made
    /// on the bytes in place would be a decision made on bytes that are no longer
    /// there.
    pub fn document<'buf>(
        &self,
        demand: &ConfigDemand,
        into: &'buf mut [u8; MAX_DOCUMENT_BYTES],
    ) -> &'buf [u8] {
        let taken = demand.len();
        let Some(target) = into.get_mut(..taken) else {
            // Unreachable: `take` clamped the length to the array's own size.
            return &[];
        };
        self.request.copy_into(target);
        target
    }

    /// Answer `demand` with the running document.
    ///
    /// `document` is truncated to the region, on
    /// [`ConfigRequester::submit`]'s terms; the caller has already refused a
    /// configuration whose rendering would not fit, so the truncation is the
    /// memory-safety bound and not a behaviour.
    pub fn deliver(&mut self, demand: ConfigDemand, generation: u32, document: &[u8]) {
        let published = self.publish_document(document);
        self.reply.len.store(published, Ordering::Relaxed);
        self.publish(demand, ConfigStatus::Document, generation, 0, 0, 0);
    }

    /// Answer `demand` with what became of the submission. Publishes a zero
    /// length, which is what makes [`ConfigFault::BytesWithoutADocument`] a fault
    /// the requester can raise against a peer that does otherwise.
    pub fn answer(&mut self, demand: ConfigDemand, answer: ConfigAnswer) {
        self.reply.len.store(0, Ordering::Relaxed);
        self.publish(
            demand,
            answer.status(),
            answer.generation(),
            answer.reason(),
            answer.detail(),
            answer.changes(),
        );
    }

    /// Requests this responder has answered, by the number of the last one.
    #[must_use]
    pub const fn served(&self) -> u32 {
        self.served
    }

    fn publish_document(&self, document: &[u8]) -> u32 {
        let mut published = 0u32;
        for (cell, byte) in self.reply.document.iter().zip(document) {
            cell.store(*byte, Ordering::Relaxed);
            published = published.saturating_add(1);
        }
        published
    }

    fn publish(
        &mut self,
        demand: ConfigDemand,
        status: ConfigStatus,
        generation: u32,
        reason: u32,
        detail: u32,
        changes: u32,
    ) {
        self.reply.status.store(status.to_bits(), Ordering::Relaxed);
        self.reply.generation.store(generation, Ordering::Relaxed);
        self.reply.reason.store(reason, Ordering::Relaxed);
        self.reply.detail.store(detail, Ordering::Relaxed);
        self.reply.changes.store(changes, Ordering::Relaxed);
        self.served = demand.sequence;
        // Release, and last: the document and the six words above it must be
        // visible to management before the sequence that claims them as this
        // request's answer is. Reversing the two is what would let a requester
        // copy out a half-written document and believe it.
        self.reply
            .sequence
            .store(demand.sequence, Ordering::Release);
    }
}

// Two cross-PD shared-memory ABIs: pin both layouts so a field reorder or a size
// change is a compile error rather than a silently corrupted mapping.
const _: () = {
    use core::mem::{align_of, offset_of};

    // Every published length is compared as a `u32` and then used as a `usize`,
    // which is exact only while a `usize` is at least as wide; x86_64's is.
    assert!(size_of::<usize>() >= size_of::<u32>());
    assert!(MAX_DOCUMENT_BYTES <= u32::MAX as usize);
    assert!(MAX_DOCUMENT_BYTES > 0);
    // A zeroed pair of regions is the valid idle state: sequence zero is no
    // request and answers none, so neither side acts on what the kernel handed
    // it. That the zero status and the zero operation happen to be meaningful
    // values is harmless because no sequence ever matches them.
    assert!(ConfigOperation::Submit.to_bits() == 0);
    assert!(ConfigStatus::Applied.to_bits() == 0);
    // Both vocabularies run from zero with no gap, so their extent is a fact
    // about the two arrays rather than about a reading of the matches above.
    let mut index = 0;
    while index < ConfigOperation::ALL.len() {
        assert!(ConfigOperation::ALL[index].to_bits() as usize == index);
        index += 1;
    }
    assert!(ConfigOperation::from_bits(ConfigOperation::ALL.len() as u32).is_none());
    let mut index = 0;
    while index < ConfigStatus::ALL.len() {
        assert!(ConfigStatus::ALL[index].to_bits() as usize == index);
        index += 1;
    }
    assert!(ConfigStatus::from_bits(ConfigStatus::ALL.len() as u32).is_none());
    // The cross-field rule, held where both halves are visible. Every operation
    // has at least one status that answers it, so no request can be issued that
    // the responder has no admissible answer for.
    assert!(ConfigStatus::Document.answers(ConfigOperation::Read));
    assert!(!ConfigStatus::Document.answers(ConfigOperation::Submit));
    assert!(ConfigStatus::Applied.answers(ConfigOperation::Submit));
    assert!(ConfigStatus::Applied.answers(ConfigOperation::Commit));
    assert!(!ConfigStatus::Applied.answers(ConfigOperation::Read));
    assert!(!ConfigStatus::NoSuchOperation.answers(ConfigOperation::Read));
    assert!(ConfigStatus::Staged.answers(ConfigOperation::Stage));
    assert!(!ConfigStatus::Staged.answers(ConfigOperation::Submit));
    assert!(ConfigStatus::Confirmed.answers(ConfigOperation::Confirm));
    assert!(ConfigStatus::RolledBack.answers(ConfigOperation::Rollback));
    let mut index = 0;
    while index < ConfigOperation::ALL.len() {
        let operation = ConfigOperation::ALL[index];
        let mut answered = false;
        let mut status = 0;
        while status < ConfigStatus::ALL.len() {
            if ConfigStatus::ALL[status].answers(operation) {
                answered = true;
            }
            status += 1;
        }
        assert!(answered);
        index += 1;
    }

    assert!(offset_of!(ConfigRequest, sequence) == 0);
    assert!(offset_of!(ConfigRequest, operation) == 4);
    assert!(offset_of!(ConfigRequest, len) == 8);
    assert!(offset_of!(ConfigRequest, generation) == 12);
    assert!(offset_of!(ConfigRequest, document) == 16);
    assert!(align_of::<ConfigRequest>() == 4);
    assert!(size_of::<ConfigRequest>() == 16 + MAX_DOCUMENT_BYTES);

    assert!(offset_of!(ConfigReply, sequence) == 0);
    assert!(offset_of!(ConfigReply, status) == 4);
    assert!(offset_of!(ConfigReply, generation) == 8);
    assert!(offset_of!(ConfigReply, reason) == 12);
    assert!(offset_of!(ConfigReply, detail) == 16);
    assert!(offset_of!(ConfigReply, changes) == 20);
    assert!(offset_of!(ConfigReply, len) == 24);
    assert!(offset_of!(ConfigReply, _pad) == 28);
    assert!(offset_of!(ConfigReply, document) == 32);
    assert!(align_of::<ConfigReply>() == 4);
    assert!(size_of::<ConfigReply>() == 32 + MAX_DOCUMENT_BYTES);

    // Each region must hold its type and be mappable.
    assert!(CONFIG_REQUEST_REGION_SIZE >= size_of::<ConfigRequest>());
    assert!(CONFIG_REQUEST_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(CONFIG_REPLY_REGION_SIZE >= size_of::<ConfigReply>());
    assert!(CONFIG_REPLY_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
