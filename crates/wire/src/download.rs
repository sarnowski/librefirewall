//! The recording download channel: a one-outstanding-request window through
//! which the management domain reads a recording sink it cannot reach itself.
//!
//! Faces the byzantine peer protection domain (CONCEPT §7.1) from both sides,
//! and behind the responder the block device — a hostile or malfunctioning
//! device (§7.1) one indirection away, since what the recorder publishes here
//! is what that medium returned. Nothing on this side judges the bytes: whether
//! a window is a valid pcapng segment is the reader's question, and it is asked
//! of an artifact rather than of a region.
//!
//! # Why the channel exists at all
//!
//! The recorder owns the block device and is the only domain that can read the
//! rings on it (CONCEPT §15). The management domain serves `GET` of a recording
//! as pcapng (§12) and owns no storage capability. Handing management the
//! device instead would put an HTTP surface on the same domain as the medium
//! holding every recorded payload, which is the one grant this split exists to
//! withhold.
//!
//! # Two regions, because a region is the unit of grant
//!
//! [`DownloadRequest`] is management's to write and the recorder's to read;
//! [`DownloadReply`] is the reverse. [`crate::LogRecords`]'s split, and here the
//! asymmetry is what keeps management from writing the window it then reads back
//! — a domain that could forge a reply could serve an operator a recording the
//! appliance never made, which is a fabricated evidence artifact rather than
//! merely a wrong answer.
//!
//! The handles carry that asymmetry rather than restating it: each reaches the
//! other's region only through a view with no store on it (DOC-9).
//!
//! # The sequence number is the whole correlation
//!
//! Nothing else says a reply belongs to a request. The requester increments the
//! number and the responder echoes it, and a reply carrying any other number is
//! **ignored entirely** — never read for a status, never read for a length,
//! never partially believed. Zero is reserved for *no request*, so a zeroed pair
//! of regions is a channel with nothing outstanding rather than a request the
//! recorder is expected to answer.
//!
//! [`PendingDownload`] is what makes that hard to get wrong. It is not `Copy`, it is
//! returned by [`DownloadRequester::request`] alone, and [`poll`] takes it **by
//! value** — so the reply cannot be looked at without giving up the handle, and
//! the handle only comes back when there was nothing to look at. A caller cannot
//! read a window it never asked for, because it has no way to name one.
//!
//! # One request in flight, which is what makes a single fence enough
//!
//! The responder publishes the window and then the sequence, `Release`; the
//! requester reads the sequence and then the window, `Acquire`. That pair alone
//! would not stop a torn read against a writer free to publish whenever it
//! liked — [`crate::ClockCalibration`] needs a seqlock for exactly that reason.
//! It is enough here because the protocol admits only one outstanding request:
//! the responder writes only in answer to a demand it took, and cannot take
//! another until the requester issues one, which a requester holding a
//! [`PendingDownload`] has not done. So between the sequence becoming visible and the
//! requester finishing its copy there is, from a peer keeping to the protocol,
//! no second write.
//!
//! A peer *not* keeping to it can write mid-copy and hand management a window
//! spliced out of two answers. That is bounded, in-region and panic-free, and it
//! is a recorder corrupting the artifact it is itself the sole authority for —
//! the shape a component harming only what it already owns should have.
//!
//! # What each side still achieves against the other
//!
//! * **A hostile requester wastes the recorder's time and nothing else.** Its
//!   offset and sink are read as claims; its length is clamped to the window by
//!   [`DownloadDemand::len`] before the recorder can size a read from it.
//! * **A hostile responder cannot make management read past the window.** The
//!   published length is checked against the window and against what was
//!   actually asked for, and both refusals are counted (ENG-4).
//! * **A status outside the closed set is a fault, not a success.** There is no
//!   value of the word that means "assume it worked".

use core::{
    mem::size_of,
    sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
};

use crate::MAPPING_ALIGN;

/// Bytes of the snapshot one reply carries.
///
/// 32 KiB, and the number is a balance between two costs that pull opposite
/// ways. Smaller multiplies round trips over a whole ring — a gigabyte-scale
/// recording at 4 KiB is a quarter of a million request/reply exchanges, each
/// one a notification and a scheduling round for two domains. Larger buys
/// nothing on a path that is not hot: a download is an operator action, not
/// dataplane work, and the region is resident for the appliance's whole life
/// whether anyone is downloading or not.
///
/// 32 KiB is also comfortably above the largest segment the recorder writes, so
/// no single pcapng block is split across more windows than the reader would
/// have to join anyway.
///
/// The reply region then rounds to nine pages, of which the last holds only the
/// header and slack. A window sized to make the region exactly eight would have
/// to be `32768` minus the header's size — a number every implementation of
/// either side would have to reproduce, and would have to change whenever a
/// header field did. One page is cheaper than that.
pub const DOWNLOAD_WINDOW_LEN: usize = 32 * 1024;

/// Bytes the system description reserves for the request region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const DOWNLOAD_REQUEST_REGION_SIZE: usize =
    size_of::<DownloadRequest>().next_multiple_of(MAPPING_ALIGN);

/// As [`DOWNLOAD_REQUEST_REGION_SIZE`], for the direction carrying the window.
pub const DOWNLOAD_REPLY_REGION_SIZE: usize =
    size_of::<DownloadReply>().next_multiple_of(MAPPING_ALIGN);

/// Which recording a request names.
///
/// The two sinks of CONCEPT §15.1, and the reason there are exactly two is
/// there: they are separate rings because their rates differ by three to four
/// orders of magnitude, so a traffic burst cannot evict connection history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadSink {
    /// Always on, every interface, no filter: connection lifecycle and policy
    /// decisions with their causing packet's headers. Breadth.
    Log,
    /// Filtered, full packet content. Depth.
    Capture,
}

impl DownloadSink {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Log => 0,
            Self::Capture => 1,
        }
    }

    /// `None` for every other bit pattern, on [`crate::Verdict::from_bits`]'s
    /// terms: the field is peer-written, so an undecodable value is input to
    /// reject rather than one to coerce. The recorder answers such a request
    /// with [`DownloadRefusal::NoSuchSink`] rather than ignoring it, because a
    /// requester left waiting cannot tell a refusal from a hang.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Log),
            1 => Some(Self::Capture),
            _ => None,
        }
    }
}

/// The status word of a reply, as it appears in the region.
///
/// The decoded form is [`DownloadPoll`], which splits this into the case that
/// carries bytes and the cases that cannot — so a refusal accompanied by a
/// length is a fault rather than something a caller has to remember not to read
/// (DOC-9). This enum is the wire encoding, and exists in the public surface
/// because an implementation of either side needs the numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadStatus {
    /// The window holds the requested bytes.
    Ok,
    /// No snapshot to read yet: the sink is enabled but has not been bound to
    /// an extent, or the recorder has not finished coming up.
    NotReady,
    /// The offset is past the end of the snapshot.
    OutOfRange,
    /// The ring wrapped past the offset while it was being read, so the bytes
    /// that were there are gone. Distinct from [`Self::OutOfRange`] because an
    /// operator acts on the two differently: one is a bad request, the other is
    /// a download that could not keep up with the traffic.
    Overrun,
    /// The medium refused the read.
    DeviceError,
    /// The request named no sink this appliance has.
    NoSuchSink,
}

impl DownloadStatus {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::NotReady => 1,
            Self::OutOfRange => 2,
            Self::Overrun => 3,
            Self::DeviceError => 4,
            Self::NoSuchSink => 5,
        }
    }

    /// `None` for every other bit pattern, on [`DownloadSink::from_bits`]'s
    /// terms. There is deliberately no value that means "assume it worked".
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Ok),
            1 => Some(Self::NotReady),
            2 => Some(Self::OutOfRange),
            3 => Some(Self::Overrun),
            4 => Some(Self::DeviceError),
            5 => Some(Self::NoSuchSink),
            _ => None,
        }
    }
}

/// [`DownloadStatus`] without its success, which is what a refusal can be.
///
/// A separate type so [`DownloadResponder::refuse`] cannot publish a success
/// and [`DownloadPoll::Refused`] cannot carry one — the encoding's one word
/// becomes two shapes that mean different things (DOC-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadRefusal {
    NotReady,
    OutOfRange,
    Overrun,
    DeviceError,
    NoSuchSink,
}

impl DownloadRefusal {
    #[must_use]
    pub const fn to_status(self) -> DownloadStatus {
        match self {
            Self::NotReady => DownloadStatus::NotReady,
            Self::OutOfRange => DownloadStatus::OutOfRange,
            Self::Overrun => DownloadStatus::Overrun,
            Self::DeviceError => DownloadStatus::DeviceError,
            Self::NoSuchSink => DownloadStatus::NoSuchSink,
        }
    }

    /// `None` for [`DownloadStatus::Ok`], which is the point of the type.
    #[must_use]
    pub const fn from_status(status: DownloadStatus) -> Option<Self> {
        match status {
            DownloadStatus::Ok => None,
            DownloadStatus::NotReady => Some(Self::NotReady),
            DownloadStatus::OutOfRange => Some(Self::OutOfRange),
            DownloadStatus::Overrun => Some(Self::Overrun),
            DownloadStatus::DeviceError => Some(Self::DeviceError),
            DownloadStatus::NoSuchSink => Some(Self::NoSuchSink),
        }
    }
}

/// The request region: what management is asking for. Management maps this
/// read-write and the recorder read-only.
///
/// Every field is private and no accessor reaches one, so the ordering each
/// word carries is a property of this type rather than a convention its two
/// domains are asked to keep (DOC-9).
#[repr(C)]
pub struct DownloadRequest {
    sequence: AtomicU32,
    sink: AtomicU32,
    offset: AtomicU64,
    len: AtomicU32,
    /// Alignment only. Nothing is placed here and nothing reads it, so the
    /// bytes a peer leaves in it name nothing — unlike [`crate::TapAnnotation`]'s
    /// reserved words, which are held at zero because they are expected to be
    /// given a meaning.
    _pad: AtomicU32,
}

impl DownloadRequest {
    /// A zeroed region, which is what the kernel hands a domain that maps one:
    /// sequence zero is *no request*, so nothing is outstanding.
    ///
    /// A function rather than a `const`: a `const` holding an atomic is copied
    /// at each mention, so a store through one is read back by nobody.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            sink: AtomicU32::new(0),
            offset: AtomicU64::new(0),
            len: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
        }
    }

    /// Take the asking side's handle: this region to write, the recorder's
    /// reply to read.
    ///
    /// Take it **once** per channel and keep it: a second restarts at sequence
    /// zero and would reuse numbers the first has outstanding. No type stops it,
    /// for [`crate::LogRecords::writer`]'s reason.
    #[must_use]
    pub const fn requester<'chan>(
        &'chan self,
        reply: &'chan DownloadReply,
    ) -> DownloadRequester<'chan> {
        DownloadRequester {
            request: self,
            reply: PeerReply::new(reply),
            sequence: 0,
            faults: 0,
        }
    }
}

impl Default for DownloadRequest {
    fn default() -> Self {
        Self::zero()
    }
}

/// The reply region: the window and what to make of it. The recorder maps this
/// read-write and management read-only.
///
/// Private for [`DownloadRequest`]'s reason.
#[repr(C)]
pub struct DownloadReply {
    sequence: AtomicU32,
    status: AtomicU32,
    len: AtomicU32,
    /// Alignment only, on [`DownloadRequest::_pad`]'s terms.
    _pad: AtomicU32,
    total_len: AtomicU64,
    /// One atomic per byte rather than packed into words, for
    /// the tap ring's reason: these are bytes off a medium, so packing them
    /// would make the byte order of the region a thing this crate chooses
    /// rather than a thing it mirrors.
    bytes: [AtomicU8; DOWNLOAD_WINDOW_LEN],
}

impl DownloadReply {
    /// As [`DownloadRequest::zero`]. Sequence zero answers no request, so a
    /// zeroed reply is never mistaken for one.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            status: AtomicU32::new(0),
            len: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
            total_len: AtomicU64::new(0),
            bytes: [const { AtomicU8::new(0) }; DOWNLOAD_WINDOW_LEN],
        }
    }

    /// Take the answering side's handle: this region to write, management's
    /// request to read. On [`DownloadRequest::requester`]'s terms.
    #[must_use]
    pub const fn responder<'chan>(
        &'chan self,
        request: &'chan DownloadRequest,
    ) -> DownloadResponder<'chan> {
        DownloadResponder {
            reply: self,
            request: PeerRequest::new(request),
            served: 0,
        }
    }
}

impl Default for DownloadReply {
    fn default() -> Self {
        Self::zero()
    }
}

/// Each side's view of the region it reads and may not write.
///
/// A module of their own, and that is the whole mechanism: the borrow each view
/// wraps is private to it, so nothing outside — including the two handles in the
/// parent — can reach past a view to the region behind it (DOC-9).
mod peer {
    use core::sync::atomic::Ordering;

    use super::{DownloadReply, DownloadRequest};

    /// The reply region as management holds it: loads only.
    pub(super) struct PeerReply<'chan>(&'chan DownloadReply);

    impl<'chan> PeerReply<'chan> {
        pub(super) const fn new(reply: &'chan DownloadReply) -> Self {
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

        pub(super) fn len(&self) -> u32 {
            self.0.len.load(Ordering::Relaxed)
        }

        pub(super) fn total_len(&self) -> u64 {
            self.0.total_len.load(Ordering::Relaxed)
        }

        /// Bounded by `into`, which the caller obtained from the window's own
        /// length: `zip` walks the shorter of the two, so no index is taken.
        pub(super) fn copy_into(&self, into: &mut [u8]) {
            for (byte, cell) in into.iter_mut().zip(&self.0.bytes) {
                *byte = cell.load(Ordering::Relaxed);
            }
        }
    }

    /// The request region as the recorder holds it, on [`PeerReply`]'s terms.
    pub(super) struct PeerRequest<'chan>(&'chan DownloadRequest);

    impl<'chan> PeerRequest<'chan> {
        pub(super) const fn new(request: &'chan DownloadRequest) -> Self {
            Self(request)
        }

        /// Acquire, and read first, for [`PeerReply::sequence`]'s reason with
        /// the directions exchanged.
        pub(super) fn sequence(&self) -> u32 {
            self.0.sequence.load(Ordering::Acquire)
        }

        pub(super) fn sink(&self) -> u32 {
            self.0.sink.load(Ordering::Relaxed)
        }

        pub(super) fn offset(&self) -> u64 {
            self.0.offset.load(Ordering::Relaxed)
        }

        pub(super) fn len(&self) -> u32 {
            self.0.len.load(Ordering::Relaxed)
        }
    }
}

use peer::{PeerReply, PeerRequest};

/// A request the requester has issued and not yet had answered.
///
/// Neither `Copy` nor `Clone`, and produced only by
/// [`DownloadRequester::request`]: the sequence number a reply must match
/// cannot be conjured, duplicated, or kept across an answer, so "believe only
/// the reply to the request you made" is a property of the type rather than a
/// discipline (DOC-9).
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a request nothing polls is a download that never completes"]
pub struct PendingDownload {
    sequence: u32,
    /// What was asked for, so a reply claiming more can be refused. The window
    /// bound is the memory-safety one; this is the protocol one.
    requested: u32,
}

impl PendingDownload {
    /// The number the reply must echo. For an operator report; nothing decides
    /// under it, because the deciding is [`DownloadRequester::poll`]'s.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Bytes this request asked for.
    #[must_use]
    pub const fn requested(&self) -> u32 {
        self.requested
    }
}

/// A reply the responder's bytes cannot be. Each one consumes the [`PendingDownload`]
/// it was raised against: a peer that answered with nonsense will not answer
/// better on a second look, and the request has to be made again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadFault {
    /// A status word outside [`DownloadStatus`].
    StatusUnknown { status: u32 },
    /// More bytes claimed than the window holds. The one fault that would be a
    /// read past the region if it were believed.
    LenPastWindow { len: u32 },
    /// More bytes claimed than were asked for.
    LenPastRequest { len: u32, requested: u32 },
    /// A refusal carrying bytes, which no answer means: a status other than
    /// [`DownloadStatus::Ok`] says the window holds nothing.
    BytesOnRefusal { status: DownloadStatus, len: u32 },
}

/// What [`DownloadRequester::poll`] found.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the pending request is returned inside this and is lost if dropped"]
pub enum DownloadPoll<'buf> {
    /// No reply to *this* request yet — either the recorder has not answered or
    /// what is in the region answers something else. The handle comes back so
    /// the caller can poll again; this is one attempt, and a caller that spins
    /// on it has written the unbounded loop the single attempt exists to avoid
    /// (ENG-4).
    Outstanding(PendingDownload),
    /// The recorder served the request. `bytes` is the window it published,
    /// already bounded by both what the window holds and what was asked for.
    Delivered {
        bytes: &'buf [u8],
        /// The snapshot's length, so a caller knows when it has read it all.
        total_len: u64,
    },
    /// The recorder answered and served nothing, saying why.
    Refused {
        reason: DownloadRefusal,
        /// The snapshot's length as the recorder knows it, which is what makes
        /// [`DownloadRefusal::OutOfRange`] actionable rather than merely a
        /// refusal.
        total_len: u64,
    },
    /// The reply carried this request's sequence and could not be believed.
    Faulted(DownloadFault),
}

/// The asking side, holding its own sequence and fault tally in private memory.
pub struct DownloadRequester<'chan> {
    request: &'chan DownloadRequest,
    reply: PeerReply<'chan>,
    /// Private, and never read back from the region: a number this side read
    /// out of shared memory could be walked backwards by the peer, which would
    /// let an old reply match a new request.
    sequence: u32,
    faults: u32,
}

impl DownloadRequester<'_> {
    /// Bytes one reply can carry, whatever is asked for.
    #[must_use]
    pub const fn window_len(&self) -> usize {
        DOWNLOAD_WINDOW_LEN
    }

    /// Ask for `len` bytes of `sink` at `offset`, and take the handle the
    /// answer must be claimed with.
    ///
    /// `len` is clamped to [`DOWNLOAD_WINDOW_LEN`] here rather than refused:
    /// asking for more than a window is not an error, it is a download that
    /// takes more than one round, and the clamp is what the [`PendingDownload`] then
    /// holds a reply to. Issuing a second request abandons the first — the
    /// responder will answer a sequence nothing is waiting on, and the old
    /// [`PendingDownload`] can then only ever come back [`DownloadPoll::Outstanding`].
    pub fn request(&mut self, sink: DownloadSink, offset: u64, len: usize) -> PendingDownload {
        let requested = if len < DOWNLOAD_WINDOW_LEN {
            // Below the window, so the cast keeps every bit.
            len as u32
        } else {
            DOWNLOAD_WINDOW_LEN as u32
        };
        // Zero is *no request*, so it is stepped over rather than used: a
        // wrapped sequence must still name a request the responder can answer.
        self.sequence = match self.sequence.wrapping_add(1) {
            0 => 1,
            next => next,
        };

        self.request.sink.store(sink.to_bits(), Ordering::Relaxed);
        self.request.offset.store(offset, Ordering::Relaxed);
        self.request.len.store(requested, Ordering::Relaxed);
        // Release, and last: the three words above must be visible to the
        // recorder before the sequence that makes them a request is.
        self.request
            .sequence
            .store(self.sequence, Ordering::Release);

        PendingDownload {
            sequence: self.sequence,
            requested,
        }
    }

    /// Look once for the answer to `pending`, copying any window into `into`.
    ///
    /// The sequence is read **before** anything else and with `Acquire`, which
    /// is what makes the responder's window visible before it is copied; a
    /// mismatch returns the handle and reads nothing at all, so a reply to
    /// another request cannot be partially believed.
    ///
    /// `into` is a whole window-length array rather than a slice, which removes
    /// a "buffer too small" case from the signature: the only length that can be
    /// wrong is the peer's, and it is refused by the slicing that bounds the
    /// copy.
    pub fn poll<'buf>(
        &mut self,
        pending: PendingDownload,
        into: &'buf mut [u8; DOWNLOAD_WINDOW_LEN],
    ) -> DownloadPoll<'buf> {
        if self.reply.sequence() != pending.sequence {
            return DownloadPoll::Outstanding(pending);
        }

        let len = self.reply.len();
        let total_len = self.reply.total_len();
        let raw_status = self.reply.status();

        let Some(status) = DownloadStatus::from_bits(raw_status) else {
            return self.fault(DownloadFault::StatusUnknown { status: raw_status });
        };
        // The window bound and the copy's destination are one operation, so the
        // check cannot drift from the slice it protects.
        let Some(target) = into.get_mut(..len as usize) else {
            return self.fault(DownloadFault::LenPastWindow { len });
        };
        if len > pending.requested {
            return self.fault(DownloadFault::LenPastRequest {
                len,
                requested: pending.requested,
            });
        }

        if let Some(reason) = DownloadRefusal::from_status(status) {
            if len != 0 {
                return self.fault(DownloadFault::BytesOnRefusal { status, len });
            }
            return DownloadPoll::Refused { reason, total_len };
        }

        self.reply.copy_into(target);
        DownloadPoll::Delivered {
            bytes: target,
            total_len,
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

    fn fault<'buf>(&mut self, fault: DownloadFault) -> DownloadPoll<'buf> {
        self.faults = self.faults.saturating_add(1);
        DownloadPoll::Faulted(fault)
    }
}

/// A request the recorder has taken and not yet answered.
///
/// Consumed by [`DownloadResponder::deliver`] and
/// [`DownloadResponder::refuse`], so one demand produces exactly one reply: a
/// second answer would publish a window under a sequence the requester has
/// already read (DOC-9).
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a demand nothing answers leaves the requester waiting"]
pub struct DownloadDemand {
    sequence: u32,
    sink: Option<DownloadSink>,
    offset: u64,
    len: u32,
}

impl DownloadDemand {
    /// The number this demand must be answered under.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Which sink was asked for, or `None` where the word named none this
    /// appliance has — which is answered with [`DownloadRefusal::NoSuchSink`]
    /// rather than ignored, so a requester is never left unable to tell a
    /// refusal from a hang.
    #[must_use]
    pub const fn sink(&self) -> Option<DownloadSink> {
        self.sink
    }

    /// Where in the snapshot to read. A claim, and the recorder's own extent is
    /// what bounds it — nothing here can, because only the recorder knows how
    /// long the snapshot is.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// How many bytes to read, already clamped to [`DOWNLOAD_WINDOW_LEN`], so
    /// no request can size a read beyond what a reply could carry (ENG-4).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The answering side, holding the last sequence it served in private memory.
pub struct DownloadResponder<'chan> {
    reply: &'chan DownloadReply,
    request: PeerRequest<'chan>,
    /// Private, on [`DownloadRequester::sequence`]'s terms: a peer that could
    /// rewind this would have the recorder serve one request twice.
    served: u32,
}

impl DownloadResponder<'_> {
    /// Bytes one reply can carry.
    #[must_use]
    pub const fn window_len(&self) -> usize {
        DOWNLOAD_WINDOW_LEN
    }

    /// Take the outstanding request, if there is one this responder has not
    /// already answered.
    ///
    /// `None` covers both "nothing was ever asked" — sequence zero, which is
    /// what a zeroed region holds — and "the number has not moved since the last
    /// answer". A peer that rewrites the sequence to an arbitrary value produces
    /// at most one demand per change, so a request storm costs one reply each
    /// and never an unbounded loop.
    pub fn take(&mut self) -> Option<DownloadDemand> {
        let sequence = self.request.sequence();
        if sequence == 0 || sequence == self.served {
            return None;
        }
        let raw_len = self.request.len();
        let len = if (raw_len as usize) < DOWNLOAD_WINDOW_LEN {
            raw_len
        } else {
            DOWNLOAD_WINDOW_LEN as u32
        };
        Some(DownloadDemand {
            sequence,
            sink: DownloadSink::from_bits(self.request.sink()),
            offset: self.request.offset(),
            len,
        })
    }

    /// Answer `demand` with `bytes`, and say how many crossed.
    ///
    /// `bytes` is truncated to what the demand asked for, which
    /// [`DownloadDemand::len`] has already bounded by the window — so a
    /// recorder handing over more than was asked publishes only what was.
    pub fn deliver(&mut self, demand: DownloadDemand, bytes: &[u8], total_len: u64) -> usize {
        let published = self.publish_bytes(demand.len(), bytes);
        self.publish(demand, DownloadStatus::Ok, published, total_len);
        published as usize
    }

    /// Answer `demand` with nothing, saying why. Publishes a zero length, which
    /// is what makes [`DownloadFault::BytesOnRefusal`] a fault the requester can
    /// raise against a peer that does otherwise.
    pub fn refuse(&mut self, demand: DownloadDemand, reason: DownloadRefusal, total_len: u64) {
        self.publish_bytes(demand.len(), &[]);
        self.publish(demand, reason.to_status(), 0, total_len);
    }

    /// Requests this responder has answered, by the number of the last one.
    #[must_use]
    pub const fn served(&self) -> u32 {
        self.served
    }

    /// Copies at most `wanted` bytes of `bytes` into the window and answers how
    /// many. `wanted` comes from a [`DownloadDemand`], so it is already within
    /// the window; `zip` then walks the shortest of the three and takes no
    /// index.
    fn publish_bytes(&self, wanted: usize, bytes: &[u8]) -> u32 {
        let mut published = 0;
        for (cell, byte) in self.reply.bytes.iter().zip(bytes).take(wanted) {
            cell.store(*byte, Ordering::Relaxed);
            published += 1;
        }
        published
    }

    fn publish(
        &mut self,
        demand: DownloadDemand,
        status: DownloadStatus,
        len: u32,
        total_len: u64,
    ) {
        self.reply.status.store(status.to_bits(), Ordering::Relaxed);
        self.reply.len.store(len, Ordering::Relaxed);
        self.reply.total_len.store(total_len, Ordering::Relaxed);
        self.served = demand.sequence;
        // Release, and last: the window and the three words above it must be
        // visible to management before the sequence that claims them as this
        // request's answer is. Reversing the two is what would let a requester
        // copy out a half-written window and believe it.
        self.reply
            .sequence
            .store(demand.sequence, Ordering::Release);
    }
}

// Two cross-PD shared-memory ABIs: pin both layouts so a field reorder or a size
// change is a compile error rather than a silently corrupted mapping (TEST-5).
const _: () = {
    use core::mem::{align_of, offset_of};

    // Every published length is compared as a `u32` and then used as a `usize`,
    // which is exact only while a `usize` is at least as wide (CONCEPT §3).
    assert!(size_of::<usize>() >= size_of::<u32>());
    assert!(DOWNLOAD_WINDOW_LEN <= u32::MAX as usize);
    assert!(DOWNLOAD_WINDOW_LEN > 0);
    // A zeroed pair of regions is the valid idle state: sequence zero is no
    // request and answers none, so neither side acts on what the kernel handed
    // it. That the zero status happens to be `Ok` is harmless because no
    // sequence ever matches it.
    assert!(DownloadStatus::Ok.to_bits() == 0);
    assert!(DownloadSink::Log.to_bits() == 0);
    assert!(DownloadRefusal::from_status(DownloadStatus::Ok).is_none());
    assert!(DownloadStatus::from_bits(6).is_none());
    assert!(DownloadSink::from_bits(2).is_none());

    assert!(size_of::<DownloadRequest>() == 24);
    assert!(align_of::<DownloadRequest>() == 8);
    assert!(offset_of!(DownloadRequest, sequence) == 0);
    assert!(offset_of!(DownloadRequest, sink) == 4);
    assert!(offset_of!(DownloadRequest, offset) == 8);
    assert!(offset_of!(DownloadRequest, len) == 16);
    assert!(offset_of!(DownloadRequest, _pad) == 20);
    // Naturally aligned, which is what makes each store and load a single
    // access rather than two a reader could tear across.
    assert!(offset_of!(DownloadRequest, offset).is_multiple_of(align_of::<u64>()));

    assert!(offset_of!(DownloadReply, sequence) == 0);
    assert!(offset_of!(DownloadReply, status) == 4);
    assert!(offset_of!(DownloadReply, len) == 8);
    assert!(offset_of!(DownloadReply, _pad) == 12);
    assert!(offset_of!(DownloadReply, total_len) == 16);
    assert!(offset_of!(DownloadReply, bytes) == 24);
    assert!(align_of::<DownloadReply>() == 8);
    assert!(offset_of!(DownloadReply, total_len).is_multiple_of(align_of::<u64>()));
    assert!(size_of::<DownloadReply>() == 24 + DOWNLOAD_WINDOW_LEN);

    // Each region must hold its type and be mappable.
    assert!(DOWNLOAD_REQUEST_REGION_SIZE >= size_of::<DownloadRequest>());
    assert!(DOWNLOAD_REQUEST_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(DOWNLOAD_REPLY_REGION_SIZE >= size_of::<DownloadReply>());
    assert!(DOWNLOAD_REPLY_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
