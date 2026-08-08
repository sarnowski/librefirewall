//! The two resources an unprovisioned appliance serves, the one it takes, and
//! the twenty-six ways a request is refused.
//!
//! # Adversary
//!
//! An **unauthenticated management-plane attacker**, directly. Every byte
//! [`Onboarding::take`] reads was chosen by whoever reached the onboarding port
//! and got a TLS session up — which anybody can, the session being what
//! authenticates the *appliance* and nothing else — and so was the pacing.
//!
//! Four consequences shape the whole of this file.
//!
//! * **The head is parsed by `lfw_http` and by nothing here.** That parser is
//!   fuzzed, total over arbitrary bytes, and already refuses the framings two
//!   parties could disagree about. What this adds is which targets exist, under
//!   which methods, and how often.
//! * **Every byte a peer sends is bounded before it is held.** The head's
//!   accumulation stops at [`REQUEST_CAPACITY`] and the request is refused
//!   there rather than waited on, so a peer that never ends a head costs a
//!   fixed array. A body is never held here at all — it goes straight to the
//!   [`Upload`] the caller supplied, whose own bound the parser has already
//!   held the declared length to.
//! * **Nothing a peer sent reaches an operator surface.** A refusal is named by
//!   a token out of a closed vocabulary and placed by numbers this appliance
//!   computed — the status it answered and the bytes it was holding. The target
//!   a peer typed is not among them, and neither is any byte of the head.
//! * **One request per connection.** Every response carries `Connection: close`
//!   and this surface answers exactly one; what follows a completed response is
//!   read and dropped rather than parsed, so a peer cannot pipeline a second
//!   request onto a session already committed to an answer.
//!
//! # The head is filled first and parsed afterwards
//!
//! One TLS delivery can be tens of kibibytes, and a package upload's first one
//! carries a head and a great deal of body. So what arrives is copied into the
//! head buffer up to its bound and *then* parsed, and the head is refused for
//! being too long only when the buffer is full and the head still has not
//! ended. Refusing on the arithmetic instead — the way a surface that took no
//! body could — would answer a legitimate upload's very first delivery with
//! "your headers are too large", which is both wrong and unactionable.
//!
//! # Closed for good, once this appliance has an owner
//!
//! The surface is constructed closed when the domain that holds the device key
//! says the record on its medium names an owner, and it closes itself the
//! moment an upload is installed. Both are the same statement made at two
//! ranges: **an onboarded appliance serves no onboarding.** The durable half is
//! the first one — the fact is read off the medium on every boot, so the close
//! is not a flag a restart clears.
//!
//! # Nothing here signs anything
//!
//! The certificate signing request is composed once, before any peer connects,
//! and this surface serves the bytes. That is deliberate and it is a property
//! rather than an implementation detail: were the request built per call, a
//! peer could make the protection domain that holds the appliance's private key
//! sign as often as it could open a connection. It cannot — what it can ask for
//! is a copy of an array.

use lfw_clock::Monotonic;
use lfw_http::{
    ContentType, MAX_HEAD_LEN, MAX_REQUEST_BYTES, Parsed, Request, RequestError, Status, parse,
    write_head,
};
use lfw_log::{DomainDetail, OnboardRefusal, OnboardRoute};
use lfw_x509::{DEVICE_ID_LEN, FINGERPRINT_LEN, MAX_CSR_PEM_LEN};

use crate::limiter::{Limiter, Throttle};
use crate::page::{MAX_PAGE_LEN, write_page};
use crate::upload::{Upload, UploadRefused};

/// Bytes of body this surface will take, which is the widest onboarding package
/// there is.
///
/// `lfw_package::ARCHIVE_BOUND` is the same number and so is the staging region
/// the archive crosses in. This crate declines to depend on the package reader
/// for one integer — it reads no member and holds no rule about one — so the
/// number is stated here and the protection domain that sees both is where they
/// are held equal.
pub const MAX_UPLOAD_LEN: usize = 128 * 1024;

/// Bytes of request head this surface accumulates before it refuses one.
///
/// The parser's own bound, because the two decisions are the same decision:
/// what a head may be is what a head may be, and a surface holding a different
/// number would be a second opinion about it.
pub const REQUEST_CAPACITY: usize = MAX_REQUEST_BYTES;

/// Bytes of body the longest response carries.
pub const MAX_BODY_LEN: usize = if MAX_PAGE_LEN > MAX_CSR_PEM_LEN {
    MAX_PAGE_LEN
} else {
    MAX_CSR_PEM_LEN
};

/// Bytes one whole response occupies, head and body together. Derived, so a
/// response can never be the thing that does not fit.
pub const MAX_RESPONSE_LEN: usize = MAX_HEAD_LEN + MAX_BODY_LEN;

/// The most console records one decision owes.
///
/// Two, and it is the limiter that decides it: a throttled request owes the
/// refusal and what the limiter is doing. Every other decision owes one.
pub const REQUEST_RECORDS: usize = 2;

/// The target of the page, which is the site root.
const PAGE_TARGET: &str = "/";

/// The target of the certificate signing request.
const CSR_TARGET: &str = "/certificate.csr";

/// The target a configuration package is uploaded to.
const PACKAGE_TARGET: &str = "/configuration.tar";

/// What this appliance is, as the two public strings a peer is shown and the
/// request it is asked to carry away.
///
/// Every field is public by the certificate profile's own terms: the identifier
/// is a meaningless name, the fingerprint is a digest of a public key, and the
/// request is a name and a proof of possession. There is nothing here to keep,
/// which is why it is held by value in the domain that answers the network
/// rather than fetched per request from the domain that holds the key.
#[derive(Clone, Copy)]
pub struct Identity {
    device: [u8; DEVICE_ID_LEN],
    fingerprint: [u8; FINGERPRINT_LEN],
    csr: [u8; MAX_CSR_PEM_LEN],
    csr_len: usize,
}

impl Identity {
    /// The identity a boot established.
    ///
    /// `csr` is the armoured certificate signing request; a length past the
    /// array is clamped rather than refused, because the only caller is this
    /// appliance's own writer and a clamp keeps a first-party arithmetic slip
    /// from becoming a fault on the path a peer drives.
    #[must_use]
    pub fn new(
        device: [u8; DEVICE_ID_LEN],
        fingerprint: [u8; FINGERPRINT_LEN],
        csr: &[u8],
    ) -> Self {
        let mut held = [0_u8; MAX_CSR_PEM_LEN];
        let len = csr.len().min(MAX_CSR_PEM_LEN);
        if let (Some(room), Some(taken)) = (held.get_mut(..len), csr.get(..len)) {
            room.copy_from_slice(taken);
        }
        Self {
            device,
            fingerprint,
            csr: held,
            csr_len: len,
        }
    }

    /// The armoured request, bounded by what was given rather than by the array
    /// behind it.
    #[must_use]
    pub fn csr(&self) -> &[u8] {
        self.csr.get(..self.csr_len).unwrap_or_default()
    }
}

/// What one turn of the surface decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The head has not ended. Not an outcome and not an error: a request split
    /// across records is ordinary.
    Waiting,
    /// A resource went back, and how many bytes of body it was.
    Served { route: OnboardRoute, bytes: usize },
    /// A package arrived whole and was installed, and how many bytes of archive
    /// it was. The appliance now has an owner, so this surface is shut.
    Installed { bytes: usize },
    /// A refusal went back, with the status the peer was told and the bytes of
    /// head this end was holding when it decided.
    Refused {
        refusal: OnboardRefusal,
        status: Status,
        held: usize,
        /// What the limiter was doing, on the one refusal it causes.
        throttle: Option<Throttle>,
    },
}

impl Decision {
    /// The console records this decision owes, in the order they are emitted.
    ///
    /// Here rather than in the protection domain that emits them, on the same
    /// terms the handshake outcomes are: what the domain supplies is the
    /// lifecycle point they ride on, and what is decided here is which facts
    /// reach an operator.
    ///
    /// **Nothing an adversary chose travels.** A resource is a token out of a
    /// closed vocabulary, a refusal likewise, and every number beside them is
    /// one this appliance computed.
    #[must_use]
    pub fn records(&self) -> [Option<DomainDetail>; REQUEST_RECORDS] {
        match self {
            Self::Waiting => [None, None],
            Self::Served { route, bytes } => [
                Some(DomainDetail::OnboardingServed {
                    route: *route,
                    bytes: *bytes as u64,
                }),
                None,
            ],
            Self::Installed { bytes } => [
                Some(DomainDetail::OnboardingInstalled {
                    bytes: *bytes as u64,
                }),
                None,
            ],
            Self::Refused {
                refusal,
                status,
                held,
                throttle,
            } => [
                Some(DomainDetail::OnboardingRequest {
                    refusal: *refusal,
                    status: status.code(),
                    held: *held as u64,
                }),
                throttle.map(
                    |Throttle {
                         strikes,
                         wait_millis,
                     }| DomainDetail::OnboardingThrottled {
                        strikes: u64::from(strikes),
                        wait_millis,
                    },
                ),
            ],
        }
    }
}

/// The onboarding request surface: one connection's worth of it at a time.
///
/// The limiter outlives a connection and everything else does not, which is the
/// whole shape of the type: a peer that opens a thousand connections meets one
/// limiter, and a peer that opens one meets a buffer that begins empty.
pub struct Onboarding {
    /// Absent on a boot whose cryptography never established, which is an
    /// appliance with nothing to serve and a token that says so.
    identity: Option<Identity>,
    /// Whether this appliance has an owner and so serves no onboarding.
    ///
    /// Set at construction from what the domain holding the device key read off
    /// its medium, and set again by an install this surface accepted. It
    /// outlives a connection for the same reason the limiter does and for a
    /// stronger one: a close a new connection could undo would be no close at
    /// all.
    closed: bool,
    limiter: Limiter,
    held: [u8; REQUEST_CAPACITY],
    held_len: usize,
    /// Where in the body an accepted upload is, or [`Stage::Head`] while a head
    /// is still being read. Not a buffer: the body itself is never here.
    stage: Stage,
    response: [u8; MAX_RESPONSE_LEN],
    response_len: usize,
    taken: usize,
    /// Whether this connection has been answered. What arrives afterwards is
    /// dropped: one response closes the connection, so a second request on it
    /// is a peer that did not read the first one's terms.
    answered: bool,
}

/// What the surface is reading.
///
/// Two states and no third: everything before a head has ended is
/// [`Self::Head`], and the only thing that follows one is a body this surface
/// agreed to take. A request that is being answered has left both — `answered`
/// is what says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Head,
    /// A body this surface agreed to take: how many bytes were declared, and how
    /// many are still owed. `owed` counts down as segments are handed on and
    /// reaches zero exactly once, which is where the upload is judged; `declared`
    /// does not move, being what the record beside the answer states.
    Body {
        declared: usize,
        owed: usize,
    },
}

impl Onboarding {
    /// The surface a boot brings up.
    ///
    /// `owned` closes it before a peer has connected, which is what makes an
    /// onboarded appliance serve nothing across a reboot: the fact comes off the
    /// medium every time the appliance starts, so there is no state here for a
    /// restart to lose.
    #[must_use]
    pub fn new(identity: Option<Identity>, owned: bool) -> Self {
        Self {
            identity,
            closed: owned,
            limiter: Limiter::new(),
            held: [0; REQUEST_CAPACITY],
            held_len: 0,
            stage: Stage::Head,
            response: [0; MAX_RESPONSE_LEN],
            response_len: 0,
            taken: 0,
            answered: false,
        }
    }

    /// Whether this appliance has an owner and so serves no onboarding.
    #[must_use]
    pub const fn closed(&self) -> bool {
        self.closed
    }

    /// The limiter, which outlives every connection.
    #[must_use]
    pub const fn limiter(&self) -> &Limiter {
        &self.limiter
    }

    /// Begin a connection, discarding whatever the last one left.
    ///
    /// Everything but the limiter: what a peer must not inherit is the previous
    /// peer's half-written head, and what it must not escape is the previous
    /// peer's allowance.
    pub fn opened(&mut self) {
        self.held_len = 0;
        self.stage = Stage::Head;
        self.response_len = 0;
        self.taken = 0;
        self.answered = false;
    }

    /// Take plaintext the peer sent and decide what it asked for, handing any
    /// body on to `upload`.
    ///
    /// `now` is `None` where the node has no clock; see [`Limiter`].
    pub fn take(
        &mut self,
        now: Option<Monotonic>,
        plaintext: &[u8],
        upload: &mut dyn Upload,
    ) -> Decision {
        if self.answered {
            // Read and dropped. Not held: a peer that goes on writing at a
            // connection already committed to one answer must not be able to
            // make this end hold anything for it.
            return Decision::Waiting;
        }
        if let Stage::Body { declared, owed } = self.stage {
            return self.carry(declared, owed, plaintext, upload);
        }
        // Filled first and parsed second, so a delivery carrying a head and the
        // beginning of a body is not refused for the size of the head it does
        // have. What did not fit is body, or it is a head past its bound —
        // which the parse below is what decides.
        let taken = self.fill(plaintext);
        let rest = plaintext.get(taken..).unwrap_or_default();
        // What the head asked for, read out of the buffer and copied into
        // values before anything is written back. Nothing that borrows a peer's
        // bytes outlives this block, which is what keeps a response from being
        // composed while a view into the request it answers is still live.
        let asked = {
            let head = self.held.get(..self.held_len).unwrap_or_default();
            match parse(head, MAX_UPLOAD_LEN) {
                Ok(Parsed::NeedMore) => {
                    if self.held_len >= REQUEST_CAPACITY {
                        // Held at the bound rather than truncated to it: a head
                        // this end shortened would be this end deciding what
                        // the peer said.
                        return self.refuse(
                            OnboardRefusal::HeadTooLong,
                            Status::HeadersTooLarge,
                            None,
                        );
                    }
                    return Decision::Waiting;
                }
                Ok(Parsed::Complete { request, consumed }) => Asked::of(&request, consumed),
                Err(error) => {
                    let status = error.status();
                    return self.refuse(named(error), status, None);
                }
            }
        };
        self.decide(now, asked, rest, upload)
    }

    /// Bytes of the response the wire has not taken.
    #[must_use]
    pub fn pending(&self) -> &[u8] {
        self.response
            .get(self.taken..self.response_len)
            .unwrap_or_default()
    }

    /// Drop the first `bytes` of what is owed the wire.
    pub fn sent(&mut self, bytes: usize) {
        self.taken = self.taken.saturating_add(bytes).min(self.response_len);
    }

    /// Whether the answer has gone and the connection may close.
    #[must_use]
    pub const fn finished(&self) -> bool {
        self.answered && self.taken >= self.response_len
    }

    /// Append as much of what arrived as the head buffer still holds, answering
    /// how many bytes that was.
    ///
    /// It refuses nothing. Whether a delivery that did not fit is a head past
    /// its bound or a body that has not been asked for yet is a question about
    /// the head, and only the parse knows the answer.
    fn fill(&mut self, plaintext: &[u8]) -> usize {
        let room = REQUEST_CAPACITY.saturating_sub(self.held_len);
        let taking = room.min(plaintext.len());
        let end = self.held_len.saturating_add(taking);
        if let (Some(into), Some(from)) = (
            self.held.get_mut(self.held_len..end),
            plaintext.get(..taking),
        ) {
            into.copy_from_slice(from);
            self.held_len = end;
            return taking;
        }
        // Unreachable: both slices are bounded by the same `taking`, which is
        // bounded by the array and by the argument. Answered rather than
        // asserted, no fault being admissible on a path a peer paces — and
        // taking nothing leaves the head short, which the parse reads as a
        // request that has not ended.
        0
    }

    /// Hand `segment` on to the upload and count it against what is still owed.
    ///
    /// Where it completes the body, the package is judged here: the surface has
    /// nothing left to wait for, and a caller that had to be told separately
    /// that a body was whole could forget to ask.
    fn carry(
        &mut self,
        declared: usize,
        owed: usize,
        segment: &[u8],
        upload: &mut dyn Upload,
    ) -> Decision {
        match feed(owed, segment, upload) {
            Ok(0) => self.finish_upload(declared, upload),
            Ok(left) => {
                self.stage = Stage::Body {
                    declared,
                    owed: left,
                };
                Decision::Waiting
            }
            Err(refusal) => {
                // Back to reading a head, which is what a connection that has
                // been answered is between requests. Nothing reaches the stage
                // again on this connection — the answer short-circuits every
                // later delivery — so this is target state rather than a check,
                // and leaving a half-read body behind would be state nothing
                // clears.
                self.stage = Stage::Head;
                self.refuse(refusal, upload_status(refusal), None)
            }
        }
    }

    /// The body is whole: ask the caller to install it and answer what it said.
    fn finish_upload(&mut self, bytes: usize, upload: &mut dyn Upload) -> Decision {
        match upload.install() {
            Ok(()) => {
                // Shut before the answer is composed, so nothing between here
                // and the next connection can serve this surface again.
                self.closed = true;
                self.stage = Stage::Head;
                self.finish(Status::Ok, None, 0);
                Decision::Installed { bytes }
            }
            Err(UploadRefused) => {
                self.stage = Stage::Head;
                self.refuse(OnboardRefusal::PackageRefused, Status::BadRequest, None)
            }
        }
    }

    /// Which resource a whole head asked for, and whether it may have it.
    ///
    /// The order is the point: the limiter runs **before** the route is looked
    /// at, so the work a refused request costs is the same whatever it asked
    /// for, and an identity that does not exist is answered before a route is
    /// resolved against it.
    fn decide(
        &mut self,
        now: Option<Monotonic>,
        asked: Asked,
        rest: &[u8],
        upload: &mut dyn Upload,
    ) -> Decision {
        if let Err(throttle) = self.limiter.admit(now) {
            return self.refuse(
                OnboardRefusal::RateLimited,
                Status::TooManyRequests,
                Some(throttle),
            );
        }
        // Before the route, because a closed surface has none: an appliance with
        // an owner serves no onboarding at all, so every address is gone rather
        // than one of them being.
        if self.closed {
            return self.refuse(OnboardRefusal::AlreadyOwned, Status::Gone, None);
        }
        let Some(identity) = self.identity else {
            return self.refuse(
                OnboardRefusal::IdentityAbsent,
                Status::ServiceUnavailable,
                None,
            );
        };
        // Everything this surface does not have. A method it does not implement
        // is answered exactly as an address it does not have, so nothing here is
        // a place-holder a client could mistake for a resource that is nearly
        // ready.
        let Some(target) = asked.target else {
            return self.refuse(OnboardRefusal::UnknownRoute, Status::NotFound, None);
        };
        match target {
            Target::Page | Target::CertificateRequest => {
                if !asked.is_get {
                    return self.refuse(
                        OnboardRefusal::MethodNotServed,
                        Status::MethodNotAllowed,
                        None,
                    );
                }
                self.serve(target.route(), &identity)
            }
            Target::ConfigurationPackage => {
                if !asked.is_post {
                    return self.refuse(
                        OnboardRefusal::MethodNotServed,
                        Status::MethodNotAllowed,
                        None,
                    );
                }
                self.begin_upload(asked, rest, upload)
            }
        }
    }

    /// Reserve the upload, then hand on whatever of the body already arrived.
    ///
    /// The order is the point: the caller's reserve is taken **before** a byte
    /// is placed, so an appliance that has nowhere to put a package refuses the
    /// request rather than beginning one it cannot finish.
    fn begin_upload(&mut self, asked: Asked, rest: &[u8], upload: &mut dyn Upload) -> Decision {
        let declared = asked.body_len;
        if declared == 0 {
            // Nothing is staged and nothing is asked of the key holder, so no
            // other domain's record would say anything about this request.
            return self.refuse(OnboardRefusal::UploadEmpty, Status::BadRequest, None);
        }
        if upload.open(declared).is_err() {
            return self.refuse(
                OnboardRefusal::UploadUnavailable,
                Status::ServiceUnavailable,
                None,
            );
        }
        // Whatever of the body landed in the head buffer, then the rest of this
        // delivery. Two slices rather than one because the head's own bound is
        // where the first ends; `upload` is a separate argument, so handing on
        // the first borrows the buffer and nothing else.
        let carried =
            match feed_carried(&self.held, self.held_len, asked.consumed, declared, upload) {
                Ok(owed) => owed,
                Err(refusal) => return self.refuse(refusal, upload_status(refusal), None),
            };
        self.carry(declared, carried, rest, upload)
    }

    /// Compose a resource's response and answer what it was.
    fn serve(&mut self, route: OnboardRoute, identity: &Identity) -> Decision {
        let (content_type, bytes) = match route {
            OnboardRoute::Page => {
                let written = write_page(
                    &identity.device,
                    &identity.fingerprint,
                    self.response.get_mut(MAX_HEAD_LEN..).unwrap_or_default(),
                );
                match written {
                    Ok(len) => (ContentType::Html, len),
                    // Unreachable by the derived bound, and answered rather
                    // than asserted: no fault is admissible on a path a peer
                    // paces, and an appliance that cannot compose its own page
                    // is one an administrator needs told about.
                    Err(_) => {
                        return self.refuse(
                            OnboardRefusal::IdentityAbsent,
                            Status::ServiceUnavailable,
                            None,
                        );
                    }
                }
            }
            OnboardRoute::CertificateRequest => {
                let request = identity.csr();
                let end = MAX_HEAD_LEN.saturating_add(request.len());
                match self.response.get_mut(MAX_HEAD_LEN..end) {
                    Some(room) => {
                        room.copy_from_slice(request);
                        (ContentType::Pkcs10, request.len())
                    }
                    None => {
                        return self.refuse(
                            OnboardRefusal::IdentityAbsent,
                            Status::ServiceUnavailable,
                            None,
                        );
                    }
                }
            }
        };
        self.finish(Status::Ok, Some(content_type), bytes);
        Decision::Served { route, bytes }
    }

    /// Compose a refusal's response and answer what it was.
    ///
    /// A refusal has no body: the status is the whole of what a client is owed,
    /// and prose composed for one would be a second surface to keep true.
    fn refuse(
        &mut self,
        refusal: OnboardRefusal,
        status: Status,
        throttle: Option<Throttle>,
    ) -> Decision {
        let held = self.held_len;
        self.finish(status, None, 0);
        Decision::Refused {
            refusal,
            status,
            held,
            throttle,
        }
    }

    /// Write the head in front of the body and mark the connection answered.
    ///
    /// The head is written last and moved into place, because `Content-Length`
    /// is part of it and a length nobody has measured is a length that can be
    /// wrong.
    fn finish(&mut self, status: Status, content_type: Option<ContentType>, bytes: usize) {
        let mut head = [0_u8; MAX_HEAD_LEN];
        let head_len =
            write_head(status, content_type, bytes as u64, &mut head).map_or(0, |len| len);
        // The body sits at `MAX_HEAD_LEN` and the head is shorter than that, so
        // it is moved forward to abut it. A copy within one array, both ends of
        // which are bounded by constants this crate derived.
        let start = MAX_HEAD_LEN.saturating_sub(head_len);
        if let (Some(room), Some(written)) = (
            self.response.get_mut(start..MAX_HEAD_LEN),
            head.get(..head_len),
        ) {
            room.copy_from_slice(written);
        }
        self.taken = start;
        self.response_len = MAX_HEAD_LEN.saturating_add(bytes);
        self.answered = true;
    }
}

/// A target this surface has, whether or not it is one it serves bytes for.
///
/// Its own enum rather than `lfw_log`'s: that vocabulary names the resources a
/// request was *answered with*, and a package upload is answered with a status
/// and no body. A member there for it would be a served resource that is never
/// served, which is a token an operator could grep for and never find.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Page,
    CertificateRequest,
    ConfigurationPackage,
}

impl Target {
    /// How the console names this resource, for the two that are served.
    ///
    /// The upload's arm is unreachable — it is answered by
    /// [`Decision::Installed`], which carries no route — and it maps to the page
    /// rather than being asserted away, no fault being admissible on a path a
    /// peer paces.
    const fn route(self) -> OnboardRoute {
        match self {
            Self::Page | Self::ConfigurationPackage => OnboardRoute::Page,
            Self::CertificateRequest => OnboardRoute::CertificateRequest,
        }
    }
}

/// What a head asked for, as values that borrow none of it.
///
/// The bridge between a parser that hands back views into a peer's bytes and a
/// surface that answers into its own buffer: everything the decision needs is a
/// handful of facts, so nothing longer has to outlive the parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Asked {
    /// The resource, or nothing where the target names none.
    target: Option<Target>,
    is_get: bool,
    is_post: bool,
    /// Bytes of head, which is where a body begins in the buffer.
    consumed: usize,
    /// Bytes of body the head declared, already held to [`MAX_UPLOAD_LEN`] by
    /// the parser.
    body_len: usize,
}

impl Asked {
    fn of(request: &Request<'_>, consumed: usize) -> Self {
        let target = match path_of(request.target()) {
            PAGE_TARGET => Some(Target::Page),
            CSR_TARGET => Some(Target::CertificateRequest),
            PACKAGE_TARGET => Some(Target::ConfigurationPackage),
            _ => None,
        };
        Self {
            target,
            is_get: request.is_get(),
            is_post: request.is_post(),
            consumed,
            body_len: request.body_len(),
        }
    }
}

/// Hand on the body bytes that landed in the head buffer, answering what is
/// still owed.
///
/// A free function rather than a method because it reads the head buffer and
/// writes to the upload at the same time, and those are two different things the
/// caller owns: passing the buffer in is what keeps the borrow of it disjoint
/// from the `&mut` the surface holds of itself.
fn feed_carried(
    held: &[u8; REQUEST_CAPACITY],
    held_len: usize,
    consumed: usize,
    declared: usize,
    upload: &mut dyn Upload,
) -> Result<usize, OnboardRefusal> {
    let carried = held.get(consumed..held_len).unwrap_or_default();
    feed(declared, carried, upload)
}

/// Hand `segment` on and answer what is still owed after it.
///
/// # Errors
/// [`OnboardRefusal::UploadOverran`] where the peer sent past the length it
/// declared, and [`OnboardRefusal::UploadUnstaged`] where the caller kept fewer
/// bytes than were offered.
fn feed(owed: usize, segment: &[u8], upload: &mut dyn Upload) -> Result<usize, OnboardRefusal> {
    if segment.len() > owed {
        // The peer contradicting its own `Content-Length`. Refused rather than
        // truncated to the declared length: two parties disagreeing about where
        // a message ends is the one thing this surface's parser exists to have
        // only one opinion about.
        return Err(OnboardRefusal::UploadOverran);
    }
    let kept = upload.take(segment);
    if kept != segment.len() {
        // Unreachable while the declared length is held to what the caller
        // reserved, and answered rather than asserted for the reason every
        // other refusal here is.
        return Err(OnboardRefusal::UploadUnstaged);
    }
    Ok(owed.saturating_sub(kept))
}

/// The status a peer is told for each way an upload was refused.
///
/// Two of these are the peer's doing and one is this appliance's, which is what
/// the two classes of code say: a 4xx is a request to correct and a 5xx is an
/// appliance that could not, and an administrator acts on them differently.
const fn upload_status(refusal: OnboardRefusal) -> Status {
    match refusal {
        OnboardRefusal::UploadOverran => Status::BadRequest,
        // Every other member reaches this only through the two `feed` raises;
        // both are this end failing to place what it agreed to take, which is a
        // surface that is unavailable rather than a request that was wrong.
        _ => Status::ServiceUnavailable,
    }
}

/// A target's path, with any query string dropped.
///
/// Split rather than refused: a client that appends a cache-buster to the page
/// is asking for the page, and a surface that answered "no such resource" to it
/// would send an administrator looking for a fault that is not there.
fn path_of(target: &str) -> &str {
    match target.split_once('?') {
        Some((path, _)) => path,
        None => target,
    }
}

/// The parser's refusal as the console names it.
///
/// Every member is matched explicitly and there is no residual: the parser is
/// first-party and its error type is closed, so a variant added there fails
/// this build rather than landing on a token that would read as a diagnosis of
/// something else.
const fn named(error: RequestError) -> OnboardRefusal {
    match error {
        RequestError::BareLineFeed => OnboardRefusal::BareLineFeed,
        RequestError::StrayCarriageReturn => OnboardRefusal::StrayCarriageReturn,
        RequestError::MalformedRequestLine => OnboardRefusal::MalformedRequestLine,
        RequestError::MalformedMethod => OnboardRefusal::MalformedMethod,
        RequestError::MalformedTarget => OnboardRefusal::MalformedTarget,
        RequestError::TargetTooLong => OnboardRefusal::TargetTooLong,
        RequestError::UnsupportedVersion => OnboardRefusal::UnsupportedVersion,
        RequestError::MalformedVersion => OnboardRefusal::MalformedVersion,
        RequestError::TooManyHeaders => OnboardRefusal::TooManyHeaders,
        RequestError::MalformedHeaderName => OnboardRefusal::MalformedHeaderName,
        RequestError::MalformedHeaderValue => OnboardRefusal::MalformedHeaderValue,
        RequestError::ObsoleteLineFolding => OnboardRefusal::ObsoleteLineFolding,
        RequestError::BodyNotAccepted => OnboardRefusal::BodyNotAccepted,
        RequestError::BodyTooLarge { .. } => OnboardRefusal::BodyTooLarge,
        RequestError::NotUtf8 => OnboardRefusal::NotUtf8,
    }
}
