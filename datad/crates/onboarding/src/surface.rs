//! The two resources an unprovisioned appliance serves, and the fifteen ways a
//! request for one of them is refused.
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
//! * **Every byte a peer sends is bounded before it is held.** The accumulation
//!   stops at [`REQUEST_CAPACITY`] and the request is refused there rather than
//!   waited on, so a peer that never ends a head costs a fixed array.
//! * **Nothing a peer sent reaches an operator surface.** A refusal is named by
//!   a token out of a closed vocabulary and placed by numbers this appliance
//!   computed — the status it answered and the bytes it was holding. The target
//!   a peer typed is not among them, and neither is any byte of the head.
//! * **One request per connection.** Every response carries `Connection: close`
//!   and this surface answers exactly one; what follows a completed response is
//!   read and dropped rather than parsed, so a peer cannot pipeline a second
//!   request onto a session already committed to an answer.
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
    limiter: Limiter,
    held: [u8; REQUEST_CAPACITY],
    held_len: usize,
    response: [u8; MAX_RESPONSE_LEN],
    response_len: usize,
    taken: usize,
    /// Whether this connection has been answered. What arrives afterwards is
    /// dropped: one response closes the connection, so a second request on it
    /// is a peer that did not read the first one's terms.
    answered: bool,
}

impl Onboarding {
    #[must_use]
    pub fn new(identity: Option<Identity>) -> Self {
        Self {
            identity,
            limiter: Limiter::new(),
            held: [0; REQUEST_CAPACITY],
            held_len: 0,
            response: [0; MAX_RESPONSE_LEN],
            response_len: 0,
            taken: 0,
            answered: false,
        }
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
        self.response_len = 0;
        self.taken = 0;
        self.answered = false;
    }

    /// Take plaintext the peer sent and decide what it asked for.
    ///
    /// `now` is `None` where the node has no clock; see [`Limiter`].
    pub fn take(&mut self, now: Option<Monotonic>, plaintext: &[u8]) -> Decision {
        if self.answered {
            // Read and dropped. Not held: a peer that goes on writing at a
            // connection already committed to one answer must not be able to
            // make this end hold anything for it.
            return Decision::Waiting;
        }
        if let Err(refusal) = self.absorb(plaintext) {
            return self.refuse(refusal, Status::HeadersTooLarge, None);
        }
        // What the head asked for, read out of the buffer and copied into two
        // values before anything is written back. Nothing that borrows a peer's
        // bytes outlives this block, which is what keeps a response from being
        // composed while a view into the request it answers is still live.
        let asked = {
            let head = self.held.get(..self.held_len).unwrap_or_default();
            // No body at all: this surface takes none, so a head declaring one
            // is refused by the parser before a byte of it is looked at.
            match parse(head, 0) {
                Ok(Parsed::NeedMore) => return Decision::Waiting,
                Ok(Parsed::Complete { request, .. }) => Asked::of(&request),
                Err(error) => {
                    let status = error.status();
                    return self.refuse(named(error), status, None);
                }
            }
        };
        self.decide(now, asked)
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

    /// Append what arrived, or say the head outgrew what may be held.
    fn absorb(&mut self, plaintext: &[u8]) -> Result<(), OnboardRefusal> {
        let end = self.held_len.saturating_add(plaintext.len());
        let Some(room) = self.held.get_mut(self.held_len..end) else {
            // Held at the bound rather than truncated to it: a head this end
            // shortened would be this end deciding what the peer said.
            self.held_len = REQUEST_CAPACITY;
            return Err(OnboardRefusal::HeadTooLong);
        };
        room.copy_from_slice(plaintext);
        self.held_len = end;
        Ok(())
    }

    /// Which resource a whole head asked for, and whether it may have it.
    ///
    /// The order is the point: the limiter runs **before** the route is looked
    /// at, so the work a refused request costs is the same whatever it asked
    /// for, and an identity that does not exist is answered before a route is
    /// resolved against it.
    fn decide(&mut self, now: Option<Monotonic>, asked: Asked) -> Decision {
        if let Err(throttle) = self.limiter.admit(now) {
            return self.refuse(
                OnboardRefusal::RateLimited,
                Status::TooManyRequests,
                Some(throttle),
            );
        }
        let Some(identity) = self.identity else {
            return self.refuse(
                OnboardRefusal::IdentityAbsent,
                Status::ServiceUnavailable,
                None,
            );
        };
        // Everything this surface does not have, `POST /configuration.tar`
        // among it. A method it does not implement is answered exactly as an
        // address it does not have, so nothing here is a place-holder a client
        // could mistake for a resource that is nearly ready.
        let Some(route) = asked.route else {
            return self.refuse(OnboardRefusal::UnknownRoute, Status::NotFound, None);
        };
        if !asked.is_get {
            return self.refuse(
                OnboardRefusal::MethodNotServed,
                Status::MethodNotAllowed,
                None,
            );
        }
        self.serve(route, &identity)
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

/// What a head asked for, as two values that borrow none of it.
///
/// The bridge between a parser that hands back views into a peer's bytes and a
/// surface that answers into its own buffer: everything the decision needs is
/// two facts, so nothing longer than two facts has to outlive the parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Asked {
    /// The resource, or nothing where the target names none.
    route: Option<OnboardRoute>,
    is_get: bool,
}

impl Asked {
    fn of(request: &Request<'_>) -> Self {
        let route = match path_of(request.target()) {
            PAGE_TARGET => Some(OnboardRoute::Page),
            CSR_TARGET => Some(OnboardRoute::CertificateRequest),
            _ => None,
        };
        Self {
            route,
            is_get: request.is_get(),
        }
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
