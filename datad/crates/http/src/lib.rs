//! HTTP/1.1 as a server speaks it: an incremental request-head parser and a
//! response-head builder, both bounded, allocator-free and total over arbitrary
//! bytes.
//!
//! # Adversary
//!
//! The **management-plane attacker**, directly and with nothing in
//! between. Every byte [`parse`] reads arrived on a TCP connection to the
//! management port, so the whole surface is that party's to choose: the method,
//! the target, how many headers there are, how long each is, where a line ends,
//! and whether the request ever ends at all.
//!
//! Three consequences shape everything below.
//!
//! * **Every dimension is a named constant** — [`MAX_REQUEST_BYTES`],
//!   [`MAX_TARGET_LEN`], [`MAX_HEADERS`], [`MAX_HEADER_NAME_LEN`],
//!   [`MAX_HEADER_VALUE_LEN`], [`MAX_METHOD_LEN`] — because an unbounded header
//!   count or line length is that attacker exhausting a protection domain's
//!   fixed memory. The caller enforces the first against its own
//!   accumulation buffer; this crate enforces the rest.
//! * **Nothing panics and nothing indexes.** Arbitrary bytes produce a
//!   [`Request`] or a [`RequestError`], never a fault, which a fuzz
//!   target asserts over arbitrary input split into arbitrary segments.
//! * **A refusal names a status.** [`RequestError::status`] maps every cause to
//!   the code the client is owed, so a caller answers rather than closing.
//!
//! # `\r\n` only, and a bare `\n` is refused
//!
//! RFC 9112 section 2.2 permits a *recipient* to accept a bare LF as a line
//! terminator. This one does not, and the decision is deliberate: request
//! smuggling lives in exactly that latitude — two parties on a path disagreeing
//! about where a line ends is how one request becomes two. There will be a
//! second party on that path (see below), so the strict reading is the one that
//! composes. A bare LF is [`RequestError::BareLineFeed`] and a 400, reported at
//! the first line ending rather than by waiting out the byte bound.
//!
//! # One framing for a body, and every other one refused
//!
//! A request body is admitted under **exactly one** framing: a single
//! `Content-Length` whose value is decimal, within the caller's `body_limit`, and
//! on a `POST`. Everything else is refused before a body byte is looked at, and
//! each refusal is one half of request smuggling closed:
//!
//! * **Any `Transfer-Encoding` is refused.** Chunked framing is a second opinion
//!   about where a message ends, and this parser deliberately has only one.
//! * **A repeated `Content-Length` is refused**, whatever the values, so two
//!   parties on a path cannot pick different ones.
//! * **A body on any method but `POST` is refused.** RFC 9110 permits one on a
//!   `GET`; a server that read it and did nothing with it would be a party that
//!   agreed a length for bytes nothing consumes.
//! * **A length past `body_limit` is refused with 413**, at the head, so nothing
//!   is accumulated on the way to discovering it.
//!
//! What this crate does *not* do is read the body: [`parse`] reports its declared
//! length and hands back the head's own length, and the caller — which owns the
//! storage — decides where those bytes go. A parser that buffered a body would be
//! choosing a buffer for a domain whose memory it knows nothing about.
//!
//! # Built for the proxy, used by the management port
//!
//! The design's inspecting proxy needs an HTTP/1.1 parser on a path where the
//! bytes belong to *two* untrusted parties at once, so this crate owns no
//! buffer, decides no policy and knows no target: [`parse`] takes
//! a slice the caller accumulated and hands back borrowed fields. What the
//! management server adds on top — which targets exist, what a response body
//! is — is `lfw_ip_endpoint::http`. The pieces a proxy needs and a server does
//! not, chiefly response *parsing* and chunked framing, are absent rather than
//! stubbed.
//!
//! # A known, deliberate gap in the target design: this is plain HTTP
//!
//! The target design requires the management API to carry encryption, authentication
//! and read/write authorization through an mTLS certificate pair. **None of that
//! exists here.** There is no TLS anywhere in this appliance, so this crate parses
//! cleartext and the server above it authenticates nobody: *anything that can reach
//! the management port can read every metric the node exposes, read its
//! configuration, and — through the request bodies this crate now frames —
//! **replace** that configuration.* The write is the reason the read/write
//! authorization the design requires is not a refinement to be added later: without
//! it, reaching the port is the authority to decide what the appliance forwards.
//! That is a recorded, deliberate deviation and is why the port belongs on an
//! isolated management network until the intended TLS termination and certificate
//! handling exist. Nothing here is a step toward them — TLS terminates below HTTP
//! and will be a layer under this crate rather than a change to it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod request;
mod response;

pub use request::{Header, Parsed, Request, RequestError, parse};
pub use response::{
    ContentType, HTML_CONTENT_TYPE, MAX_HEAD_LEN, OCTET_STREAM_CONTENT_TYPE, PKCS10_CONTENT_TYPE,
    XML_CONTENT_TYPE, write_head,
};

/// Bytes of request head a caller may accumulate before the head must have
/// ended.
///
/// It is the caller's bound rather than this crate's — [`parse`] is handed a
/// slice and never grows one — but it is stated here because it is the same
/// decision as the four below and belongs beside them. Two kibibytes holds a
/// browser's conditional GET with a full cookie jar and refuses anything a
/// management client would ever send; a request that outgrows it is answered
/// [`Status::HeadersTooLarge`], not waited on.
pub const MAX_REQUEST_BYTES: usize = 2048;

/// Bytes of request target. Enough for every management path with query
/// parameters to spare, and short enough that a target is never the reason a
/// request head fills its buffer.
pub const MAX_TARGET_LEN: usize = 128;

/// Header fields one request may carry.
pub const MAX_HEADERS: usize = 24;

/// Bytes of one header field name.
pub const MAX_HEADER_NAME_LEN: usize = 64;

/// Bytes of one header field value, after the optional whitespace around it is
/// trimmed.
pub const MAX_HEADER_VALUE_LEN: usize = 256;

/// Bytes of the request method. `GET` is the only one this server answers, and
/// the bound exists so an arbitrary run of token characters before the first
/// space is refused by length rather than compared.
pub const MAX_METHOD_LEN: usize = 16;

/// Digits a `Content-Length` may carry before it is refused unread.
///
/// A bound on the adversary rather than on the protocol: a length is compared
/// against the caller's `body_limit`, so the only thing an arbitrary run of
/// digits buys is arithmetic on a number no body can be. Ten digits is past every
/// `body_limit` this workspace states and short of a `u64`'s width, so the
/// accumulation below cannot overflow.
pub const MAX_CONTENT_LENGTH_DIGITS: usize = 10;

/// The one protocol version this server speaks. RFC 9112 keep-alive, pipelining
/// and chunked framing are all HTTP/1.1 features the server above deliberately
/// does not use; the version is nevertheless required exactly, because a client
/// announcing 1.0 is announcing a different framing contract.
pub const VERSION: &str = "HTTP/1.1";

/// The status codes this server can answer with.
///
/// A closed set, in ascending order, which is also the order
/// `lfw_metrics::HTTP_STATUSES` counts them in — held together by a test in
/// `lfw_ip_endpoint`, the crate that owns both dependencies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    RequestTimeout,
    /// What a resource that existed and has been withdrawn for good answers
    /// with. The onboarding surface is the only one that can: an appliance that
    /// has been given an owner closes it permanently, and a client told 404
    /// would be told the address was never served — which would send an
    /// administrator looking for a typing mistake instead of reading the state
    /// the appliance is in.
    Gone,
    ContentTooLarge,
    UriTooLong,
    /// What a rate limiter answers with. No server here has ever been able to
    /// say "come back later" before: the management port answers whatever it is
    /// asked as fast as it is asked, and the one surface that must not is the
    /// one an unprovisioned appliance exposes to whoever reaches it.
    TooManyRequests,
    HeadersTooLarge,
    ServiceUnavailable,
    VersionNotSupported,
}

impl Status {
    /// Every variant, so a counter table and a bound are built by iteration
    /// rather than by a list that drifts from the enum.
    pub const ALL: [Self; 12] = [
        Self::Ok,
        Self::BadRequest,
        Self::NotFound,
        Self::MethodNotAllowed,
        Self::RequestTimeout,
        Self::Gone,
        Self::ContentTooLarge,
        Self::UriTooLong,
        Self::TooManyRequests,
        Self::HeadersTooLarge,
        Self::ServiceUnavailable,
        Self::VersionNotSupported,
    ];

    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::RequestTimeout => 408,
            Self::Gone => 410,
            Self::ContentTooLarge => 413,
            Self::UriTooLong => 414,
            Self::TooManyRequests => 429,
            Self::HeadersTooLarge => 431,
            Self::ServiceUnavailable => 503,
            Self::VersionNotSupported => 505,
        }
    }

    /// The reason phrase. RFC 9112 makes it optional and unregulated; the
    /// registered phrase is used because a human reads it in a terminal.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::BadRequest => "Bad Request",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::RequestTimeout => "Request Timeout",
            Self::Gone => "Gone",
            Self::ContentTooLarge => "Content Too Large",
            Self::UriTooLong => "URI Too Long",
            Self::TooManyRequests => "Too Many Requests",
            Self::HeadersTooLarge => "Request Header Fields Too Large",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::VersionNotSupported => "HTTP Version Not Supported",
        }
    }

    /// The decimal code as a label value, for the metric that counts responses.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Ok => "200",
            Self::BadRequest => "400",
            Self::NotFound => "404",
            Self::MethodNotAllowed => "405",
            Self::RequestTimeout => "408",
            Self::Gone => "410",
            Self::ContentTooLarge => "413",
            Self::UriTooLong => "414",
            Self::TooManyRequests => "429",
            Self::HeadersTooLarge => "431",
            Self::ServiceUnavailable => "503",
            Self::VersionNotSupported => "505",
        }
    }

    /// The index this status occupies in [`ALL`](Self::ALL), and so in a
    /// counter table keyed by it.
    #[must_use]
    pub const fn slot(self) -> usize {
        self as usize
    }
}

#[cfg(test)]
mod tests;
