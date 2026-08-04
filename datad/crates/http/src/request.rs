//! Reading a request head out of bytes that arrived in whatever pieces the
//! network chose.
//!
//! [`parse`] is a pure function of the bytes accumulated so far: it answers
//! [`Parsed::NeedMore`] until the head has ended, a [`Request`] borrowing those
//! bytes once it has, and a [`RequestError`] the moment something is wrong.
//! Nothing is remembered between calls, so a caller re-parses its whole buffer
//! each time a segment arrives — which costs a scan of at most
//! [`MAX_REQUEST_BYTES`](crate::MAX_REQUEST_BYTES) bytes and removes every
//! question about resuming a state machine mid-token.
//!
//! **`NeedMore` is an outcome and not an error.** A request split across TCP
//! segments is ordinary, and a parser that could not tell "not yet" from "no"
//! would either refuse a legitimate client or wait on a broken one.

use crate::{
    MAX_CONTENT_LENGTH_DIGITS, MAX_HEADER_NAME_LEN, MAX_HEADER_VALUE_LEN, MAX_HEADERS,
    MAX_METHOD_LEN, MAX_TARGET_LEN, Status, VERSION,
};

/// One header field, borrowed out of the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    /// As it arrived: field names are case-insensitive, so a lookup lowercases
    /// rather than the parser rewriting a caller's bytes.
    pub name: &'a str,
    pub value: &'a str,
}

/// A request head that has been read whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    method: &'a str,
    target: &'a str,
    headers: [Option<Header<'a>>; MAX_HEADERS],
    count: usize,
    /// Bytes of body the head declares, already held to the caller's
    /// `body_limit` and to the one framing this parser admits.
    body_len: usize,
}

impl<'a> Request<'a> {
    /// The method exactly as it arrived. RFC 9110 makes methods
    /// case-*sensitive*, so this is compared and never folded.
    #[must_use]
    pub const fn method(&self) -> &'a str {
        self.method
    }

    /// The request target, in origin form.
    #[must_use]
    pub const fn target(&self) -> &'a str {
        self.target
    }

    #[must_use]
    pub fn is_get(&self) -> bool {
        self.method == "GET"
    }

    /// The one method that may carry a body here, which is why it has an accessor
    /// of its own rather than a caller comparing the string.
    #[must_use]
    pub fn is_post(&self) -> bool {
        self.method == "POST"
    }

    /// Bytes of body that follow this head, and zero where none do.
    ///
    /// A *declared* length rather than a delivered one: what arrives is the
    /// caller's to accumulate, and a peer that sends fewer bytes than it announced
    /// leaves a request nothing completes — which is the fail-closed outcome, not
    /// a case this parser can decide.
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.body_len
    }

    /// Every header, in the order they arrived.
    pub fn headers(&self) -> impl Iterator<Item = Header<'a>> + '_ {
        self.headers.iter().take(self.count).copied().flatten()
    }

    /// The first value of a field, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers()
            .find(|header| equals_ignoring_case(header.name, name))
            .map(|header| header.value)
    }
}

/// How far [`parse`] got.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing needs an allocator; the value is a temporary the caller \
              destructures at once, and the large variant is the header table \
              MAX_HEADERS fixes"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// The head has not ended yet. The caller accumulates more bytes and asks
    /// again — up to its own byte bound, past which it answers
    /// [`Status::HeadersTooLarge`] rather than waiting for ever.
    NeedMore,
    /// A whole head, and how many bytes of the caller's buffer it occupied
    /// including the terminating blank line.
    Complete {
        request: Request<'a>,
        consumed: usize,
    },
}

/// Why a request was refused, at the granularity a caller can act on: each
/// variant names one rule and maps to the status the client is owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// A line ended with a bare LF. See the crate header on why that is refused
    /// rather than tolerated.
    BareLineFeed,
    /// A CR that no LF followed, which no field value may contain.
    StrayCarriageReturn,
    /// The request line is not three space-separated parts.
    MalformedRequestLine,
    /// The method is longer than [`MAX_METHOD_LEN`], or is not a token.
    MalformedMethod,
    /// The target is empty, or carries a byte no request target may.
    MalformedTarget,
    /// The target is longer than [`MAX_TARGET_LEN`].
    TargetTooLong,
    /// Well-formed `HTTP/<major>.<minor>`, and not the one version this server
    /// speaks.
    UnsupportedVersion,
    /// Not an HTTP version at all.
    MalformedVersion,
    /// More than [`MAX_HEADERS`] fields.
    TooManyHeaders,
    /// A field name longer than [`MAX_HEADER_NAME_LEN`], or one that is not a
    /// token, or a line with no colon in it.
    MalformedHeaderName,
    /// A field value longer than [`MAX_HEADER_VALUE_LEN`], or one carrying a
    /// byte a field value may not.
    MalformedHeaderValue,
    /// A continuation line: RFC 9112 section 5.2 deprecates obs-fold and requires a
    /// server that does not support it to refuse the message.
    ObsoleteLineFolding,
    /// A body framed in a way this parser will not read: any `Transfer-Encoding`,
    /// a repeated or non-decimal `Content-Length`, or a body on a method other
    /// than `POST`. See the crate header on why each is refused rather than
    /// interpreted.
    BodyNotAccepted,
    /// A `Content-Length` above the caller's `body_limit`. Refused at the head, so
    /// no byte of the body is accumulated on the way to finding out.
    BodyTooLarge { declared: u64 },
    /// The bytes are not UTF-8, which is what is checked: a head is ASCII, and
    /// every ASCII string is UTF-8, so this refuses the bytes no `&str` can
    /// hold rather than every byte above 0x7F. The fields that must be ASCII
    /// say so themselves — a token, a target, a field value.
    NotUtf8,
}

impl RequestError {
    /// The status the client is owed for this refusal.
    #[must_use]
    pub const fn status(self) -> Status {
        match self {
            Self::TargetTooLong => Status::UriTooLong,
            Self::TooManyHeaders | Self::MalformedHeaderName | Self::MalformedHeaderValue => {
                // 431 covers both "too many" and "one too large", which is what
                // RFC 6585 section 5 defines it for; the length rules are the only way
                // to reach these three, a name or value that is merely
                // ill-formed being refused by the same variant.
                Status::HeadersTooLarge
            }
            Self::BodyTooLarge { .. } => Status::ContentTooLarge,
            Self::UnsupportedVersion => Status::VersionNotSupported,
            Self::BareLineFeed
            | Self::StrayCarriageReturn
            | Self::MalformedRequestLine
            | Self::MalformedMethod
            | Self::MalformedTarget
            | Self::MalformedVersion
            | Self::ObsoleteLineFolding
            | Self::BodyNotAccepted
            | Self::NotUtf8 => Status::BadRequest,
        }
    }
}

/// The blank line that ends a head.
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Read whatever has arrived.
///
/// `body_limit` is the most body the caller can hold, and a head declaring more
/// is refused here rather than accumulated: the bound belongs to the caller
/// because the storage does, and passing it in is what keeps this crate from
/// choosing a buffer size for a protection domain it knows nothing about. A
/// caller that takes no body at all passes zero.
///
/// # Errors
/// [`RequestError`] for a head this server will not read; each names the status
/// the client is owed.
pub fn parse(bytes: &[u8], body_limit: usize) -> Result<Parsed<'_>, RequestError> {
    let terminator = find(bytes, HEAD_TERMINATOR);
    // The head's own bytes and no others: a verdict on *this* head that
    // depended on what follows it is the disagreement about where a message
    // ends that request smuggling is.
    let head_bytes = match terminator {
        Some(end) => bytes
            .get(..end.saturating_add(HEAD_TERMINATOR.len()))
            .unwrap_or(bytes),
        None => bytes,
    };
    check_line_endings(head_bytes)?;
    let Some(end) = terminator else {
        return Ok(Parsed::NeedMore);
    };
    let head = bytes.get(..end).unwrap_or_default();
    let consumed = end.saturating_add(HEAD_TERMINATOR.len());
    let head = core::str::from_utf8(head).map_err(|_| RequestError::NotUtf8)?;

    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let (method, target) = parse_request_line(request_line)?;

    let mut headers = [None; MAX_HEADERS];
    let mut count = 0usize;
    for line in lines {
        // Counted before it is read, so a field past the bound is refused for
        // being one field too many — a 431 — whatever its syntax. Parsing first
        // would answer 400 for the same request and hide the bound behind
        // whichever rule the extra field happened to break.
        let Some(slot) = headers.get_mut(count) else {
            return Err(RequestError::TooManyHeaders);
        };
        *slot = Some(parse_header(line)?);
        count = count.saturating_add(1);
    }

    let mut request = Request {
        method,
        target,
        headers,
        count,
        body_len: 0,
    };
    request.body_len = body_length(&request, body_limit)?;
    Ok(Parsed::Complete { request, consumed })
}

/// Every LF is preceded by a CR and every CR is followed by an LF, so the only
/// line ending in the head is `\r\n`. A trailing CR is not a fault: it is the
/// first half of a terminator whose second half is still on the wire.
fn check_line_endings(bytes: &[u8]) -> Result<(), RequestError> {
    let mut previous: Option<u8> = None;
    for byte in bytes {
        if *byte == b'\n' && previous != Some(b'\r') {
            return Err(RequestError::BareLineFeed);
        }
        if previous == Some(b'\r') && *byte != b'\n' {
            return Err(RequestError::StrayCarriageReturn);
        }
        previous = Some(*byte);
    }
    Ok(())
}

/// `METHOD SP request-target SP HTTP-version`, and nothing else: RFC 9112 section 3
/// admits exactly two spaces, so a target carrying one is a malformed line
/// rather than a target to unescape.
fn parse_request_line(line: &str) -> Result<(&str, &str), RequestError> {
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().ok_or(RequestError::MalformedRequestLine)?;
    let version = parts.next().ok_or(RequestError::MalformedRequestLine)?;
    if parts.next().is_some() {
        return Err(RequestError::MalformedRequestLine);
    }
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(RequestError::MalformedMethod);
    }
    if method.len() > MAX_METHOD_LEN {
        return Err(RequestError::MalformedMethod);
    }
    if target.len() > MAX_TARGET_LEN {
        return Err(RequestError::TargetTooLong);
    }
    // Visible ASCII only: a target is where a control character would reach a
    // log line, and no form of it may carry one.
    if target.is_empty() || !target.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
        return Err(RequestError::MalformedTarget);
    }
    if version != VERSION {
        return Err(version_error(version));
    }
    Ok((method, target))
}

/// A version this server does not speak is 505; a string that is not a version
/// at all is 400. Telling them apart is what makes the status useful.
fn version_error(version: &str) -> RequestError {
    let Some(number) = version.strip_prefix("HTTP/") else {
        return RequestError::MalformedVersion;
    };
    let Some((major, minor)) = number.split_once('.') else {
        return RequestError::MalformedVersion;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if digits(major) && digits(minor) {
        RequestError::UnsupportedVersion
    } else {
        RequestError::MalformedVersion
    }
}

/// `field-name ":" OWS field-value OWS`, with no space before the colon and no
/// continuation lines.
fn parse_header(line: &str) -> Result<Header<'_>, RequestError> {
    if line.starts_with(' ') || line.starts_with('\t') {
        return Err(RequestError::ObsoleteLineFolding);
    }
    let (name, value) = line
        .split_once(':')
        .ok_or(RequestError::MalformedHeaderName)?;
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(RequestError::MalformedHeaderName);
    }
    if name.len() > MAX_HEADER_NAME_LEN {
        return Err(RequestError::MalformedHeaderName);
    }
    let value = value.trim_matches([' ', '\t']);
    if value.len() > MAX_HEADER_VALUE_LEN {
        return Err(RequestError::MalformedHeaderValue);
    }
    // VCHAR, SP and HTAB: RFC 9110 section 5.5's field-content, minus the obs-text a
    // strict recipient need not accept.
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7E).contains(&byte))
    {
        return Err(RequestError::MalformedHeaderValue);
    }
    Ok(Header { name, value })
}

/// How many body bytes follow this head, under the one framing this parser
/// admits.
///
/// Every rejection here is a framing this parser refuses to hold a second opinion
/// about; the crate header states each and why. The order matters in one place: a
/// length is refused for being *unreadable* before it is refused for being *too
/// large*, so a client is told which of the two it did.
fn body_length(request: &Request<'_>, body_limit: usize) -> Result<usize, RequestError> {
    let mut declared: Option<u64> = None;
    for header in request.headers() {
        if equals_ignoring_case(header.name, "transfer-encoding") {
            return Err(RequestError::BodyNotAccepted);
        }
        if equals_ignoring_case(header.name, "content-length") {
            if declared.is_some() {
                return Err(RequestError::BodyNotAccepted);
            }
            declared = Some(content_length(header.value)?);
        }
    }
    let Some(declared) = declared else {
        return Ok(0);
    };
    if declared == 0 {
        return Ok(0);
    }
    if !request.is_post() {
        return Err(RequestError::BodyNotAccepted);
    }
    // Lossless: the comparison is what makes the narrowing exact, and a
    // `body_limit` is a `usize` the caller can hold.
    if declared > body_limit as u64 {
        return Err(RequestError::BodyTooLarge { declared });
    }
    Ok(declared as usize)
}

/// A `Content-Length` value: decimal digits and nothing else, no sign, no
/// whitespace inside, and at most [`MAX_CONTENT_LENGTH_DIGITS`] of them.
///
/// A leading zero is admitted, RFC 9110 section 8.6 stating the field as `1*DIGIT`
/// with no such prohibition; anything the grammar does not admit is refused
/// rather than read as far as it parses, which is where a second party would
/// disagree.
fn content_length(value: &str) -> Result<u64, RequestError> {
    if value.is_empty() || value.len() > MAX_CONTENT_LENGTH_DIGITS {
        return Err(RequestError::BodyNotAccepted);
    }
    let mut declared = 0u64;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return Err(RequestError::BodyNotAccepted);
        }
        // Cannot overflow: ten digits is at most 9_999_999_999, far inside a
        // `u64`, and the length above is what holds it to ten.
        declared = declared
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'));
    }
    Ok(declared)
}

/// RFC 9110 section 5.6.2's `tchar`.
const fn is_token_byte(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn equals_ignoring_case(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .all(|(a, b)| a.eq_ignore_ascii_case(&b))
}

/// The first index at which `needle` begins in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
