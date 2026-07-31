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
    MAX_HEADER_NAME_LEN, MAX_HEADER_VALUE_LEN, MAX_HEADERS, MAX_METHOD_LEN, MAX_TARGET_LEN, Status,
    VERSION,
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
    /// A continuation line: RFC 9112 §5.2 deprecates obs-fold and requires a
    /// server that does not support it to refuse the message.
    ObsoleteLineFolding,
    /// A request announcing a body. See the crate header.
    BodyNotAccepted,
    /// The bytes are not UTF-8, and so not the ASCII a head is made of.
    NotAscii,
}

impl RequestError {
    /// The status the client is owed for this refusal.
    #[must_use]
    pub const fn status(self) -> Status {
        match self {
            Self::TargetTooLong => Status::UriTooLong,
            Self::TooManyHeaders | Self::MalformedHeaderName | Self::MalformedHeaderValue => {
                // 431 covers both "too many" and "one too large", which is what
                // RFC 6585 §5 defines it for; the length rules are the only way
                // to reach these three, a name or value that is merely
                // ill-formed being refused by the same variant.
                Status::HeadersTooLarge
            }
            Self::UnsupportedVersion => Status::VersionNotSupported,
            Self::BareLineFeed
            | Self::StrayCarriageReturn
            | Self::MalformedRequestLine
            | Self::MalformedMethod
            | Self::MalformedTarget
            | Self::MalformedVersion
            | Self::ObsoleteLineFolding
            | Self::BodyNotAccepted
            | Self::NotAscii => Status::BadRequest,
        }
    }
}

/// The blank line that ends a head.
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Read whatever has arrived.
///
/// # Errors
/// [`RequestError`] for a head this server will not read; each names the status
/// the client is owed.
pub fn parse(bytes: &[u8]) -> Result<Parsed<'_>, RequestError> {
    check_line_endings(bytes)?;
    let Some(end) = find(bytes, HEAD_TERMINATOR) else {
        return Ok(Parsed::NeedMore);
    };
    let head = bytes.get(..end).unwrap_or_default();
    let consumed = end.saturating_add(HEAD_TERMINATOR.len());
    let head = core::str::from_utf8(head).map_err(|_| RequestError::NotAscii)?;

    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let (method, target) = parse_request_line(request_line)?;

    let mut headers = [None; MAX_HEADERS];
    let mut count = 0usize;
    for line in lines {
        let header = parse_header(line)?;
        let Some(slot) = headers.get_mut(count) else {
            return Err(RequestError::TooManyHeaders);
        };
        *slot = Some(header);
        count = count.saturating_add(1);
    }

    let request = Request {
        method,
        target,
        headers,
        count,
    };
    refuse_a_body(&request)?;
    Ok(Parsed::Complete { request, consumed })
}

/// Every LF is preceded by a CR and every CR is followed by an LF, so the only
/// line ending in the buffer is `\r\n`.
///
/// A trailing CR with nothing after it yet is not a fault: it is the first half
/// of a terminator whose second half is still on the wire.
fn check_line_endings(bytes: &[u8]) -> Result<(), RequestError> {
    let mut previous: Option<u8> = None;
    for (index, byte) in bytes.iter().enumerate() {
        match *byte {
            b'\n' if previous != Some(b'\r') => return Err(RequestError::BareLineFeed),
            _ => {}
        }
        if previous == Some(b'\r') && *byte != b'\n' && index > 0 {
            return Err(RequestError::StrayCarriageReturn);
        }
        previous = Some(*byte);
    }
    Ok(())
}

/// `METHOD SP request-target SP HTTP-version`, and nothing else: RFC 9112 §3
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
    // VCHAR, SP and HTAB: RFC 9110 §5.5's field-content, minus the obs-text a
    // strict recipient need not accept.
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7E).contains(&byte))
    {
        return Err(RequestError::MalformedHeaderValue);
    }
    Ok(Header { name, value })
}

/// No request this server answers carries a body, and a parser that guessed the
/// framing would be the second opinion request smuggling needs.
fn refuse_a_body(request: &Request<'_>) -> Result<(), RequestError> {
    for header in request.headers() {
        if equals_ignoring_case(header.name, "transfer-encoding") {
            return Err(RequestError::BodyNotAccepted);
        }
        if equals_ignoring_case(header.name, "content-length") && header.value != "0" {
            return Err(RequestError::BodyNotAccepted);
        }
    }
    Ok(())
}

/// RFC 9110 §5.6.2's `tchar`.
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
