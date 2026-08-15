//! Composing a response head into a caller's storage.
//!
//! The head is written *after* the body is known, because `Content-Length` is
//! part of it and a length nobody has measured is a length that can be wrong.
//! The caller renders its body first, then asks for a head, then places the two
//! together — which is why this writes into a slice and returns a length rather
//! than owning anything.
//!
//! **Every response closes the connection.** `Connection: close` is on every
//! head this writes, and it is a decision rather than an omission: keep-alive
//! obliges a server to frame an unbounded sequence of requests on one
//! connection, which is more state per connection and a second place for two
//! parties to disagree about where a message ends. A management request is one
//! request, and answering it and closing is the complete behaviour rather than a
//! subset of one.

use crate::Status;

/// Opaque bytes: this crate parses no format and would be claiming to know one.
pub const OCTET_STREAM_CONTENT_TYPE: &str = "application/octet-stream";

/// The configuration document. `application/xml` rather than `text/xml`, RFC 7303
/// section 9.1 making the latter's default charset US-ASCII where an operator's document declares UTF-8.
pub const XML_CONTENT_TYPE: &str = "application/xml; charset=utf-8";

/// The one page an appliance ever serves a person. The charset is stated
/// because the page carries no markup that could state it a second time — a
/// document declaring its encoding twice is a document with two answers.
pub const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// A PKCS#10 certification request, as RFC 2311 section 3.5 registers it. `charset` is absent
/// deliberately: the media type is defined over the DER structure, and the PEM armouring it travels
/// in is US-ASCII by its own grammar rather than by a parameter.
pub const PKCS10_CONTENT_TYPE: &str = "application/pkcs10";

/// A content type this crate can promise a head for.
///
/// A closed set rather than a `&str`, and that is the whole point of the type:
/// [`MAX_HEAD_LEN`] is derived from exactly these, so a caller that reserves
/// that much room in front of its body can never be refused a head. A `&str`
/// parameter would let a caller name a longer type and be handed a bound that
/// does not hold for it — which is a response that fails to begin rather than
/// one that fails to fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    /// [`OCTET_STREAM_CONTENT_TYPE`]: bytes this crate claims to know nothing
    /// about.
    OctetStream,
    /// [`XML_CONTENT_TYPE`]: the configuration document a node states.
    Xml,
    /// [`HTML_CONTENT_TYPE`]: the onboarding page.
    Html,
    /// [`PKCS10_CONTENT_TYPE`]: the certificate signing request.
    Pkcs10,
}

impl ContentType {
    /// Every variant, so [`MAX_HEAD_LEN`] is derived by iteration rather than
    /// from a list that drifts from the enum.
    pub const ALL: [Self; 4] = [Self::OctetStream, Self::Xml, Self::Html, Self::Pkcs10];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OctetStream => OCTET_STREAM_CONTENT_TYPE,
            Self::Xml => XML_CONTENT_TYPE,
            Self::Html => HTML_CONTENT_TYPE,
            Self::Pkcs10 => PKCS10_CONTENT_TYPE,
        }
    }
}

/// Digits a `u64` content length can take.
const MAX_LENGTH_DIGITS: usize = 20;

/// Bytes the longest head this crate can write occupies, derived from the status
/// table and [`ContentType::ALL`] rather than measured.
///
/// A caller reserves this much in front of its body and can then never be
/// refused a head: [`ContentType`] admits no type longer than this was derived
/// from.
pub const MAX_HEAD_LEN: usize = head_bound();

pub(crate) const fn head_bound() -> usize {
    // "HTTP/1.1 " + code + " " + the longest reason + CRLF
    let mut longest_reason = 0;
    let mut index = 0;
    while index < Status::ALL.len() {
        let reason = Status::ALL[index].reason().len();
        if reason > longest_reason {
            longest_reason = reason;
        }
        index += 1;
    }
    let mut longest_type = 0;
    let mut index = 0;
    while index < ContentType::ALL.len() {
        let content_type = ContentType::ALL[index].as_str().len();
        if content_type > longest_type {
            longest_type = content_type;
        }
        index += 1;
    }
    let status_line = 9 + 3 + 1 + longest_reason + 2;
    let content_type = 14 + longest_type + 2;
    let content_length = 16 + MAX_LENGTH_DIGITS + 2;
    let connection = 19;
    status_line + content_type + content_length + connection + 2
}

/// Why a head could not be written. One variant, because the only thing that can
/// go wrong is the caller's storage — every other input is a value from a closed
/// set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadDoesNotFit {
    pub capacity: usize,
}

/// Write a complete response head into `out`, answering its length.
///
/// `content_type` is omitted where there is no body worth typing; the length is
/// always written, so a client always knows where the message ends without
/// relying on the close.
///
/// `content_length` is a `u64` because it counts bytes on the wire, not bytes
/// anybody holds: a streamed body outruns every buffer a domain owns.
///
/// # Errors
/// [`HeadDoesNotFit`] when `out` is shorter than the head. A slice of
/// [`MAX_HEAD_LEN`] bytes can never provoke it.
pub fn write_head(
    status: Status,
    content_type: Option<ContentType>,
    content_length: u64,
    out: &mut [u8],
) -> Result<usize, HeadDoesNotFit> {
    let capacity = out.len();
    let mut writer = Writer { out, at: 0 };
    let write = |writer: &mut Writer<'_>| -> Result<(), Full> {
        writer.bytes(b"HTTP/1.1 ")?;
        writer.number(u64::from(status.code()))?;
        writer.bytes(b" ")?;
        writer.bytes(status.reason().as_bytes())?;
        writer.bytes(b"\r\n")?;
        if let Some(content_type) = content_type {
            writer.bytes(b"Content-Type: ")?;
            writer.bytes(content_type.as_str().as_bytes())?;
            writer.bytes(b"\r\n")?;
        }
        writer.bytes(b"Content-Length: ")?;
        writer.number(content_length)?;
        writer.bytes(b"\r\n")?;
        writer.bytes(b"Connection: close\r\n\r\n")
    };
    match write(&mut writer) {
        Ok(()) => Ok(writer.at),
        Err(Full) => Err(HeadDoesNotFit { capacity }),
    }
}

struct Full;

struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Full> {
        let end = self.at.checked_add(bytes.len()).ok_or(Full)?;
        let target = self.out.get_mut(self.at..end).ok_or(Full)?;
        target.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn number(&mut self, value: u64) -> Result<(), Full> {
        let mut digits = [b'0'; MAX_LENGTH_DIGITS];
        let mut at = MAX_LENGTH_DIGITS;
        let mut rest = value;
        loop {
            at = at.checked_sub(1).ok_or(Full)?;
            if let Some(digit) = digits.get_mut(at) {
                *digit = b'0'.saturating_add((rest % 10) as u8);
            }
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        self.bytes(digits.get(at..).unwrap_or_default())
    }
}
