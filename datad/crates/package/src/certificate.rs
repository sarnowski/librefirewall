//! The two certificate members: unwrapping the armour they travel in, and
//! walking far enough into one to find the key it binds.
//!
//! # Adversary
//!
//! The **management-plane attacker**, whose bytes these are. Neither half here
//! decides whether a certificate is *trustworthy* — that is the injected chain
//! verifier's, over an adopted parser. What is decided here is structural, and
//! only what a structural answer can settle.
//!
//! # Why a walk and not a search
//!
//! The one question this crate asks of a certificate is whether the key it
//! binds is the appliance's own. Searching the certificate's bytes for the
//! key's encoding would answer a different question: a certificate can carry
//! those bytes in an extension, an issuer name, or a serial number without
//! binding them to anything, and a search would call that a match. So the key
//! is taken from the one place that binds it — the seventh element of the
//! signed body — by descending to it through named elements and refusing
//! anything that is not shaped like a certificate on the way. The descent is
//! eight reads deep and carries no loop, so the work it does is fixed rather
//! than bounded.

use lfw_x509::{MAX_CERTIFICATE_LEN, SPKI_LEN};

/// The armour opening every certificate in this profile.
const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----\n";

/// The line closing it.
const END_LINE: &[u8] = b"-----END CERTIFICATE-----";

/// Base64 characters one armoured line may carry.
const LINE_CHARS: usize = 64;

/// The DER universal tag for a SEQUENCE, constructed.
///
/// The four tags below are public beside [`read_tlv`] and for its reason: a
/// caller descending with this walker needs the alphabet it is written in, and a
/// second copy of `0x30` somewhere else is a byte two readers can disagree about.
pub const SEQUENCE: u8 = 0x30;

/// The DER universal tag for an INTEGER.
pub const INTEGER: u8 = 0x02;

/// The DER universal tag for a BIT STRING, which is how a certificate carries a
/// public key and a signature.
pub const BIT_STRING: u8 = 0x03;

/// The DER universal tag for an OBJECT IDENTIFIER.
pub const OBJECT_IDENTIFIER: u8 = 0x06;

/// The DER tag of the explicit `[0]` the version is wrapped in.
pub const CONTEXT_ZERO: u8 = 0xA0;

/// Which element of a certificate a structural refusal was about.
///
/// The certificate's own vocabulary rather than an offset, so a refusal says
/// where in a certificate the fault is without carrying a byte of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Element {
    Certificate,
    TbsCertificate,
    Version,
    SerialNumber,
    SignatureAlgorithm,
    Issuer,
    Validity,
    Subject,
    SubjectPublicKeyInfo,
    /// The `AlgorithmIdentifier` inside one of the two places a certificate
    /// carries one, and the object identifier inside that.
    AlgorithmIdentifier,
    /// The BIT STRING inside a `SubjectPublicKeyInfo`, which is where the point
    /// itself is.
    SubjectPublicKey,
    /// The BIT STRING a certificate's own signature is in.
    SignatureValue,
}

/// Why a member is not one certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateError {
    /// The member does not open with the encapsulation boundary, so whatever
    /// else it is, it is not one armoured structure with nothing before it.
    MissingBeginBoundary,
    MissingEndBoundary,
    /// A base64 line longer than the encoding permits.
    LineTooLong {
        len: usize,
        bound: usize,
    },
    NotBase64,
    /// Padding somewhere other than the end of the last group.
    PaddingMisplaced,
    /// The base64 ended part way through a group.
    NotAWholeGroup,
    /// Padding whose discarded bits are not zero, which is a second encoding
    /// of one certificate and a place two readers can disagree.
    NonCanonicalPadding,
    /// Something other than line feeds after the closing boundary.
    TrailingContent,
    CertificateIsEmpty,
    CertificateTooLong {
        len: usize,
        bound: usize,
    },
    /// An element ran past the end of what encloses it.
    TruncatedDer {
        element: Element,
    },
    /// An element of a shape a certificate does not have there.
    UnexpectedTag {
        element: Element,
    },
    /// A length in indefinite form, which DER does not have.
    IndefiniteLength {
        element: Element,
    },
    /// A length not written in the fewest octets, which is a second encoding
    /// of one value.
    NonMinimalLength {
        element: Element,
    },
    /// A length wider than an address, so no slice could hold what it names.
    LengthOutOfRange {
        element: Element,
    },
    /// Bytes after the certificate, inside what should hold one.
    TrailingDer,
}

/// One certificate in the encoding the appliance stores and validates it in.
///
/// Fixed storage rather than a borrow, because the armour has to be undone to
/// get here and there is nothing in the member to borrow.
pub struct Certificate {
    der: [u8; MAX_CERTIFICATE_LEN],
    len: usize,
}

impl Certificate {
    /// The certificate, as DER.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.der.get(..self.len).unwrap_or_default()
    }
}

/// Undo the armour and hold what comes out to the shape of a certificate.
///
/// # Errors
/// [`CertificateError`] naming the rule the member broke.
pub(crate) fn decode(member: &[u8]) -> Result<Certificate, CertificateError> {
    let mut der = [0_u8; MAX_CERTIFICATE_LEN];
    let len = unarmour(member, &mut der)?;
    if len == 0 {
        return Err(CertificateError::CertificateIsEmpty);
    }
    let certificate = Certificate { der, len };
    // The walk runs here rather than on demand, so a value of this type is one
    // whose shape has already been answered for.
    subject_public_key_info(certificate.as_bytes())?;
    Ok(certificate)
}

/// The DER `SubjectPublicKeyInfo` the certificate binds, as a whole structure.
///
/// # Errors
/// [`CertificateError`] naming the element that was not shaped like one.
pub fn subject_public_key_info(der: &[u8]) -> Result<&[u8], CertificateError> {
    let (certificate, after) = read_tlv(der, Element::Certificate, SEQUENCE)?;
    if !after.is_empty() {
        return Err(CertificateError::TrailingDer);
    }
    let (tbs, _) = read_tlv(certificate, Element::TbsCertificate, SEQUENCE)?;
    let (_, rest) = read_tlv(tbs, Element::Version, CONTEXT_ZERO)?;
    let (_, rest) = read_tlv(rest, Element::SerialNumber, INTEGER)?;
    let (_, rest) = read_tlv(rest, Element::SignatureAlgorithm, SEQUENCE)?;
    let (_, rest) = read_tlv(rest, Element::Issuer, SEQUENCE)?;
    let (_, rest) = read_tlv(rest, Element::Validity, SEQUENCE)?;
    let (_, rest) = read_tlv(rest, Element::Subject, SEQUENCE)?;
    whole_tlv(rest, Element::SubjectPublicKeyInfo, SEQUENCE)
}

/// Whether the certificate binds exactly this key.
///
/// # Errors
/// [`CertificateError`] where the certificate is not shaped like one.
pub(crate) fn binds_key(
    certificate: &Certificate,
    appliance_key: &[u8; SPKI_LEN],
) -> Result<bool, CertificateError> {
    Ok(subject_public_key_info(certificate.as_bytes())? == appliance_key.as_slice())
}

/// Read one tag-length-value, answering its content and what follows it.
///
/// Public because the appliance has exactly one bounded DER walk and this is it:
/// the domain that checks whether an anchor signed a certificate descends the
/// same structures under the same rules — definite lengths, minimally encoded,
/// nothing running past what encloses it — and a second walk written beside this
/// one would be a second set of those rules to keep true.
pub fn read_tlv(
    bytes: &[u8],
    element: Element,
    expected: u8,
) -> Result<(&[u8], &[u8]), CertificateError> {
    let Some((tag, after_tag)) = bytes.split_first() else {
        return Err(CertificateError::TruncatedDer { element });
    };
    if *tag != expected {
        return Err(CertificateError::UnexpectedTag { element });
    }
    let (length, after_length) = read_length(after_tag, element)?;
    let Some((value, rest)) = after_length.split_at_checked(length) else {
        return Err(CertificateError::TruncatedDer { element });
    };
    Ok((value, rest))
}

/// The same read, answering the structure whole — tag, length and content —
/// which is the encoding a `SubjectPublicKeyInfo` is compared in.
fn whole_tlv(bytes: &[u8], element: Element, expected: u8) -> Result<&[u8], CertificateError> {
    let (_, rest) = read_tlv(bytes, element, expected)?;
    let taken = bytes.len().saturating_sub(rest.len());
    bytes
        .get(..taken)
        .ok_or(CertificateError::TruncatedDer { element })
}

/// A definite, minimally encoded length.
fn read_length(bytes: &[u8], element: Element) -> Result<(usize, &[u8]), CertificateError> {
    let Some((first, rest)) = bytes.split_first() else {
        return Err(CertificateError::TruncatedDer { element });
    };
    if *first < 0x80 {
        return Ok((usize::from(*first), rest));
    }
    let octets = usize::from(*first & 0x7f);
    if octets == 0 {
        return Err(CertificateError::IndefiniteLength { element });
    }
    let Some((digits, after)) = rest.split_at_checked(octets) else {
        return Err(CertificateError::TruncatedDer { element });
    };
    if digits.first() == Some(&0) {
        return Err(CertificateError::NonMinimalLength { element });
    }
    let mut length = 0_usize;
    for digit in digits {
        length = length
            .checked_mul(256)
            .and_then(|shifted| shifted.checked_add(usize::from(*digit)))
            .ok_or(CertificateError::LengthOutOfRange { element })?;
    }
    if length < 0x80 {
        return Err(CertificateError::NonMinimalLength { element });
    }
    Ok((length, after))
}

/// Strip the armour, answering how many DER bytes came out.
fn unarmour(member: &[u8], out: &mut [u8; MAX_CERTIFICATE_LEN]) -> Result<usize, CertificateError> {
    let Some(mut rest) = member.strip_prefix(BEGIN) else {
        return Err(CertificateError::MissingBeginBoundary);
    };
    let mut decoder = Decoder {
        out,
        at: 0,
        packed: 0,
        filled: 0,
        padding: 0,
        closed: false,
    };
    let mut closed = false;
    // One turn per line, and a line carries at least its own ending, so the
    // member's bound is the loop's.
    for _ in 0..member.len() {
        let Some((line, tail)) = split_line(rest) else {
            return Err(CertificateError::MissingEndBoundary);
        };
        rest = tail;
        if line == END_LINE {
            closed = true;
            break;
        }
        if line.len() > LINE_CHARS {
            return Err(CertificateError::LineTooLong {
                len: line.len(),
                bound: LINE_CHARS,
            });
        }
        for character in line {
            decoder.push(*character)?;
        }
    }
    if !closed {
        return Err(CertificateError::MissingEndBoundary);
    }
    // A line feed is not content; the management server ends the armour with a
    // blank line and the appliance's own writer does not, and both are one
    // encapsulated structure with nothing after it.
    if !rest.iter().all(|byte| *byte == b'\n') {
        return Err(CertificateError::TrailingContent);
    }
    decoder.finish()
}

/// One line and what follows it, the ending consumed.
fn split_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = bytes.iter().position(|byte| *byte == b'\n')?;
    let line = bytes.get(..end)?;
    let tail = bytes.get(end.checked_add(1)?..)?;
    Some((line, tail))
}

/// Base64 as RFC 4648 section 4 fixes it, one character at a time, canonical
/// or refused.
struct Decoder<'a> {
    out: &'a mut [u8; MAX_CERTIFICATE_LEN],
    /// DER bytes the input decodes to, counted past the storage so an
    /// over-long certificate is refused by its own length rather than cut.
    at: usize,
    packed: u32,
    filled: u32,
    padding: u32,
    closed: bool,
}

impl Decoder<'_> {
    fn push(&mut self, character: u8) -> Result<(), CertificateError> {
        if self.closed {
            return Err(CertificateError::PaddingMisplaced);
        }
        if character == b'=' {
            // Padding fills only the third and fourth places of a group.
            if self.filled < 2 {
                return Err(CertificateError::PaddingMisplaced);
            }
            self.padding = self.padding.saturating_add(1);
            self.packed <<= 6;
        } else {
            if self.padding > 0 {
                return Err(CertificateError::PaddingMisplaced);
            }
            let Some(sextet) = sextet(character) else {
                return Err(CertificateError::NotBase64);
            };
            self.packed = (self.packed << 6) | u32::from(sextet);
        }
        self.filled = self.filled.saturating_add(1);
        if self.filled == 4 {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), CertificateError> {
        // The padded places contribute nothing, so the bits they displaced must
        // have been zero; anything else is a second spelling of one value.
        let discarded = match self.padding {
            0 => 0,
            1 => 0x0000_00ff,
            _ => 0x0000_ffff,
        };
        if self.packed & discarded != 0 {
            return Err(CertificateError::NonCanonicalPadding);
        }
        let bytes = [
            (self.packed >> 16) as u8,
            (self.packed >> 8) as u8,
            self.packed as u8,
        ];
        let carried = 3_usize.saturating_sub(self.padding as usize);
        for byte in bytes.into_iter().take(carried) {
            if let Some(slot) = self.out.get_mut(self.at) {
                *slot = byte;
            }
            self.at = self.at.saturating_add(1);
        }
        if self.padding > 0 {
            self.closed = true;
        }
        self.packed = 0;
        self.filled = 0;
        Ok(())
    }

    fn finish(self) -> Result<usize, CertificateError> {
        if self.filled != 0 {
            return Err(CertificateError::NotAWholeGroup);
        }
        if self.at > MAX_CERTIFICATE_LEN {
            return Err(CertificateError::CertificateTooLong {
                len: self.at,
                bound: MAX_CERTIFICATE_LEN,
            });
        }
        Ok(self.at)
    }
}

/// The six bits a base64 character stands for.
fn sextet(character: u8) -> Option<u8> {
    match character {
        b'A'..=b'Z' => character.checked_sub(b'A'),
        b'a'..=b'z' => character.checked_sub(b'a').and_then(|c| c.checked_add(26)),
        b'0'..=b'9' => character.checked_sub(b'0').and_then(|c| c.checked_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_must_be_definite_and_minimal() {
        assert_eq!(
            read_length(&[0x80], Element::Certificate),
            Err(CertificateError::IndefiniteLength {
                element: Element::Certificate
            })
        );
        assert_eq!(
            read_length(&[0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1], Element::Certificate),
            Err(CertificateError::LengthOutOfRange {
                element: Element::Certificate
            })
        );
        // A leading zero octet, and a long form spelling a short-form value.
        assert_eq!(
            read_length(&[0x82, 0x00, 0x81], Element::Certificate),
            Err(CertificateError::NonMinimalLength {
                element: Element::Certificate
            })
        );
        assert_eq!(
            read_length(&[0x81, 0x7f], Element::Certificate),
            Err(CertificateError::NonMinimalLength {
                element: Element::Certificate
            })
        );
        assert_eq!(
            read_length(&[0x81, 0x80], Element::Certificate),
            Ok((128, &[][..]))
        );
        assert_eq!(read_length(&[0x05], Element::Certificate), Ok((5, &[][..])));
        assert_eq!(
            read_length(&[], Element::Certificate),
            Err(CertificateError::TruncatedDer {
                element: Element::Certificate
            })
        );
        assert_eq!(
            read_length(&[0x82, 0x01], Element::Certificate),
            Err(CertificateError::TruncatedDer {
                element: Element::Certificate
            })
        );
    }

    #[test]
    fn every_base64_character_stands_for_its_own_sextet() {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (expected, character) in alphabet.iter().enumerate() {
            assert_eq!(sextet(*character).map(usize::from), Some(expected));
        }
        assert_eq!(sextet(b'='), None);
        assert_eq!(sextet(b'-'), None);
    }

    #[test]
    fn a_line_needs_an_ending_to_be_a_line() {
        assert_eq!(split_line(b"ab\ncd"), Some((&b"ab"[..], &b"cd"[..])));
        assert_eq!(split_line(b"ab"), None);
    }
}
