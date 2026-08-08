//! The armouring every artifact in this profile travels in: RFC 7468's strict
//! textual encoding, written and never read.
//!
//! One encapsulated structure per file, no leading and no trailing content,
//! base64 in lines of at most 64 characters, `\n` endings. Strict rather than
//! lax on purpose — the lax grammar admits explanatory text around the
//! boundaries, and a file whose readers may disagree about where the structure
//! begins is the same class of defect as two parties disagreeing about where a
//! message ends.
//!
//! # Adversary
//!
//! None reaches it: what it encodes is a DER structure this appliance minted.
//! It is written to the standard for an external-input path anyway — every
//! bound is a named constant, nothing indexes and nothing can overflow —
//! because what it produces is served to an unauthenticated peer, and a writer
//! that could be walked off the end of its output by a length is a writer whose
//! caller has to reason about it.

use crate::profile::MAX_CSR_LEN;

/// The label a certificate signing request is encapsulated under.
pub const CSR_LABEL: &str = "CERTIFICATE REQUEST";

/// Base64 characters one line carries, as RFC 7468 section 3 fixes it.
const LINE_CHARS: usize = 64;

/// Bytes the PEM encoding of the longest request this profile writes occupies,
/// derived from [`MAX_CSR_LEN`] rather than measured.
///
/// A caller sizes its buffer from this and can then never be refused: the DER
/// bound above is what the whole derivation stands on.
pub const MAX_CSR_PEM_LEN: usize = pem_bound(CSR_LABEL.len(), MAX_CSR_LEN);

/// Why an encoding could not be written. One variant, because the only thing
/// that can go wrong is the caller's storage — the label and the body are the
/// caller's own and neither is parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PemDoesNotFit {
    pub needed: usize,
    pub capacity: usize,
}

/// Bytes the encapsulation of `body_len` DER bytes under a label of
/// `label_len` characters occupies.
///
/// Written out as arithmetic rather than measured so a bound is derivable in a
/// constant: the two boundary lines, the base64 of the body, and one line
/// ending per line of it.
const fn pem_bound(label_len: usize, body_len: usize) -> usize {
    // "-----BEGIN " + label + "-----\n" and the matching "END", which is one
    // character shorter to open and so is bounded by the longer of the two
    // twice.
    let boundary = 11 + label_len + 6;
    let encoded = base64_len(body_len);
    // Every full line and the short last one each take a line ending; a body of
    // zero bytes takes none, which this over-counts by one and never under.
    let endings = encoded / LINE_CHARS + 1;
    2 * boundary + encoded + endings
}

/// Base64 characters `bytes` encodes to, padded to a multiple of four.
const fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

/// Write `body` encapsulated under `label` into `out`, answering its length.
///
/// # Errors
/// [`PemDoesNotFit`] where `out` is shorter than the encoding, naming both
/// sizes so a caller's own bound can be compared against what was needed. A
/// slice of [`MAX_CSR_PEM_LEN`] bytes can never provoke it for a body inside
/// [`MAX_CSR_LEN`].
pub fn write_pem(label: &str, body: &[u8], out: &mut [u8]) -> Result<usize, PemDoesNotFit> {
    let needed = pem_bound(label.len(), body.len());
    let capacity = out.len();
    let mut writer = Writer { out, at: 0 };
    let write = |writer: &mut Writer<'_>| -> Result<(), Full> {
        writer.bytes(b"-----BEGIN ")?;
        writer.bytes(label.as_bytes())?;
        writer.bytes(b"-----\n")?;
        writer.base64(body)?;
        writer.bytes(b"-----END ")?;
        writer.bytes(label.as_bytes())?;
        writer.bytes(b"-----\n")
    };
    match write(&mut writer) {
        Ok(()) => Ok(writer.at),
        Err(Full) => Err(PemDoesNotFit { needed, capacity }),
    }
}

/// The output ran out. Carried as a unit so the two sizes are reported once, by
/// the one function that knows both.
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

    /// The body, base64 encoded, broken into lines.
    ///
    /// Three input bytes to four characters, the tail padded with `=`. Total
    /// over any length: the chunk iterator yields the short tail as a chunk of
    /// its own, and every index into the alphabet is a six-bit value the table
    /// has 64 entries for.
    fn base64(&mut self, body: &[u8]) -> Result<(), Full> {
        let mut column = 0usize;
        for chunk in body.chunks(3) {
            let mut group = [0u8; 3];
            for (slot, byte) in group.iter_mut().zip(chunk) {
                *slot = *byte;
            }
            // Destructured rather than indexed, so the three bytes are named
            // by the pattern that proves there are three of them.
            let [high, middle, low] = group;
            let packed = (u32::from(high) << 16) | (u32::from(middle) << 8) | u32::from(low);
            for index in 0..4 {
                // A character is written where the input reached it and `=`
                // where it did not: three bytes make four characters, two make
                // three, one makes two.
                let character = if index <= chunk.len() {
                    let shift = 18 - 6 * index;
                    let sextet = ((packed >> shift) & 0x3f) as usize;
                    ALPHABET.get(sextet).copied().unwrap_or(b'=')
                } else {
                    b'='
                };
                self.bytes(&[character])?;
                column = column.saturating_add(1);
                if column == LINE_CHARS {
                    self.bytes(b"\n")?;
                    column = 0;
                }
            }
        }
        // The last line, where it did not end on the bound. A body of zero
        // bytes takes no line at all, which is the one case that writes nothing
        // here.
        if column > 0 {
            self.bytes(b"\n")?;
        }
        Ok(())
    }
}

/// RFC 4648 section 4's alphabet, which RFC 7468 encodes under.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
