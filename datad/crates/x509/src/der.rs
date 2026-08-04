//! A bounded DER writer: the encoding, and nothing that reads one.

/// Why an encoding did not fit or could not be represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerError {
    /// The caller's buffer ran out. Names how many bytes the value needed at
    /// the point it stopped, which is what a caller sizing a buffer wants.
    OutOfSpace { needed: usize },
    /// A value longer than this writer encodes a length for. Refused rather
    /// than truncated: a structure whose length header disagreed with its
    /// contents is one every parser downstream would reject differently.
    TooLong { bytes: usize },
}

/// The DER tag bytes this writer emits, named where they are used rather than
/// spelled at each call site.
pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OBJECT_IDENTIFIER: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;
pub const UTC_TIME: u8 = 0x17;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// A context-specific constructed tag, `[n]`.
#[must_use]
pub const fn context(number: u8) -> u8 {
    0xa0 | number
}

/// A context-specific primitive tag, `[n]` with no inner structure — what a
/// `GeneralName`'s alternatives use.
#[must_use]
pub const fn context_primitive(number: u8) -> u8 {
    0x80 | number
}

/// The most bytes a length header takes here: the long-form marker and three
/// length bytes, which reaches 16 MiB — far past anything this crate writes.
const MAX_LENGTH_BYTES: usize = 4;

/// The most a header can occupy: the tag and that length.
const MAX_HEADER: usize = 1 + MAX_LENGTH_BYTES;

/// A cursor over a caller's buffer that writes DER into it.
///
/// Every write is bounded by the buffer and answers [`DerError`] rather than
/// panicking, so a structure that outgrows what a caller reserved fails as a
/// value and not as a fault. Nothing here indexes.
///
/// # Adversary
///
/// None today: every value this writes is one the appliance minted — its own
/// key, its own device identifier, a validity window from its own clock. It is
/// written to the standard for an external-input path anyway, because the
/// structures it emits are the ones a peer will one day hand back.
pub struct Writer<'a> {
    buffer: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    #[must_use]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, at: 0 }
    }

    /// How many bytes have been written.
    #[must_use]
    pub fn len(&self) -> usize {
        self.at
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.at == 0
    }

    /// # Errors
    /// [`DerError::OutOfSpace`] where the bytes do not fit.
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), DerError> {
        let end = self
            .at
            .checked_add(bytes.len())
            .ok_or(DerError::TooLong { bytes: usize::MAX })?;
        let target = self
            .buffer
            .get_mut(self.at..end)
            .ok_or(DerError::OutOfSpace { needed: end })?;
        target.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    /// A primitive element: a tag, a length, and the content given.
    ///
    /// # Errors
    /// [`DerError`] where the element does not fit or cannot be lengthed.
    pub fn primitive(&mut self, tag: u8, content: &[u8]) -> Result<(), DerError> {
        self.header(tag, content.len())?;
        self.bytes(content)
    }

    /// A constructed element whose content `body` writes. The length is not
    /// known until `body` has run, so the content is written past a reserved
    /// header and moved back over it once the length is known — which is what
    /// lets one pass write a nested structure into a caller's buffer with no
    /// allocator and no second traversal.
    ///
    /// # Errors
    /// Whatever `body` answers, or [`DerError`] where the element does not fit.
    pub fn constructed(
        &mut self,
        tag: u8,
        body: impl FnOnce(&mut Self) -> Result<(), DerError>,
    ) -> Result<(), DerError> {
        let start = self.at;
        let content_at = start
            .checked_add(MAX_HEADER)
            .ok_or(DerError::TooLong { bytes: usize::MAX })?;
        if content_at > self.buffer.len() {
            return Err(DerError::OutOfSpace { needed: content_at });
        }
        self.at = content_at;
        body(self)?;
        let content_len = self.at.saturating_sub(content_at);
        let mut header = [0_u8; MAX_HEADER];
        let header_len = encode_header(tag, content_len, &mut header)?;
        // The header is at most what was reserved, so the content moves down
        // by the difference and never up over itself.
        self.buffer
            .copy_within(content_at..self.at, start.saturating_add(header_len));
        let target = self
            .buffer
            .get_mut(start..start.saturating_add(header_len))
            .ok_or(DerError::OutOfSpace {
                needed: start.saturating_add(header_len),
            })?;
        target.copy_from_slice(header.get(..header_len).unwrap_or_default());
        self.at = start.saturating_add(header_len).saturating_add(content_len);
        Ok(())
    }

    /// A `BIT STRING` with no unused bits, which is every one this crate
    /// writes: a public key and a signature are both whole bytes.
    ///
    /// # Errors
    /// [`DerError`] where the element does not fit.
    pub fn bit_string(&mut self, content: &[u8]) -> Result<(), DerError> {
        let length = content
            .len()
            .checked_add(1)
            .ok_or(DerError::TooLong { bytes: usize::MAX })?;
        self.header(BIT_STRING, length)?;
        self.bytes(&[0])?;
        self.bytes(content)
    }

    /// A non-negative `INTEGER` from a big-endian magnitude: leading zero
    /// bytes are dropped and one is prepended where the top bit would
    /// otherwise make the value negative. Both are what DER requires, and
    /// neither is optional — a serial number encoded either other way is one a
    /// validator reads as a different number.
    ///
    /// # Errors
    /// [`DerError`] where the element does not fit.
    pub fn unsigned_integer(&mut self, magnitude: &[u8]) -> Result<(), DerError> {
        let significant = magnitude
            .iter()
            .position(|byte| *byte != 0)
            .map_or(&[][..], |at| magnitude.get(at..).unwrap_or_default());
        let Some(first) = significant.first() else {
            return self.primitive(INTEGER, &[0]);
        };
        if *first & 0x80 == 0 {
            return self.primitive(INTEGER, significant);
        }
        let length = significant
            .len()
            .checked_add(1)
            .ok_or(DerError::TooLong { bytes: usize::MAX })?;
        self.header(INTEGER, length)?;
        self.bytes(&[0])?;
        self.bytes(significant)
    }

    fn header(&mut self, tag: u8, length: usize) -> Result<(), DerError> {
        let mut encoded = [0_u8; MAX_HEADER];
        let len = encode_header(tag, length, &mut encoded)?;
        self.bytes(encoded.get(..len).unwrap_or_default())
    }
}

/// The tag and length of an element, written into `out`, and how many bytes
/// that took.
fn encode_header(tag: u8, length: usize, out: &mut [u8; MAX_HEADER]) -> Result<usize, DerError> {
    let Some(slot) = out.first_mut() else {
        return Err(DerError::OutOfSpace { needed: 1 });
    };
    *slot = tag;
    if length < 0x80 {
        // Short form: the length is the byte.
        if let Some(slot) = out.get_mut(1) {
            *slot = length as u8;
        }
        return Ok(2);
    }
    let width = if length <= 0xff {
        1
    } else if length <= 0xffff {
        2
    } else if length <= 0xff_ffff {
        3
    } else {
        return Err(DerError::TooLong { bytes: length });
    };
    if let Some(slot) = out.get_mut(1) {
        *slot = 0x80 | width as u8;
    }
    for step in 0..width {
        let shift = 8 * (width - 1 - step);
        if let Some(slot) = out.get_mut(2 + step) {
            *slot = (length >> shift) as u8;
        }
    }
    Ok(2 + width)
}

#[cfg(test)]
mod tests;
