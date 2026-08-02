//! The reader that stands between a hostile byte string and everything else.
//!
//! It is a pull reader over the document: [`Reader`] yields one [`Event`] at a
//! time and borrows the document for every name it hands back, so no part of
//! the input is copied except an attribute value, which cannot be borrowed
//! because a reference expands to bytes the document does not contain.
//!
//! # What is refused, and why refusal rather than support
//!
//! The XML features this reader will not implement are the ones whose whole
//! purpose is to make a document mean more than it says: a DTD introduces
//! definitions the document body then expands, an entity declaration makes that
//! expansion recursive, an external entity makes it a fetch, and a CDATA
//! section makes markup out of text a reader was told to ignore. None has a use
//! in a configuration file of six attributes, and each has a well-known attack
//! built on it. Supporting them and bounding the damage is a strictly weaker
//! position than having no code that can be driven at all.
//!
//! The five predefined entities and numeric character references survive
//! because refusing them would make some legal identifier unwritable, and their
//! expansion is fixed rather than document-supplied — the property the whole
//! rest of the list lacks.
//!
//! # Where this reader is not XML
//!
//! Two knowing deviations, both narrowing. **Attribute values are not
//! normalized**: XML turns a tab, line feed or carriage return in a value into a
//! space, and this delivers the bytes — every value the schema admits has a
//! grammar that refuses whitespace, so this changes which refusal a document
//! gets and never whether it gets one. And **a name may not be
//! namespace-qualified**: `:` is outside the name set, so a qualified name ends
//! at the colon and the tag then fails to parse.

use lfw_log::RejectReason;

/// The largest document the reader will look at. Held here rather than at the
/// caller because a bound the caller may forget is a bound the reader does not
/// have.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// How deeply elements may nest. The schema uses three levels; the slack is
/// there so a depth rejection reads as an attack rather than as a schema
/// change.
pub const MAX_DEPTH: usize = 8;

/// Attributes one element may carry. The widest element in the schema carries
/// six.
pub const MAX_ATTRIBUTES: usize = 8;

/// Longest element or attribute name. The longest in the schema is
/// `prefix-length`.
pub const MAX_NAME_LEN: usize = 32;

/// Longest attribute value, counted after references expand — a MAC address,
/// the widest value the schema admits, is seventeen bytes.
pub const MAX_ATTRIBUTE_VALUE_LEN: usize = 32;

/// Longest reference the reader will scan for a `;`: `&#x10FFFF;` is the widest
/// one that can be valid, so anything longer is padding around a value that
/// would have fitted — `&#000000000065;` is a legal-if-padded `A`. Refused as
/// over-long rather than as unterminated, the `;` being further off rather than
/// absent.
const MAX_REFERENCE_LEN: usize = 12;

/// What was wrong with the document, at the granularity a developer and a test
/// need. [`DocumentFault::reason`] narrows it to the closed vocabulary an
/// operator reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DocumentFault {
    /// More bytes than [`MAX_DOCUMENT_BYTES`].
    DocumentTooLarge,
    /// No element at all: an empty document, or one that is only a comment.
    MissingRootElement,
    /// A second element after the root closed.
    TrailingContent,
    /// Non-whitespace text where the schema admits no character data, which is
    /// everywhere.
    CharacterData,
    /// `<!--` with no `-->`.
    UnterminatedComment,
    /// `--` inside a comment, which XML forbids.
    DoubleHyphenInComment,
    /// `<?` with no `?>`.
    UnterminatedProcessingInstruction,
    /// A processing instruction other than an XML declaration at offset zero.
    ProcessingInstruction,
    /// `<!DOCTYPE`.
    Doctype,
    /// `<!ENTITY`.
    EntityDeclaration,
    /// Any other `<!` declaration: DTD markup this schema admits none of.
    MarkupDeclaration,
    /// `<![CDATA[`.
    CdataSection,
    /// `<` followed by something that cannot start a name.
    ExpectedElementName,
    /// A start tag that ends at the end of the document.
    UnterminatedTag,
    /// An attribute name not followed by `=`.
    ExpectedAttributeEquals,
    /// An attribute value not opened by `"` or `'`.
    UnquotedAttributeValue,
    /// An attribute value whose closing quote never arrives.
    UnterminatedAttributeValue,
    /// A raw `<` inside an attribute value.
    LessThanInAttributeValue,
    /// `</name` not closed by `>`.
    UnterminatedEndTag,
    /// An end tag naming an element that is not the innermost open one.
    MismatchedEndTag,
    /// An end tag with no element open.
    UnexpectedEndTag,
    /// The document ends with an element still open.
    UnclosedElement,
    /// Nesting past [`MAX_DEPTH`].
    DepthExceeded,
    /// A name longer than [`MAX_NAME_LEN`].
    NameTooLong,
    /// A value longer than [`MAX_ATTRIBUTE_VALUE_LEN`] once references expand.
    ValueTooLong,
    /// More than [`MAX_ATTRIBUTES`] attributes on one element.
    TooManyAttributes,
    /// One element carrying the same attribute name twice.
    DuplicateAttribute,
    /// A `&` with no `;` before the document ends.
    UnterminatedReference,
    /// A reference whose `;` is further away than [`MAX_REFERENCE_LEN`].
    ReferenceTooLong,
    /// A named reference outside the five predefined entities.
    UnknownEntityReference,
    /// A numeric reference that is not a character XML admits.
    InvalidCharacterReference,
    /// An element the schema does not admit at this point.
    UnknownElement,
    /// A second `<interfaces>`, `<neighbours>` or `<management>`. Distinct from
    /// [`Self::UnknownElement`]: the element is one the schema names, and what
    /// is wrong is that it is the second.
    DuplicateElement,
    /// An attribute the schema does not admit on this element.
    UnknownAttribute,
    /// An element or attribute the schema requires and the document omits.
    MissingElement,
    /// An attribute the schema requires and the element omits.
    MissingAttribute,
    /// An attribute value that is not the shape its attribute admits.
    MalformedValue,
    /// More objects than the handover image has slots for.
    CapacityExceeded,
}

impl DocumentFault {
    /// The token an operator reads. Several faults share one: the vocabulary is
    /// sized to what somebody would go and change in the document, and every
    /// unterminated construct is one edit.
    #[must_use]
    pub const fn reason(self) -> RejectReason {
        match self {
            Self::DocumentTooLarge => RejectReason::DocumentTooLarge,
            Self::MissingRootElement | Self::MissingElement => RejectReason::MissingElement,
            Self::CharacterData | Self::CdataSection => RejectReason::UnexpectedCharacterData,
            Self::Doctype | Self::MarkupDeclaration => RejectReason::Doctype,
            Self::EntityDeclaration => RejectReason::EntityDeclaration,
            Self::DepthExceeded => RejectReason::DepthExceeded,
            Self::NameTooLong => RejectReason::NameTooLong,
            Self::ValueTooLong => RejectReason::ValueTooLong,
            Self::TooManyAttributes => RejectReason::TooManyAttributes,
            Self::DuplicateAttribute => RejectReason::DuplicateAttribute,
            Self::UnknownEntityReference => RejectReason::UnknownEntityReference,
            Self::InvalidCharacterReference => RejectReason::InvalidCharacterReference,
            Self::UnknownElement => RejectReason::UnknownElement,
            Self::UnknownAttribute => RejectReason::UnknownAttribute,
            Self::MissingAttribute => RejectReason::MissingAttribute,
            Self::MalformedValue => RejectReason::MalformedValue,
            Self::CapacityExceeded => RejectReason::CapacityExceeded,
            Self::TrailingContent
            | Self::UnterminatedComment
            | Self::UnterminatedProcessingInstruction
            | Self::ProcessingInstruction
            | Self::ExpectedElementName
            | Self::UnterminatedTag
            | Self::ExpectedAttributeEquals
            | Self::UnquotedAttributeValue
            | Self::UnterminatedAttributeValue
            | Self::LessThanInAttributeValue
            | Self::UnterminatedEndTag
            | Self::MismatchedEndTag
            | Self::UnexpectedEndTag
            | Self::UnclosedElement
            | Self::DoubleHyphenInComment
            | Self::ReferenceTooLong
            // The operator vocabulary has no duplicate-element token, and a
            // second `<interfaces>` is a structural fault like the rest of this
            // group; which element it was is the offset beside it.
            | Self::DuplicateElement
            | Self::UnterminatedReference => RejectReason::Malformed,
        }
    }
}

/// A rejection and where in the document it was decided.
///
/// The offset is the whole of what is reported about the position, and there is
/// no field for the bytes: an operator gets somewhere to look and a console
/// gets nothing an attacker chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocumentError {
    pub fault: DocumentFault,
    pub offset: u32,
}

impl DocumentError {
    pub(crate) fn at(fault: DocumentFault, offset: usize) -> Self {
        Self {
            fault,
            offset: u32::try_from(offset).unwrap_or(u32::MAX),
        }
    }

    #[must_use]
    pub const fn reason(self) -> RejectReason {
        self.fault.reason()
    }
}

/// One attribute value, expanded.
///
/// It owns its bytes because a reference does not appear in the document as
/// what it means: `&#119;` is six bytes there and one byte here, so there is
/// nothing to borrow. Sized at [`MAX_ATTRIBUTE_VALUE_LEN`], which is what keeps
/// the type `Copy` and the reader free of an allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeValue {
    bytes: [u8; MAX_ATTRIBUTE_VALUE_LEN],
    len: usize,
}

impl AttributeValue {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_ATTRIBUTE_VALUE_LEN],
            len: 0,
        }
    }

    /// The fallback is unreachable — `len` only ever advances through `push`,
    /// which refuses to move it past the array — and an empty slice rather than
    /// a panic because a branch safe Rust cannot delete is not a failure to
    /// surface.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, byte: u8) -> Result<(), ()> {
        let next = self.len.saturating_add(1);
        match self.bytes.get_mut(self.len) {
            Some(slot) => {
                *slot = byte;
                self.len = next;
                Ok(())
            }
            None => Err(()),
        }
    }
}

/// One attribute, with both of the positions a rejection about it needs: an
/// unknown attribute is reported where its name is, and a value that will not
/// parse is reported where its value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub name: &'a [u8],
    pub name_offset: u32,
    pub value: AttributeValue,
    pub value_offset: u32,
}

/// A start tag: its name, where it began, and its attributes in source order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    pub name: &'a [u8],
    pub offset: u32,
    attributes: [Option<Attribute<'a>>; MAX_ATTRIBUTES],
}

impl<'a> Element<'a> {
    #[must_use]
    pub fn attribute(&self, name: &[u8]) -> Option<&Attribute<'a>> {
        self.attributes().find(|entry| entry.name == name)
    }

    pub fn attributes(&self) -> impl Iterator<Item = &Attribute<'a>> {
        self.attributes.iter().flatten()
    }

    #[must_use]
    pub fn attribute_count(&self) -> usize {
        self.attributes().count()
    }
}

/// What the reader hands back. A `<x/>` produces a [`Event::Start`] and then a
/// [`Event::End`], so a consumer never has to ask which spelling was used.
///
/// The variants are lopsided because a start tag carries its attributes and an
/// end tag has none. Clippy's remedy for that is a `Box`, which needs the
/// allocator this crate does not have; the value is a temporary the consumer
/// destructures immediately, so what it costs is one half-kilobyte frame rather
/// than anything retained.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing the large variant needs an allocator; see the note above"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    Start(Element<'a>),
    End { name: &'a [u8], offset: u32 },
}

/// A pull reader over one document.
///
/// Fused on the first rejection: once a document has been refused there is no
/// position left that means anything, so continuing to read it would be reading
/// bytes chosen by whoever broke it.
pub struct Reader<'a> {
    document: &'a [u8],
    at: usize,
    /// Where the content starts: past a byte order mark, or zero. The
    /// declaration is admitted here rather than at offset zero, a mark being
    /// part of the encoding and not part of the document.
    prologue: usize,
    open: [Option<(&'a [u8], usize)>; MAX_DEPTH],
    depth: usize,
    pending_close: Option<(&'a [u8], usize)>,
    seen_root: bool,
    finished: bool,
}

/// The UTF-8 byte order mark, which XML admits before the declaration. Skipped
/// rather than refused: it says the encoding is the one this reader already
/// requires, and faulting a document for three bytes an operator cannot see and
/// did not type helps nobody. Offsets stay absolute, so a refusal after one
/// still points at a real byte.
const BYTE_ORDER_MARK: [u8; 3] = [0xEF, 0xBB, 0xBF];

impl<'a> Reader<'a> {
    /// # Errors
    /// [`DocumentFault::DocumentTooLarge`] when the document is longer than
    /// [`MAX_DOCUMENT_BYTES`], reported at the first byte past the bound.
    pub fn new(document: &'a [u8]) -> Result<Self, DocumentError> {
        if document.len() > MAX_DOCUMENT_BYTES {
            return Err(DocumentError::at(
                DocumentFault::DocumentTooLarge,
                MAX_DOCUMENT_BYTES,
            ));
        }
        let prologue = usize::from(document.starts_with(&BYTE_ORDER_MARK)) * BYTE_ORDER_MARK.len();
        Ok(Self {
            document,
            at: prologue,
            prologue,
            open: [None; MAX_DEPTH],
            depth: 0,
            pending_close: None,
            seen_root: false,
            finished: false,
        })
    }

    fn advance(&mut self) -> Result<Option<Event<'a>>, DocumentError> {
        if let Some((name, offset)) = self.pending_close.take() {
            self.pop_open();
            return Ok(Some(Event::End {
                name,
                offset: u32::try_from(offset).unwrap_or(u32::MAX),
            }));
        }
        loop {
            let Some(at) = self.skip_to_markup()? else {
                return self.at_end();
            };
            if starts_with(self.document, at, b"<!--") {
                self.at = self.skip_comment(at)?;
            } else if starts_with(self.document, at, b"<?") {
                self.at = self.skip_declaration(at)?;
            } else if starts_with(self.document, at, b"<!") {
                return Err(DocumentError::at(
                    classify_declaration(self.document, at),
                    at,
                ));
            } else if starts_with(self.document, at, b"</") {
                return self.close_element(at).map(Some);
            } else {
                return self.open_element(at).map(Some);
            }
        }
    }

    /// What the end of the document means, which depends entirely on what is
    /// still open.
    fn at_end(&self) -> Result<Option<Event<'a>>, DocumentError> {
        if let Some((_, offset)) = self.innermost() {
            return Err(DocumentError::at(DocumentFault::UnclosedElement, offset));
        }
        if !self.seen_root {
            return Err(DocumentError::at(DocumentFault::MissingRootElement, 0));
        }
        Ok(None)
    }

    fn innermost(&self) -> Option<(&'a [u8], usize)> {
        self.depth
            .checked_sub(1)
            .and_then(|index| self.open.get(index))
            .copied()
            .flatten()
    }

    fn pop_open(&mut self) {
        if let Some(index) = self.depth.checked_sub(1)
            && let Some(slot) = self.open.get_mut(index)
        {
            *slot = None;
            self.depth = index;
        }
    }

    fn push_open(&mut self, name: &'a [u8], offset: usize) -> Result<(), DocumentError> {
        match self.open.get_mut(self.depth) {
            Some(slot) => {
                *slot = Some((name, offset));
                self.depth = self.depth.saturating_add(1);
                Ok(())
            }
            None => Err(DocumentError::at(DocumentFault::DepthExceeded, offset)),
        }
    }

    /// Advance to the next `<`, refusing anything but whitespace on the way.
    ///
    /// This is where mixed content dies: the schema permits character data
    /// nowhere, so every byte between two pieces of markup is checked once,
    /// here, rather than per element type.
    fn skip_to_markup(&mut self) -> Result<Option<usize>, DocumentError> {
        let mut at = self.at;
        while let Some(&byte) = self.document.get(at) {
            if byte == b'<' {
                self.at = at;
                return Ok(Some(at));
            }
            if !byte.is_ascii_whitespace() {
                return Err(DocumentError::at(DocumentFault::CharacterData, at));
            }
            at = at.saturating_add(1);
        }
        self.at = at;
        Ok(None)
    }

    /// A comment, ending at the first `--` — which XML requires to be the one
    /// that closes it. Scanning for `-->` instead would take
    /// `<!-- a -- b -->` for a comment, and read as markup the text a writer
    /// believed was commented out.
    fn skip_comment(&self, at: usize) -> Result<usize, DocumentError> {
        let body = at.saturating_add(4);
        let Some(hyphens) = find(self.document, body, b"--") else {
            return Err(DocumentError::at(DocumentFault::UnterminatedComment, at));
        };
        let after = hyphens.saturating_add(2);
        if self.document.get(after) == Some(&b'>') {
            return Ok(after.saturating_add(1));
        }
        Err(DocumentError::at(
            DocumentFault::DoubleHyphenInComment,
            hyphens,
        ))
    }

    /// The XML declaration, and only at offset zero. Everything else spelled
    /// `<?` is a processing instruction, which is an instruction to a consumer
    /// this document has no business addressing.
    fn skip_declaration(&self, at: usize) -> Result<usize, DocumentError> {
        let is_declaration = at == self.prologue
            && starts_with(self.document, at, b"<?xml")
            && self
                .document
                .get(at.saturating_add(5))
                .is_some_and(u8::is_ascii_whitespace);
        if !is_declaration {
            return Err(DocumentError::at(DocumentFault::ProcessingInstruction, at));
        }
        match find(self.document, at.saturating_add(2), b"?>") {
            Some(end) => Ok(end.saturating_add(2)),
            None => Err(DocumentError::at(
                DocumentFault::UnterminatedProcessingInstruction,
                at,
            )),
        }
    }

    fn open_element(&mut self, at: usize) -> Result<Event<'a>, DocumentError> {
        if self.seen_root && self.depth == 0 {
            return Err(DocumentError::at(DocumentFault::TrailingContent, at));
        }
        let (name, after_name) = self.read_name(at.saturating_add(1))?;
        let tag = self.read_attributes(after_name, at)?;
        self.push_open(name, at)?;
        self.seen_root = true;
        self.at = tag.next;
        if tag.self_closing {
            self.pending_close = Some((name, at));
        }
        Ok(Event::Start(Element {
            name,
            offset: u32::try_from(at).unwrap_or(u32::MAX),
            attributes: tag.attributes,
        }))
    }

    fn close_element(&mut self, at: usize) -> Result<Event<'a>, DocumentError> {
        let (name, after_name) = self.read_name(at.saturating_add(2))?;
        let next = skip_whitespace(self.document, after_name);
        if self.document.get(next) != Some(&b'>') {
            return Err(DocumentError::at(DocumentFault::UnterminatedEndTag, at));
        }
        let Some((open, _)) = self.innermost() else {
            return Err(DocumentError::at(DocumentFault::UnexpectedEndTag, at));
        };
        if open != name {
            return Err(DocumentError::at(DocumentFault::MismatchedEndTag, at));
        }
        self.pop_open();
        self.at = next.saturating_add(1);
        Ok(Event::End {
            name,
            offset: u32::try_from(at).unwrap_or(u32::MAX),
        })
    }

    /// An XML name, bounded by [`MAX_NAME_LEN`] rather than by where it happens
    /// to end: a name is scanned before anything is known about the element, so
    /// the bound has to come from here and not from the schema.
    ///
    /// `:` is absent from the continuation set, so a namespace-qualified name
    /// ends at the colon and the tag then fails to parse. This schema has no
    /// namespaces and giving one a name is not something to do quietly.
    fn read_name(&self, at: usize) -> Result<(&'a [u8], usize), DocumentError> {
        let starts = self
            .document
            .get(at)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_');
        if !starts {
            return Err(DocumentError::at(DocumentFault::ExpectedElementName, at));
        }
        let mut end = at.saturating_add(1);
        while self
            .document
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            end = end.saturating_add(1);
            if end.saturating_sub(at) > MAX_NAME_LEN {
                return Err(DocumentError::at(DocumentFault::NameTooLong, at));
            }
        }
        match self.document.get(at..end) {
            Some(name) => Ok((name, end)),
            None => Err(DocumentError::at(DocumentFault::ExpectedElementName, at)),
        }
    }

    fn read_attributes(&self, mut at: usize, tag: usize) -> Result<StartTag<'a>, DocumentError> {
        let mut attributes: [Option<Attribute<'a>>; MAX_ATTRIBUTES] = [None; MAX_ATTRIBUTES];
        let mut count = 0usize;
        loop {
            at = skip_whitespace(self.document, at);
            match self.document.get(at) {
                None => return Err(DocumentError::at(DocumentFault::UnterminatedTag, tag)),
                Some(b'>') => {
                    return Ok(StartTag {
                        attributes,
                        self_closing: false,
                        next: at.saturating_add(1),
                    });
                }
                Some(b'/') if self.document.get(at.saturating_add(1)) == Some(&b'>') => {
                    return Ok(StartTag {
                        attributes,
                        self_closing: true,
                        next: at.saturating_add(2),
                    });
                }
                Some(_) => {}
            }

            let (name, after_name) = self.read_name(at)?;
            let equals = skip_whitespace(self.document, after_name);
            if self.document.get(equals) != Some(&b'=') {
                return Err(DocumentError::at(
                    DocumentFault::ExpectedAttributeEquals,
                    at,
                ));
            }
            let value_at = skip_whitespace(self.document, equals.saturating_add(1));
            let (value, next) = self.read_value(value_at)?;

            if attributes
                .iter()
                .flatten()
                .any(|seen: &Attribute<'a>| seen.name == name)
            {
                return Err(DocumentError::at(DocumentFault::DuplicateAttribute, at));
            }
            match attributes.get_mut(count) {
                Some(slot) => {
                    *slot = Some(Attribute {
                        name,
                        name_offset: u32::try_from(at).unwrap_or(u32::MAX),
                        value,
                        value_offset: u32::try_from(value_at).unwrap_or(u32::MAX),
                    });
                    count = count.saturating_add(1);
                }
                None => return Err(DocumentError::at(DocumentFault::TooManyAttributes, at)),
            }
            at = next;
        }
    }

    /// A quoted attribute value, expanded as it is read.
    ///
    /// Expanding inline is what bounds the scan: the raw bytes are consumed
    /// only as long as the expansion still fits, so a value the document
    /// declares to be sixty kilobytes is refused after tens of bytes rather
    /// than after sixty kilobytes.
    fn read_value(&self, at: usize) -> Result<(AttributeValue, usize), DocumentError> {
        let Some(&quote @ (b'"' | b'\'')) = self.document.get(at) else {
            return Err(DocumentError::at(DocumentFault::UnquotedAttributeValue, at));
        };
        let mut value = AttributeValue::empty();
        let mut cursor = at.saturating_add(1);
        while let Some(&byte) = self.document.get(cursor) {
            if byte == quote {
                return Ok((value, cursor.saturating_add(1)));
            }
            if byte == b'<' {
                return Err(DocumentError::at(
                    DocumentFault::LessThanInAttributeValue,
                    cursor,
                ));
            }
            if byte == b'&' {
                cursor = self.expand_reference(cursor, &mut value)?;
                continue;
            }
            if value.push(byte).is_err() {
                return Err(DocumentError::at(DocumentFault::ValueTooLong, cursor));
            }
            cursor = cursor.saturating_add(1);
        }
        Err(DocumentError::at(
            DocumentFault::UnterminatedAttributeValue,
            at,
        ))
    }

    /// One reference at `at`, appended to `value`; returns the index past its
    /// `;`.
    fn expand_reference(
        &self,
        at: usize,
        value: &mut AttributeValue,
    ) -> Result<usize, DocumentError> {
        let body_at = at.saturating_add(1);
        let window = self
            .document
            .get(body_at..body_at.saturating_add(MAX_REFERENCE_LEN))
            .or_else(|| self.document.get(body_at..))
            .unwrap_or_default();
        let Some(length) = window.iter().position(|byte| *byte == b';') else {
            // Which of the two turns on why the window ended: the bound, or the
            // document.
            let bounded = body_at.saturating_add(MAX_REFERENCE_LEN) <= self.document.len();
            let fault = if bounded {
                DocumentFault::ReferenceTooLong
            } else {
                DocumentFault::UnterminatedReference
            };
            return Err(DocumentError::at(fault, at));
        };
        let body = window.get(..length).unwrap_or_default();
        let next = body_at.saturating_add(length).saturating_add(1);

        let expanded = match body {
            b"lt" => '<',
            b"gt" => '>',
            b"amp" => '&',
            b"apos" => '\'',
            b"quot" => '"',
            _ => match body.split_first() {
                Some((b'#', digits)) => character_reference(digits).ok_or(DocumentError::at(
                    DocumentFault::InvalidCharacterReference,
                    at,
                ))?,
                _ => {
                    return Err(DocumentError::at(DocumentFault::UnknownEntityReference, at));
                }
            },
        };
        let mut encoded = [0u8; 4];
        for byte in expanded.encode_utf8(&mut encoded).as_bytes() {
            if value.push(*byte).is_err() {
                return Err(DocumentError::at(DocumentFault::ValueTooLong, at));
            }
        }
        Ok(next)
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Event<'a>, DocumentError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.advance() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => {
                self.finished = true;
                None
            }
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

struct StartTag<'a> {
    attributes: [Option<Attribute<'a>>; MAX_ATTRIBUTES],
    self_closing: bool,
    next: usize,
}

/// Which `<!` this is. `<!DOCTYPE` and `<!ENTITY` are named because they are
/// the two an operator might have written on purpose; everything else spelled
/// `<!` is DTD markup and reads as one refusal.
fn classify_declaration(document: &[u8], at: usize) -> DocumentFault {
    if starts_with(document, at, b"<!DOCTYPE") {
        DocumentFault::Doctype
    } else if starts_with(document, at, b"<!ENTITY") {
        DocumentFault::EntityDeclaration
    } else if starts_with(document, at, b"<![CDATA[") {
        DocumentFault::CdataSection
    } else {
        DocumentFault::MarkupDeclaration
    }
}

/// A numeric character reference's digits, as the character they name.
///
/// `None` covers every way it can fail to be one: no digits, a digit that is
/// not one, a value past the Unicode range, a surrogate, and the control
/// characters XML's `Char` production excludes. The last is the reason this
/// does not stop at [`char::from_u32`] — `&#0;` is a scalar value and is not a
/// character any XML document may contain.
fn character_reference(digits: &[u8]) -> Option<char> {
    let (radix, digits) = match digits.split_first() {
        Some((b'x' | b'X', rest)) => (16u32, rest),
        _ => (10u32, digits),
    };
    if digits.is_empty() {
        return None;
    }
    let mut code = 0u32;
    for byte in digits {
        let digit = char::from(*byte).to_digit(radix)?;
        code = code.checked_mul(radix)?.checked_add(digit)?;
    }
    let character = char::from_u32(code)?;
    let admissible = matches!(
        code,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    );
    admissible.then_some(character)
}

fn find(document: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let rest = document.get(from..)?;
    if needle.is_empty() || needle.len() > rest.len() {
        return None;
    }
    rest.windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from.saturating_add(offset))
}

fn starts_with(document: &[u8], at: usize, prefix: &[u8]) -> bool {
    document
        .get(at..)
        .is_some_and(|rest| rest.starts_with(prefix))
}

fn skip_whitespace(document: &[u8], mut at: usize) -> usize {
    while document.get(at).is_some_and(u8::is_ascii_whitespace) {
        at = at.saturating_add(1);
    }
    at
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{vec, vec::Vec};

    /// Every event a document produces, or the first rejection it produced.
    fn read(document: &[u8]) -> Result<Vec<Event<'_>>, DocumentError> {
        Reader::new(document)?.collect()
    }

    fn refusal(document: &[u8]) -> DocumentError {
        match read(document) {
            Err(error) => error,
            Ok(events) => panic!("expected a rejection, read {} events", events.len()),
        }
    }

    /// The fault and where it was decided, which is the whole of what a
    /// rejection promises.
    fn assert_refused(document: &[u8], fault: DocumentFault, offset: u32) {
        let error = refusal(document);
        assert_eq!(error.fault, fault, "document {document:?}");
        assert_eq!(error.offset, offset, "document {document:?}");
    }

    fn names<'a>(events: &[Event<'a>]) -> Vec<&'a [u8]> {
        events
            .iter()
            .map(|event| match event {
                Event::Start(element) => element.name,
                Event::End { name, .. } => *name,
            })
            .collect()
    }

    #[test]
    fn a_self_closing_element_reads_as_a_start_and_an_end() {
        let events = read(b"<a><b x=\"1\"/></a>").expect("well formed");
        assert_eq!(names(&events), [&b"a"[..], b"b", b"b", b"a"]);
        let Event::Start(element) = events[1] else {
            panic!("the second event is the start of <b>");
        };
        assert_eq!(element.attribute(b"x").expect("x").value.as_bytes(), b"1");
        assert_eq!(element.attribute_count(), 1);
        assert!(element.attribute(b"y").is_none());
    }

    #[test]
    fn a_declaration_and_comments_and_whitespace_are_not_events() {
        let document = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- a note -->\n  <a/>\n<!-- after -->\n";
        let events = read(document).expect("well formed");
        assert_eq!(names(&events), [&b"a"[..], b"a"]);
    }

    #[test]
    fn attributes_come_back_in_source_order_with_their_positions() {
        let events = read(b"<a one=\"1\" two=\"2\"/>").expect("well formed");
        let Event::Start(element) = events[0] else {
            panic!("a start");
        };
        let attributes: Vec<&[u8]> = element.attributes().map(|entry| entry.name).collect();
        assert_eq!(attributes, [&b"one"[..], b"two"]);
        let two = element.attribute(b"two").expect("two");
        assert_eq!(two.name_offset, 11);
        assert_eq!(two.value_offset, 15);
    }

    #[test]
    fn single_quoted_values_are_read_the_same_as_double_quoted_ones() {
        let events = read(b"<a x='wan'/>").expect("well formed");
        let Event::Start(element) = events[0] else {
            panic!("a start");
        };
        assert_eq!(element.attribute(b"x").expect("x").value.as_bytes(), b"wan");
    }

    #[test]
    fn an_empty_attribute_value_is_a_value() {
        let events = read(b"<a x=\"\"/>").expect("well formed");
        let Event::Start(element) = events[0] else {
            panic!("a start");
        };
        let value = element.attribute(b"x").expect("x").value;
        assert!(value.is_empty());
        assert_eq!(value.len(), 0);
        assert_eq!(value.as_bytes(), b"");
    }

    #[test]
    fn the_five_predefined_entities_expand_and_nothing_else_named_does() {
        let events = read(b"<a x=\"&lt;&gt;&amp;&apos;&quot;\"/>").expect("well formed");
        let Event::Start(element) = events[0] else {
            panic!("a start");
        };
        assert_eq!(
            element.attribute(b"x").expect("x").value.as_bytes(),
            b"<>&'\""
        );
        assert_refused(
            b"<a x=\"&nbsp;\"/>",
            DocumentFault::UnknownEntityReference,
            6,
        );
    }

    #[test]
    fn numeric_character_references_expand_in_both_radices() {
        let events = read(b"<a x=\"&#119;&#x61;&#x6E;&#128169;\"/>").expect("well formed");
        let Event::Start(element) = events[0] else {
            panic!("a start");
        };
        assert_eq!(
            element.attribute(b"x").expect("x").value.as_bytes(),
            "wan\u{1f4a9}".as_bytes()
        );
    }

    #[test]
    fn a_character_reference_outside_the_scalar_range_is_refused() {
        for document in [
            &b"<a x=\"&#xD800;\"/>"[..],
            b"<a x=\"&#x110000;\"/>",
            b"<a x=\"&#0;\"/>",
            b"<a x=\"&#x1;\"/>",
            b"<a x=\"&#xFFFE;\"/>",
            b"<a x=\"&#;\"/>",
            b"<a x=\"&#x;\"/>",
            b"<a x=\"&#zz;\"/>",
            b"<a x=\"&#99999999;\"/>",
        ] {
            assert_refused(document, DocumentFault::InvalidCharacterReference, 6);
        }
    }

    #[test]
    /// The scan for a `;` is bounded, so what a reference is refused for turns
    /// on why the window ran out: the document ended, or the bound did.
    fn a_reference_that_never_terminates_is_refused_within_a_bounded_window() {
        // The bound ran out. No `;` was seen within the longest reference that
        // can be valid, so the reference is too long to be one — whether a `;`
        // sits further along is a question the reader deliberately does not scan
        // far enough to answer, and does not need to.
        assert_refused(
            b"<a x=\"&aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"/>",
            DocumentFault::ReferenceTooLong,
            6,
        );
        // A valid character reference padded past the bound: `&#65;` is `A`, and
        // this is the same character written with nine leading zeroes. Refused,
        // and refused as over-long rather than as missing the `;` it has.
        assert_refused(
            b"<a x=\"&#000000000065;\"/>",
            DocumentFault::ReferenceTooLong,
            6,
        );
        // Exactly at the bound, from both sides: `&#x10FFFF;` is the widest
        // reference that can be valid and is not refused for its length.
        assert_eq!(
            read(b"<a x=\"&#x10FFFF;\"/>").map(|events| events.len()),
            Ok(2)
        );

        // The document ended. Nothing further could have terminated it.
        assert_refused(b"<a x=\"&\"/>", DocumentFault::UnterminatedReference, 6);
        assert_refused(b"<a x=\"&amp", DocumentFault::UnterminatedReference, 6);
    }

    /// XML forbids `--` inside a comment, and the reason is not pedantry: a
    /// writer who wrote `<!-- a -- b -->` believed everything up to the last
    /// `>` was commented out, and a reader scanning for `-->` would agree with
    /// them. A reader that instead ended the comment at the inner `--` would
    /// read `b` as markup. Refused, so neither reading is taken.
    #[test]
    fn a_double_hyphen_inside_a_comment_is_refused() {
        assert_refused(
            b"<!-- a -- b --><configuration/>",
            DocumentFault::DoubleHyphenInComment,
            7,
        );
        // `<!--->` is not an empty comment either: its single body hyphen
        // leaves no `--` to close on, so the comment simply never ends.
        assert_refused(b"<!---><a/>", DocumentFault::UnterminatedComment, 0);
        // The empty comment, which is well formed, and one whose body merely
        // contains single hyphens.
        assert_eq!(read(b"<!----><a/>").map(|events| events.len()), Ok(2));
        assert_eq!(
            read(b"<!-- a-b -c --><a/>").map(|events| events.len()),
            Ok(2)
        );
        assert_refused(b"<!-- unclosed", DocumentFault::UnterminatedComment, 0);
    }

    /// A UTF-8 byte order mark is legal before the declaration and says the
    /// encoding is the one this reader requires, so it is skipped rather than
    /// read as character data. Offsets stay absolute, so a refusal after one
    /// still points at the byte it was decided at.
    #[test]
    fn a_leading_byte_order_mark_is_part_of_the_encoding_and_not_of_the_document() {
        let mut marked = vec![0xEF, 0xBB, 0xBF];
        marked.extend_from_slice(b"<?xml version=\"1.0\"?><a/>");
        assert_eq!(
            names(&read(&marked).expect("a marked document")),
            [&b"a"[..], b"a"]
        );

        // Without a declaration too, and the offset of a later fault is counted
        // from the start of the file rather than from the start of the content.
        let mut plain = vec![0xEF, 0xBB, 0xBF];
        plain.extend_from_slice(b"<a>x</a>");
        assert_refused(&plain, DocumentFault::CharacterData, 6);

        // Only at the very start: three bytes anywhere else are character data,
        // and a partial mark is not one.
        let mut trailing = Vec::from(&b"<a/>"[..]);
        trailing.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        assert_refused(&trailing, DocumentFault::CharacterData, 4);
        assert_refused(&[0xEF, 0xBB], DocumentFault::CharacterData, 0);
    }

    #[test]
    fn a_doctype_is_refused_wherever_it_appears() {
        assert_refused(
            b"<!DOCTYPE configuration SYSTEM \"http://attacker/x.dtd\">\n<a/>",
            DocumentFault::Doctype,
            0,
        );
        assert_refused(b"<a><!DOCTYPE x></a>", DocumentFault::Doctype, 3);
    }

    #[test]
    fn an_internal_entity_declaration_is_refused() {
        assert_refused(
            b"<!ENTITY lol \"lolol\">\n<a/>",
            DocumentFault::EntityDeclaration,
            0,
        );
    }

    #[test]
    fn a_billion_laughs_expansion_never_begins() {
        // The attack needs a DTD to hold its entity declarations, so it is
        // refused at the `<!DOCTYPE` — before any entity exists to expand and
        // before the reader has read a single one of the nine levels.
        let document = concat!(
            "<!DOCTYPE lolz [\n",
            "  <!ENTITY lol \"lol\">\n",
            "  <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n",
            "  <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n",
            "]>\n",
            "<configuration>&lol2;</configuration>\n"
        );
        assert_refused(document.as_bytes(), DocumentFault::Doctype, 0);
    }

    #[test]
    fn an_external_entity_is_refused_at_its_declaration_and_at_its_reference() {
        assert_refused(
            b"<!ENTITY xxe SYSTEM \"file:///etc/shadow\">\n<a/>",
            DocumentFault::EntityDeclaration,
            0,
        );
        // Without the declaration the reference alone is a name the reader
        // knows nothing about, which is the same refusal from the other side.
        assert_refused(
            b"<a x=\"&xxe;\"/>",
            DocumentFault::UnknownEntityReference,
            6,
        );
    }

    #[test]
    fn a_cdata_section_is_refused() {
        assert_refused(
            b"<a><![CDATA[<not markup>]]></a>",
            DocumentFault::CdataSection,
            3,
        );
    }

    #[test]
    fn any_other_markup_declaration_is_refused_as_dtd() {
        for document in [
            &b"<!ELEMENT a EMPTY>\n<a/>"[..],
            b"<!ATTLIST a x CDATA #REQUIRED>\n<a/>",
            b"<!NOTATION x SYSTEM \"y\">\n<a/>",
            b"<!doctype a>\n<a/>",
            b"<!>",
        ] {
            assert_refused(document, DocumentFault::MarkupDeclaration, 0);
        }
    }

    #[test]
    fn a_processing_instruction_that_is_not_the_leading_declaration_is_refused() {
        for (document, offset) in [
            (&b"<a><?php echo 1; ?></a>"[..], 3u32),
            (b"<?xml-stylesheet href=\"x\"?><a/>", 0),
            (b"<?xml?><a/>", 0),
            (b" <?xml version=\"1.0\"?><a/>", 1),
        ] {
            assert_refused(document, DocumentFault::ProcessingInstruction, offset);
        }
    }

    #[test]
    fn an_unterminated_construct_is_refused_where_it_opened() {
        assert_refused(b"<!-- forever", DocumentFault::UnterminatedComment, 0);
        // Nothing at all after the opener, so the terminator cannot even fit in
        // what remains — a shorter path through the search than the one above.
        assert_refused(b"<!--", DocumentFault::UnterminatedComment, 0);
        assert_refused(
            b"<?xml ",
            DocumentFault::UnterminatedProcessingInstruction,
            0,
        );
        assert_refused(
            b"<?xml version",
            DocumentFault::UnterminatedProcessingInstruction,
            0,
        );
        assert_refused(b"<a x=\"1\"", DocumentFault::UnterminatedTag, 0);
        assert_refused(b"<a x=\"1", DocumentFault::UnterminatedAttributeValue, 5);
        assert_refused(b"<a></a", DocumentFault::UnterminatedEndTag, 3);
        assert_refused(b"<a>", DocumentFault::UnclosedElement, 0);
        assert_refused(b"<a><b></b>", DocumentFault::UnclosedElement, 0);
    }

    #[test]
    fn an_end_tag_that_matches_nothing_is_refused() {
        assert_refused(b"<a></b></a>", DocumentFault::MismatchedEndTag, 3);
        assert_refused(b"</a>", DocumentFault::UnexpectedEndTag, 0);
        assert_refused(b"<a/></a>", DocumentFault::UnexpectedEndTag, 4);
    }

    #[test]
    fn a_tag_that_is_not_a_tag_is_refused() {
        assert_refused(b"<1a/>", DocumentFault::ExpectedElementName, 1);
        assert_refused(b"< a/>", DocumentFault::ExpectedElementName, 1);
        assert_refused(b"<", DocumentFault::ExpectedElementName, 1);
        assert_refused(b"<a 1=\"x\"/>", DocumentFault::ExpectedElementName, 3);
        assert_refused(b"<a x/>", DocumentFault::ExpectedAttributeEquals, 3);
        assert_refused(b"<a x=1/>", DocumentFault::UnquotedAttributeValue, 5);
        assert_refused(b"<a x=\"<\"/>", DocumentFault::LessThanInAttributeValue, 6);
    }

    #[test]
    fn character_data_is_refused_everywhere_the_schema_admits_none() {
        assert_refused(b"<a>text</a>", DocumentFault::CharacterData, 3);
        assert_refused(b"leading<a/>", DocumentFault::CharacterData, 0);
        assert_refused(b"<a/>trailing", DocumentFault::CharacterData, 4);
        assert_refused(b"<a>&amp;</a>", DocumentFault::CharacterData, 3);
    }

    #[test]
    fn an_empty_document_names_the_element_it_lacks() {
        assert_refused(b"", DocumentFault::MissingRootElement, 0);
        assert_refused(b"   \n\t ", DocumentFault::MissingRootElement, 0);
        assert_refused(
            b"<!-- only a comment -->",
            DocumentFault::MissingRootElement,
            0,
        );
    }

    #[test]
    fn a_second_root_element_is_trailing_content() {
        assert_refused(b"<a/><b/>", DocumentFault::TrailingContent, 4);
        assert_refused(b"<a></a><a/>", DocumentFault::TrailingContent, 7);
    }

    #[test]
    fn a_duplicate_attribute_is_refused_at_the_second_one() {
        assert_refused(
            b"<a x=\"1\" x=\"2\"/>",
            DocumentFault::DuplicateAttribute,
            9,
        );
    }

    #[test]
    fn exactly_max_attributes_is_accepted_and_one_more_is_refused() {
        let mut at_limit = Vec::from(&b"<a"[..]);
        for index in 0..MAX_ATTRIBUTES {
            at_limit.extend_from_slice(std::format!(" a{index}=\"1\"").as_bytes());
        }
        let mut past_limit = at_limit.clone();
        at_limit.extend_from_slice(b"/>");
        past_limit.extend_from_slice(b" b=\"1\"/>");

        let events = read(&at_limit).expect("MAX_ATTRIBUTES is admissible");
        let Event::Start(element) = events[0] else {
            panic!("a start");
        };
        assert_eq!(element.attribute_count(), MAX_ATTRIBUTES);
        assert_eq!(
            refusal(&past_limit).fault,
            DocumentFault::TooManyAttributes,
            "one past MAX_ATTRIBUTES"
        );
    }

    #[test]
    fn exactly_max_depth_is_accepted_and_one_more_is_refused() {
        fn nest(levels: usize) -> Vec<u8> {
            let mut document = Vec::new();
            for _ in 0..levels {
                document.extend_from_slice(b"<a>");
            }
            for _ in 0..levels {
                document.extend_from_slice(b"</a>");
            }
            document
        }
        let at_limit = nest(MAX_DEPTH);
        let past_limit = nest(MAX_DEPTH + 1);
        let events = read(&at_limit).expect("MAX_DEPTH is admissible");
        assert_eq!(events.len(), MAX_DEPTH * 2);
        let error = refusal(&past_limit);
        assert_eq!(error.fault, DocumentFault::DepthExceeded);
        assert_eq!(error.offset, (MAX_DEPTH * 3) as u32);
    }

    #[test]
    fn exactly_max_name_len_is_accepted_and_one_more_is_refused() {
        let at_limit: Vec<u8> =
            std::format!("<{name}/>", name = "a".repeat(MAX_NAME_LEN)).into_bytes();
        let past_limit: Vec<u8> =
            std::format!("<{name}/>", name = "a".repeat(MAX_NAME_LEN + 1)).into_bytes();
        assert_eq!(read(&at_limit).expect("at the bound").len(), 2);
        assert_refused(&past_limit, DocumentFault::NameTooLong, 1);
    }

    #[test]
    fn exactly_max_attribute_value_len_is_accepted_and_one_more_is_refused() {
        let at_limit = std::format!("<a x=\"{}\"/>", "v".repeat(MAX_ATTRIBUTE_VALUE_LEN));
        let past_limit = std::format!("<a x=\"{}\"/>", "v".repeat(MAX_ATTRIBUTE_VALUE_LEN + 1));
        let events = read(at_limit.as_bytes()).expect("at the bound");
        let Event::Start(element) = events[0] else {
            panic!("a start");
        };
        assert_eq!(
            element.attribute(b"x").expect("x").value.len(),
            MAX_ATTRIBUTE_VALUE_LEN
        );
        assert_eq!(
            refusal(past_limit.as_bytes()).fault,
            DocumentFault::ValueTooLong
        );
    }

    #[test]
    fn a_value_whose_references_expand_past_the_bound_is_refused_too() {
        let past_limit = std::format!("<a x=\"{}\"/>", "&amp;".repeat(MAX_ATTRIBUTE_VALUE_LEN + 1));
        assert_eq!(
            refusal(past_limit.as_bytes()).fault,
            DocumentFault::ValueTooLong
        );
    }

    #[test]
    fn exactly_max_document_bytes_is_accepted_and_one_more_is_refused() {
        let element = &b"<a/>"[..];
        let mut at_limit = vec![b' '; MAX_DOCUMENT_BYTES - element.len()];
        at_limit.extend_from_slice(element);
        assert_eq!(at_limit.len(), MAX_DOCUMENT_BYTES);
        assert_eq!(read(&at_limit).expect("at the bound").len(), 2);

        let mut past_limit = at_limit;
        past_limit.push(b' ');
        assert_refused(
            &past_limit,
            DocumentFault::DocumentTooLarge,
            MAX_DOCUMENT_BYTES as u32,
        );
    }

    #[test]
    fn a_reader_yields_nothing_after_it_has_refused_a_document() {
        let mut reader = Reader::new(b"<a>text</a>").expect("within the size bound");
        assert!(reader.next().expect("the start of <a>").is_ok());
        assert!(reader.next().expect("the rejection").is_err());
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
    }

    #[test]
    fn a_namespace_qualified_name_is_not_a_name() {
        // The name ends at the colon and the tag then carries something that
        // is not an attribute name, which is where it dies.
        assert_refused(b"<ns:a/>", DocumentFault::ExpectedElementName, 3);
    }

    #[test]
    fn every_fault_maps_to_a_reason_and_the_syntax_group_shares_one() {
        let faults = [
            (
                DocumentFault::DocumentTooLarge,
                RejectReason::DocumentTooLarge,
            ),
            (
                DocumentFault::MissingRootElement,
                RejectReason::MissingElement,
            ),
            (DocumentFault::MissingElement, RejectReason::MissingElement),
            (
                DocumentFault::CharacterData,
                RejectReason::UnexpectedCharacterData,
            ),
            (
                DocumentFault::CdataSection,
                RejectReason::UnexpectedCharacterData,
            ),
            (DocumentFault::Doctype, RejectReason::Doctype),
            (DocumentFault::MarkupDeclaration, RejectReason::Doctype),
            (
                DocumentFault::EntityDeclaration,
                RejectReason::EntityDeclaration,
            ),
            (DocumentFault::DepthExceeded, RejectReason::DepthExceeded),
            (DocumentFault::NameTooLong, RejectReason::NameTooLong),
            (DocumentFault::ValueTooLong, RejectReason::ValueTooLong),
            (
                DocumentFault::TooManyAttributes,
                RejectReason::TooManyAttributes,
            ),
            (
                DocumentFault::DuplicateAttribute,
                RejectReason::DuplicateAttribute,
            ),
            (
                DocumentFault::UnknownEntityReference,
                RejectReason::UnknownEntityReference,
            ),
            (
                DocumentFault::InvalidCharacterReference,
                RejectReason::InvalidCharacterReference,
            ),
            (DocumentFault::UnknownElement, RejectReason::UnknownElement),
            (
                DocumentFault::UnknownAttribute,
                RejectReason::UnknownAttribute,
            ),
            (
                DocumentFault::MissingAttribute,
                RejectReason::MissingAttribute,
            ),
            (DocumentFault::MalformedValue, RejectReason::MalformedValue),
            (
                DocumentFault::CapacityExceeded,
                RejectReason::CapacityExceeded,
            ),
            (DocumentFault::TrailingContent, RejectReason::Malformed),
            (DocumentFault::UnterminatedComment, RejectReason::Malformed),
            (
                DocumentFault::UnterminatedProcessingInstruction,
                RejectReason::Malformed,
            ),
            (
                DocumentFault::ProcessingInstruction,
                RejectReason::Malformed,
            ),
            (DocumentFault::ExpectedElementName, RejectReason::Malformed),
            (DocumentFault::UnterminatedTag, RejectReason::Malformed),
            (
                DocumentFault::ExpectedAttributeEquals,
                RejectReason::Malformed,
            ),
            (
                DocumentFault::UnquotedAttributeValue,
                RejectReason::Malformed,
            ),
            (
                DocumentFault::UnterminatedAttributeValue,
                RejectReason::Malformed,
            ),
            (
                DocumentFault::LessThanInAttributeValue,
                RejectReason::Malformed,
            ),
            (DocumentFault::UnterminatedEndTag, RejectReason::Malformed),
            (DocumentFault::MismatchedEndTag, RejectReason::Malformed),
            (DocumentFault::UnexpectedEndTag, RejectReason::Malformed),
            (DocumentFault::UnclosedElement, RejectReason::Malformed),
            (
                DocumentFault::UnterminatedReference,
                RejectReason::Malformed,
            ),
        ];
        for (fault, reason) in faults {
            assert_eq!(fault.reason(), reason, "{fault:?}");
            assert_eq!(
                DocumentError::at(fault, 7).reason(),
                reason,
                "the error delegates"
            );
        }
    }

    proptest! {
        /// Total over arbitrary bytes: the reader either produces events or one
        /// typed rejection, and never panics, loops or indexes past a bound.
        #[test]
        fn reading_arbitrary_bytes_is_total(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let _ = read(&bytes);
        }

        /// The same over bytes drawn from the document alphabet, which reaches
        /// the tag machinery far more often than uniform noise does.
        #[test]
        fn reading_arbitrary_markup_is_total(
            text in r#"[<>/?!&;="'a-z0-9 \n#-]{0,400}"#,
        ) {
            let _ = read(text.as_bytes());
        }

        /// Bounded work: whatever a document says, it cannot make the reader
        /// produce more events than it has bytes.
        #[test]
        fn a_document_never_produces_more_events_than_it_has_bytes(
            text in r#"[<>/a-z ="]{0,300}"#,
        ) {
            if let Ok(events) = read(text.as_bytes()) {
                prop_assert!(events.len() <= text.len());
            }
        }

        /// Reading is a function of the bytes alone.
        #[test]
        fn reading_is_deterministic(
            text in r#"[<>/?!&;="'a-z0-9 \n#-]{0,300}"#,
        ) {
            prop_assert_eq!(read(text.as_bytes()), read(text.as_bytes()));
        }

        /// Every rejection points inside the document, or at the size bound for
        /// the one rejection decided before a byte is read.
        #[test]
        fn a_rejection_always_points_somewhere_readable(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            if let Err(error) = read(&bytes) {
                prop_assert!(error.offset as usize <= bytes.len().max(MAX_DOCUMENT_BYTES));
            }
        }

        /// Start and end events pair up: a document that reads at all is
        /// balanced, and no element is left open.
        #[test]
        fn accepted_documents_are_balanced(
            text in r#"(<[a-c](/)?>|</[a-c]>| ){0,40}"#,
        ) {
            if let Ok(events) = read(text.as_bytes()) {
                let mut depth = 0i32;
                for event in &events {
                    match event {
                        Event::Start(_) => depth += 1,
                        Event::End { .. } => depth -= 1,
                    }
                    prop_assert!(depth >= 0);
                    prop_assert!(depth <= MAX_DEPTH as i32);
                }
                prop_assert_eq!(depth, 0);
            }
        }
    }
}
