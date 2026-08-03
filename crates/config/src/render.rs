//! Writing a configuration back out as the document that describes it.
//!
//! This is the answer to "what is this appliance running". The bytes an operator
//! submitted are deliberately not kept — 64 KiB of document has no allocator to
//! live in, and [`store`](crate::store) says why the validated-is-applied
//! property survives that — so what is stated back is produced from the
//! [`Model`] the appliance is actually deciding under. That is the stronger
//! answer in any case: the submitted bytes are what one party sent, while the
//! model is what is in force, and only one of the two is worth an operator's
//! trust. It is also the only answer available for the generation a node commits
//! at boot, whose document no other domain ever saw.
//!
//! # Nothing here renders a value a second way
//!
//! Every attribute name is its [`Field`]'s console token and every value is its
//! [`Value`]'s `Display`, both reached through the entity's own
//! `field_value` — the same two vocabularies a change record is written in. So a
//! MAC cannot read one way in a console line and another in the document, and an
//! attribute this writes is by construction one the reader accepts: a field
//! added to an object appears here without an edit.
//!
//! # Adversary
//!
//! None directly. Every byte written comes from a [`Model`] a validated document
//! produced, so nothing here parses anything. What it owes the management-plane
//! attacker is indirect and is met by the type system: [`Identifier`]'s alphabet
//! is what makes a document-chosen name safe to write into an attribute value at
//! all, and no other document text reaches a [`Model`].
//!
//! # The canonical form fits the document bound, and that is a rule rather than
//! an accident
//!
//! A rendering is not free of the input's size: written out with every criterion
//! spelled, the [`wire::MAX_RULES`] rules a handover image admits come to some
//! 70 KiB, which is past [`MAX_DOCUMENT_BYTES`]. A configuration whose canonical
//! form does not fit is therefore **refused** by
//! [`validate`](crate::validate) rather than committed, so what this writes is
//! always a document the appliance would itself accept. The alternative — commit
//! it and answer a document longer than a submission may be — would give an
//! operator a configuration they could read and not edit, and the read is only
//! worth having because it is the first step of a change.

use core::fmt::{self, Write};

use lfw_log::{Field, Value};

use crate::{
    entity::{InterfaceEntry, ManagementEntry, NeighbourEntry, RuleEntry},
    model::Model,
    xml::MAX_DOCUMENT_BYTES,
};

/// The document did not fit the storage offered.
///
/// Unreachable for a model [`validate`](crate::validate) accepted written into
/// [`MAX_DOCUMENT_BYTES`] of storage, which is what that rule is for; answered
/// rather than asserted because the two are separate functions and either may
/// move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocumentDoesNotFit {
    pub capacity: usize,
}

/// Bytes the canonical form of `model` occupies.
///
/// The same walk [`render`] performs, counting instead of writing, so the two
/// cannot come to disagree about a length: a bound derived from a second
/// traversal is a bound that goes stale the first time one of them changes.
#[must_use]
pub fn rendered_len(model: &Model) -> usize {
    let mut counted = Counted { len: 0 };
    // Cannot fail: `Counted` accepts every byte.
    let _ = write_document(model, &mut counted);
    counted.len
}

/// Write the canonical form of `model` into `out`, answering its length.
///
/// # Errors
/// [`DocumentDoesNotFit`] where `out` is shorter than [`rendered_len`].
pub fn render(model: &Model, out: &mut [u8]) -> Result<usize, DocumentDoesNotFit> {
    let capacity = out.len();
    let mut filled = Filled { out, at: 0 };
    match write_document(model, &mut filled) {
        Ok(()) => Ok(filled.at),
        Err(_) => Err(DocumentDoesNotFit { capacity }),
    }
}

/// Whether the canonical form of `model` fits a document this appliance would
/// read back.
#[must_use]
pub fn fits_the_document_bound(model: &Model) -> bool {
    rendered_len(model) <= MAX_DOCUMENT_BYTES
}

/// Somewhere rendered bytes go: the slice a caller offered, or nothing but a
/// tally.
///
/// `fmt::Write` rather than a trait of this module's own, which is what lets
/// every value be written through its existing `Display` — the whole point of
/// the module. `fmt::Error` carries nothing, and there is nothing for it to
/// carry: the one thing that can go wrong is the caller's capacity.
struct Filled<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Write for Filled<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let bytes = text.as_bytes();
        let end = self.at.checked_add(bytes.len()).ok_or(fmt::Error)?;
        let target = self.out.get_mut(self.at..end).ok_or(fmt::Error)?;
        target.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }
}

struct Counted {
    len: usize,
}

impl Write for Counted {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.len = self.len.saturating_add(text.len());
        Ok(())
    }
}

/// The XML declaration, so what an appliance states is a whole document rather
/// than a fragment a reader has to be told the encoding of.
const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

fn write_document<W: Write>(model: &Model, out: &mut W) -> fmt::Result {
    out.write_str(DECLARATION)?;
    out.write_str("<configuration>\n")?;
    write_section(out, b"interfaces", model.interfaces(), write_interface)?;
    write_section(out, b"neighbours", model.neighbours(), write_neighbour)?;
    write_section(out, b"rules", model.rules(), write_rule)?;
    if let Some(management) = model.management() {
        out.write_str("  ")?;
        write_element(out, ManagementEntry::ELEMENT, None, |field| {
            management.field_value(field)
        })?;
        out.write_str("\n")?;
    }
    out.write_str("</configuration>\n")
}

/// One container element and its children, or the empty form where there are
/// none.
///
/// `<interfaces/>` rather than an open/close pair, because that is what an
/// operator writes for a section with nothing in it and the reader accepts
/// either — a document this appliance states should be one an operator would
/// have written.
fn write_section<'entry, W, T, F>(
    out: &mut W,
    element: &[u8],
    entries: impl Iterator<Item = &'entry T>,
    mut write_entry: F,
) -> fmt::Result
where
    W: Write,
    T: 'entry,
    F: FnMut(&mut W, &T) -> fmt::Result,
{
    let mut opened = false;
    for entry in entries {
        if !opened {
            opened = true;
            out.write_str("  <")?;
            write_name(out, element)?;
            out.write_str(">\n")?;
        }
        out.write_str("    ")?;
        write_entry(out, entry)?;
        out.write_str("\n")?;
    }
    if opened {
        out.write_str("  </")?;
        write_name(out, element)?;
        return out.write_str(">\n");
    }
    out.write_str("  <")?;
    write_name(out, element)?;
    out.write_str("/>\n")
}

fn write_interface<W: Write>(out: &mut W, entry: &InterfaceEntry) -> fmt::Result {
    write_element(out, InterfaceEntry::ELEMENT, Some(entry.key()), |field| {
        entry.field_value(field)
    })
}

fn write_neighbour<W: Write>(out: &mut W, entry: &NeighbourEntry) -> fmt::Result {
    write_element(out, NeighbourEntry::ELEMENT, Some(entry.key()), |field| {
        entry.field_value(field)
    })
}

/// A rule carries its id as a *field* rather than as a key, its identity being
/// something it says rather than where it sits, so nothing is written in front
/// of the field list.
fn write_rule<W: Write>(out: &mut W, entry: &RuleEntry) -> fmt::Result {
    write_element(out, RuleEntry::ELEMENT, None, |field| {
        entry.field_value(field)
    })
}

/// One self-closing element: its name, the key where the object has one, and
/// every field it answers for, in the field vocabulary's own order.
///
/// Iterating [`Field::ALL`] rather than a per-object list is what makes this
/// complete by construction: an attribute the reader requires is one the entity
/// answers a value for, so it is written, and one no object has is skipped
/// without a branch here naming it.
fn write_element<W: Write>(
    out: &mut W,
    element: &[u8],
    key: Option<lfw_log::Identifier>,
    value_of: impl Fn(Field) -> Option<Value>,
) -> fmt::Result {
    out.write_str("<")?;
    write_name(out, element)?;
    if let Some(key) = key {
        out.write_str(" id=\"")?;
        out.write_str(key.as_str())?;
        out.write_str("\"")?;
    }
    for field in Field::ALL {
        let Some(value) = value_of(field) else {
            continue;
        };
        out.write_str(" ")?;
        out.write_str(field.name())?;
        out.write_str("=\"")?;
        write!(out, "{value}")?;
        out.write_str("\"")?;
    }
    out.write_str("/>")
}

/// An element name out of the entity declaration.
///
/// The declarations spell them as byte literals, and every one of them is ASCII;
/// a name that were not would be one the reader could not match either, so the
/// unreachable arm writes nothing rather than being an error a caller has to
/// handle.
fn write_name<W: Write>(out: &mut W, element: &[u8]) -> fmt::Result {
    match core::str::from_utf8(element) {
        Ok(name) => out.write_str(name),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests;
