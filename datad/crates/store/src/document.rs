//! What makes a configuration document a slot of the version history, and what
//! makes a slot read back off the medium the document the record says it is.
//!
//! Two directions of one rule. Going *out*, a document arrives from a domain
//! that terminated a management session and is bounded, digested and placed;
//! coming *back*, a slot is read off a medium somebody may have been holding and
//! is nothing until it matches the digest the record carries for it. Neither
//! direction parses a byte of the document — what is a valid configuration is the
//! deciding domain's judgement and is made before any of this — so this file's
//! whole vocabulary is lengths, generations and one comparison.
//!
//! # Adversary
//!
//! A **management-plane attacker up to and including a compromised management
//! server** on the way out: it chooses the document bytes, its length and the
//! generation named for it. And on the way back, **whoever has had the medium**:
//! a slot's bytes are input with no provenance at all, which is why the record's
//! digest is checked rather than assumed and why the check is a comparison of a
//! computed digest and never of a length or a marker somebody could write.
//!
//! What neither can reach is anything else in the record. A document names a
//! generation and occupies a slot; the trust anchor, the endpoint and the key
//! are fields no path here touches.

use lfw_crypto::{DIGEST_LEN, sha256};

use crate::slots::{DOCUMENT_BYTES, SlotEntry, Slots};

/// Why a document was not made a version, or why one read back was not believed.
///
/// Every variant carries the numbers that made it one, so a console line says
/// which bound was crossed rather than that one was. Deliberately no variant
/// means "close enough".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocumentError {
    /// A staged length of zero. Not a document — an empty slot is how the table
    /// says a version is absent, so a zero-length one would be a version
    /// indistinguishable from no version at all.
    Empty,
    /// More bytes claimed than a slot holds. Refused rather than truncated: half
    /// a configuration is not a configuration, and a slot written short would
    /// pass its own digest for ever after.
    PastBound { len: usize, bound: usize },
    /// A generation of zero, which the table reserves for "this slot is empty".
    GenerationZero,
    /// A generation that does not advance past what the array already holds. A
    /// version that went backwards is a replay of one the appliance has already
    /// seen, and recording it would let a peer reach an older document by
    /// re-committing it under a number the array would then treat as newest.
    NotNewest { named: u64, newest: u64 },
    /// Every slot is either the running version or the candidate, so there is
    /// none a write may take. Unreachable in a build whose array is larger than
    /// two, and answered rather than asserted for the reason
    /// [`Slots::next_for_reuse`] answers it.
    ArrayFull,
    /// The bytes read back are not the bytes the record says the slot holds.
    /// **The only thing standing between a rollback and a document somebody
    /// swapped on the medium**, and it names no offset: a digest disagrees about
    /// the whole document or not at all.
    DigestMismatch,
}

impl DocumentError {
    /// The console token this refusal reaches an operator as.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::Empty => "document-empty",
            Self::PastBound { .. } => "document-past-bound",
            Self::GenerationZero => "document-generation-zero",
            Self::NotNewest { .. } => "document-generation-not-newest",
            Self::ArrayFull => "document-array-full",
            Self::DigestMismatch => "document-digest-mismatch",
        }
    }
}

/// The table entry `document` would become at `generation`, or why it would not.
///
/// The digest is taken here rather than by the caller, which is what makes "the
/// entry describes these bytes" a property of the type instead of two statements
/// a reader has to pair up. `slots` is what the generation is judged against: it
/// must be past every version the array already holds, so the newest is always
/// the one last committed.
///
/// # Errors
/// [`DocumentError::Empty`] and [`DocumentError::PastBound`] for a length that is
/// not a document's, [`DocumentError::GenerationZero`] and
/// [`DocumentError::NotNewest`] for a generation that is not a version's.
pub fn staged_entry(
    generation: u64,
    document: &[u8],
    slots: &Slots,
) -> Result<SlotEntry, DocumentError> {
    let len = document.len();
    if len == 0 {
        return Err(DocumentError::Empty);
    }
    if len > DOCUMENT_BYTES {
        return Err(DocumentError::PastBound {
            len,
            bound: DOCUMENT_BYTES,
        });
    }
    if generation == 0 {
        return Err(DocumentError::GenerationZero);
    }
    let newest = slots.newest_generation();
    if generation <= newest {
        return Err(DocumentError::NotNewest {
            named: generation,
            newest,
        });
    }
    Ok(SlotEntry {
        generation,
        len,
        digest: sha256(document),
    })
}

/// Hold `document` to what `entry` says the slot holds.
///
/// The length is compared before the digest, so a slot whose stored length no
/// longer matches is refused as the bound it is rather than as a digest that
/// happened to disagree. Both are the same fact about a medium and an operator
/// acts on them the same way — but the pair of a length and a digest is what a
/// reader checks a disk against, and a length reported as a digest mismatch is a
/// number nobody can look up.
///
/// # Errors
/// [`DocumentError::PastBound`] where the slice handed over is not the length the
/// entry names, and [`DocumentError::DigestMismatch`] where the bytes are not the
/// bytes.
pub fn matches(entry: &SlotEntry, document: &[u8]) -> Result<(), DocumentError> {
    if document.len() != entry.len {
        return Err(DocumentError::PastBound {
            len: document.len(),
            bound: entry.len,
        });
    }
    // A digest comparison and not a prefix one: `sha256` answers the whole
    // array, so there is no length here for a caller to get wrong.
    if sha256(document) != entry.digest {
        return Err(DocumentError::DigestMismatch);
    }
    Ok(())
}

// The entry's digest is exactly what this file computes into it, decided when
// the program is compiled: a width that disagreed would be a comparison over a
// prefix, which is a check that passes on documents it should refuse.
const _: () = assert!(DIGEST_LEN == 32);
