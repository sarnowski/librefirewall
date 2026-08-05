//! The fixed configuration slot array: which slot holds which document version,
//! which one is running, and which one a new version may take.
//!
//! Deliberately not a ring, and the difference is the whole reason this is a
//! separate structure from the recording rings. A ring's worst case is
//! overwriting its oldest content, which for a recording is the intended
//! behaviour and for a configuration history would one day be the running
//! configuration — the state the whole store exists to keep. So reuse takes the
//! **lowest generation** and the running slot is never a candidate for it:
//! dropping the oldest version is bounded and intentional, and losing the current
//! one is unrepresentable.

use lfw_crypto::DIGEST_LEN;

use crate::layout::SLOT_COUNT;
use crate::state::StateError;

/// Bytes one document may occupy, which is the configuration bound: 64 KiB, so a
/// slot is exactly that and the array is 512 KiB.
pub const DOCUMENT_BYTES: usize = 64 * 1024;

/// One slot of the array: `< SLOT_COUNT` by construction, so its first sector
/// lies inside the array by arithmetic rather than by a check somebody
/// remembered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SlotIndex(u8);

impl SlotIndex {
    /// The slot at `index`, or `None` where the array has no such slot.
    #[must_use]
    pub const fn new(index: usize) -> Option<Self> {
        if index < SLOT_COUNT {
            // In range by the branch, and `SLOT_COUNT` fits a `u8` by the
            // assertion below, so the cast is total.
            Some(Self(index as u8))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

const _: () = assert!(
    SLOT_COUNT <= u8::MAX as usize + 1,
    "a slot index must fit in a u8"
);

/// What one occupied slot holds, as the record's table describes it.
///
/// The digest is over the document's own bytes, so a slot read back can be held
/// to what the record says is in it — which is the only thing standing between a
/// rollback and a document somebody swapped on the medium. Not a signature: there
/// is nowhere here to keep a key that would make one mean anything, and the
/// record's own digest is what the whole table rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotEntry {
    /// The configuration generation this document is. Monotonic across the
    /// appliance's life and never zero, zero being how the table says "empty".
    pub generation: u64,
    /// Bytes of document, never zero and never past [`DOCUMENT_BYTES`].
    pub len: usize,
    pub digest: [u8; DIGEST_LEN],
}

/// Which slot a new document may take, and what taking it costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reuse {
    /// A slot that holds nothing. Nothing is lost.
    Empty(SlotIndex),
    /// The lowest generation the array holds, which is the version this write
    /// drops. Reported rather than silently taken, because "which version did I
    /// lose" is a question an operator asks after a rollback fails.
    Displaces { slot: SlotIndex, generation: u64 },
}

impl Reuse {
    #[must_use]
    pub const fn slot(self) -> SlotIndex {
        match self {
            Self::Empty(slot) | Self::Displaces { slot, .. } => slot,
        }
    }
}

/// The array's occupancy and its two named slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slots {
    entries: [Option<SlotEntry>; SLOT_COUNT],
    running: Option<SlotIndex>,
    candidate: Option<SlotIndex>,
}

impl Slots {
    /// An array holding nothing, which is what a freshly minted state's is.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: [None; SLOT_COUNT],
            running: None,
            candidate: None,
        }
    }

    /// Rebuild an array from a decoded record, refusing the shapes a commit of
    /// this appliance's could not have produced.
    ///
    /// # Errors
    /// [`StateError::SlotOutsideArray`] is unreachable here — an index arrives as
    /// a [`SlotIndex`] — so what remains is
    /// [`StateError::NamedSlotEmpty`] for a named slot holding nothing and
    /// [`StateError::SlotNamedTwice`] for one that is both running and candidate:
    /// a rollback would then have no target distinct from what is in force, and a
    /// commit would confirm the configuration it was meant to replace.
    pub fn decoded(
        entries: [Option<SlotEntry>; SLOT_COUNT],
        running: Option<SlotIndex>,
        candidate: Option<SlotIndex>,
    ) -> Result<Self, StateError> {
        for named in [running, candidate] {
            let Some(slot) = named else { continue };
            // `SlotIndex` is `< SLOT_COUNT`, so the entry exists; the `None` arm
            // is the empty slot and not an out-of-range index.
            if entries.get(slot.get()).copied().flatten().is_none() {
                return Err(StateError::NamedSlotEmpty { slot: slot.get() });
            }
        }
        if let (Some(running), Some(candidate)) = (running, candidate)
            && running == candidate
        {
            return Err(StateError::SlotNamedTwice {
                slot: running.get(),
            });
        }
        Ok(Self {
            entries,
            running,
            candidate,
        })
    }

    #[must_use]
    pub const fn entries(&self) -> &[Option<SlotEntry>; SLOT_COUNT] {
        &self.entries
    }

    #[must_use]
    pub const fn running(&self) -> Option<SlotIndex> {
        self.running
    }

    #[must_use]
    pub const fn candidate(&self) -> Option<SlotIndex> {
        self.candidate
    }

    /// What one slot holds, or `None` where it holds nothing.
    #[must_use]
    pub fn entry(&self, slot: SlotIndex) -> Option<SlotEntry> {
        self.entries.get(slot.get()).copied().flatten()
    }

    /// How many slots hold a document.
    #[must_use]
    pub fn occupied(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// The highest configuration generation the array holds, or zero for an empty
    /// array — which is not a generation, a document's being minted at one.
    #[must_use]
    pub fn newest_generation(&self) -> u64 {
        self.entries
            .iter()
            .flatten()
            .map(|entry| entry.generation)
            .max()
            .unwrap_or(0)
    }

    /// Which slot a new document takes.
    ///
    /// An empty slot first, in index order, so a fresh store fills predictably.
    /// Otherwise the lowest generation that is neither running nor candidate:
    /// both are in use, and a write over either is the loss this structure exists
    /// to make unrepresentable. `None` where every slot is one of the two, which
    /// needs an array of two and is therefore unreachable in this build — and is
    /// answered rather than asserted, because the array's size is a constant
    /// somebody may one day lower.
    #[must_use]
    pub fn next_for_reuse(&self) -> Option<Reuse> {
        let mut oldest: Option<(SlotIndex, u64)> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            // `index < SLOT_COUNT` by the iteration, so this is `Some`.
            let Some(slot) = SlotIndex::new(index) else {
                continue;
            };
            let Some(entry) = entry else {
                return Some(Reuse::Empty(slot));
            };
            if Some(slot) == self.running || Some(slot) == self.candidate {
                continue;
            }
            if oldest.is_none_or(|(_, generation)| entry.generation < generation) {
                oldest = Some((slot, entry.generation));
            }
        }
        oldest.map(|(slot, generation)| Reuse::Displaces { slot, generation })
    }

    /// Record `entry` in `slot`, as the running configuration or as the
    /// candidate.
    ///
    /// Placing the running configuration clears the candidate: a commit is what
    /// makes a candidate the running one, so a candidate surviving it would be a
    /// version staged against a configuration that is no longer there.
    pub fn place(&mut self, slot: SlotIndex, entry: SlotEntry, running: bool) {
        if let Some(target) = self.entries.get_mut(slot.get()) {
            *target = Some(entry);
        }
        if running {
            self.running = Some(slot);
            self.candidate = None;
        } else {
            self.candidate = Some(slot);
        }
    }

    /// Forget every document without touching the medium — the in-memory half of
    /// a factory reset, whose other half is overwriting the sectors.
    pub fn clear(&mut self) {
        *self = Self::empty();
    }
}

// The array's bounds, decided when the program is compiled.
const _: () = {
    assert!(DOCUMENT_BYTES.is_multiple_of(crate::SECTOR_SIZE));
    assert!(SLOT_COUNT >= 2, "a candidate and a running slot need two");
};
