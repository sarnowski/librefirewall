//! A buffer with untouchable margins either side of it.
//!
//! Two harnesses hand a caller-owned buffer to code that writes into it under
//! lengths an adversary chose — [`crate::pcapng`] to the block encoders, and
//! [`crate::recording`]'s sink to the recorder's staging area — and in both the
//! claim worth asserting is not that the call returned but that it stayed
//! inside what it was given. A `&mut [u8]` already bounds a safe writer, so
//! this is not a redundant check of the borrow checker: it is what makes the
//! *reported* length and the *touched* bytes one fact, catching a write that
//! stayed in bounds while claiming to have filled fewer bytes than it did, and
//! it keeps holding if either crate ever grows an `unsafe` fast path.

use std::{vec, vec::Vec};

/// Bytes written either side of the buffer offered.
const GUARD: usize = 64;

/// What the margins — and the untouched interior — hold. One repeated byte
/// rather than a pattern, because what is being detected is any write at all
/// and not a particular one.
const GUARD_BYTE: u8 = 0x5A;

/// A buffer of `capacity` bytes with a margin either side.
pub struct Guarded {
    bytes: Vec<u8>,
    capacity: usize,
}

impl Guarded {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: vec![GUARD_BYTE; GUARD + capacity + GUARD],
            capacity,
        }
    }

    /// The buffer the code under test is handed, which is the interior alone.
    pub fn out(&mut self) -> &mut [u8] {
        let end = GUARD + self.capacity;
        self.bytes
            .get_mut(GUARD..end)
            .expect("the interior is the length this was built with")
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn interior(&self) -> &[u8] {
        let end = GUARD + self.capacity;
        self.bytes
            .get(GUARD..end)
            .expect("the interior is the length this was built with")
    }

    /// The prefix a caller claims to have filled.
    pub fn written(&self, bytes: usize) -> &[u8] {
        self.interior()
            .get(..bytes)
            .expect("more bytes were reported written than the buffer holds")
    }

    /// Whether the interior still holds nothing but the fill, which is what a
    /// call that reported a refusal must have left behind.
    #[must_use]
    pub fn is_untouched(&self) -> bool {
        self.interior().iter().all(|byte| *byte == GUARD_BYTE)
    }

    /// How far into the interior anything was written, which bounds what a
    /// caller may claim it filled.
    #[must_use]
    pub fn touched_len(&self) -> usize {
        self.interior()
            .iter()
            .rposition(|byte| *byte != GUARD_BYTE)
            .map_or(0, |at| at + 1)
    }

    /// Neither margin was written.
    pub fn assert_margins_intact(&self, label: &str) {
        let end = GUARD + self.capacity;
        let leading = self.bytes.get(..GUARD).expect("the leading margin");
        let trailing = self.bytes.get(end..).expect("the trailing margin");
        assert!(
            leading.iter().all(|byte| *byte == GUARD_BYTE),
            "{label}: a write reached before the start of the buffer it was given"
        );
        assert!(
            trailing.iter().all(|byte| *byte == GUARD_BYTE),
            "{label}: a write reached past the end of the buffer it was given"
        );
    }
}
