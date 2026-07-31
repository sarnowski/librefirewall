//! The one route text takes from a configuration document to a console line.

use core::fmt;

/// Longest identifier the configuration schema admits, and so the whole of an
/// [`Identifier`]'s storage: text sized at compile time is what lets a record
/// be `Copy` with no allocator behind it.
pub const MAX_IDENTIFIER_LEN: usize = 16;

/// Why a byte string is not an identifier. Names the position, never the byte
/// (OBS-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierError {
    Empty,
    TooLong { len: usize },
    NotInAlphabet { offset: usize },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an identifier may not be empty"),
            Self::TooLong { len } => {
                write!(f, "{len} bytes exceeds the {MAX_IDENTIFIER_LEN}-byte limit")
            }
            Self::NotInAlphabet { offset } => {
                write!(f, "byte {offset} is outside [a-z0-9-]")
            }
        }
    }
}

/// A configuration object's stable name: `[a-z0-9-]{1,16}`.
///
/// The alphabet is not a style choice — it is what makes an operator-supplied
/// string safe to put on a console at all (OBS-5), so it is checked once, here,
/// and every later consumer receives text it can render without asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier {
    bytes: [u8; MAX_IDENTIFIER_LEN],
    len: usize,
}

impl Identifier {
    /// The key a change record about the management interface carries: that
    /// element has no `id` of its own. A literal rather than a fallible call at
    /// a place with no failure; the assertion below keeps it admissible.
    pub const MANAGEMENT: Self = Self {
        bytes: *b"management\0\0\0\0\0\0",
        len: 10,
    };

    pub fn new(bytes: &[u8]) -> Result<Self, IdentifierError> {
        if bytes.is_empty() {
            return Err(IdentifierError::Empty);
        }
        let len = bytes.len();
        if len > MAX_IDENTIFIER_LEN {
            return Err(IdentifierError::TooLong { len });
        }
        let mut stored = [0u8; MAX_IDENTIFIER_LEN];
        for (slot, (offset, &byte)) in stored.iter_mut().zip(bytes.iter().enumerate()) {
            if !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-') {
                return Err(IdentifierError::NotInAlphabet { offset });
            }
            *slot = byte;
        }
        Ok(Self { bytes: stored, len })
    }

    /// The fallback is unreachable: [`Identifier::new`] is what sets `len`, and
    /// it does so only after comparing it against the array's own size. An
    /// empty slice rather than a panic because a branch safe Rust cannot delete
    /// is not a failure to surface (ENG-12) and a rendered line is not worth
    /// faulting a domain over.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// Unreachable for the same reason plus one step: [`Identifier::new`]
    /// admits `[a-z0-9-]` alone, every byte of which is a single-byte UTF-8
    /// sequence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always false: [`Identifier::new`] refuses an empty byte string. Present
    /// because `len` without it is a lint, not because a caller has a case here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// What [`Identifier::new`] would have checked, checked at build time instead:
/// a wrong literal is a compile error rather than an unrenderable line.
const _: () = {
    let Identifier { bytes, len } = Identifier::MANAGEMENT;
    assert!(len > 0 && len <= MAX_IDENTIFIER_LEN);
    let mut offset = 0;
    while offset < MAX_IDENTIFIER_LEN {
        let byte = bytes[offset];
        if offset < len {
            assert!(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        } else {
            assert!(byte == 0);
        }
        offset += 1;
    }
};

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{format, string::String, vec, vec::Vec};

    #[test]
    fn the_shortest_and_longest_admissible_identifiers_are_accepted() {
        for text in [&b"a"[..], b"0", b"-", b"abcdefghijklmnop", b"wan-0"] {
            let id = Identifier::new(text).expect("within the alphabet and the length bound");
            assert_eq!(id.as_bytes(), text);
            assert_eq!(id.as_str().as_bytes(), text);
            assert_eq!(id.len(), text.len());
            assert!(!id.is_empty());
        }
    }

    /// The hand-built constant is the one [`Identifier::new`] would have made,
    /// which is what the const assertion beside it cannot state.
    #[test]
    fn the_management_key_is_the_identifier_its_own_constructor_would_build() {
        assert_eq!(
            Identifier::MANAGEMENT,
            Identifier::new(b"management").expect("within the alphabet")
        );
        assert_eq!(Identifier::MANAGEMENT.as_str(), "management");
        assert_eq!(Identifier::MANAGEMENT.len(), 10);
        assert!(!Identifier::MANAGEMENT.is_empty());
    }

    /// The ABI carries its own constant of the same word — a console record's
    /// key and the interface info metric's `interface` label are the one identity
    /// of an element that has no `id` — and two spellings of one word drift.
    /// This is where both are visible, so this is where they are held equal.
    #[test]
    fn the_management_key_is_the_word_the_abi_carries_for_it() {
        assert_eq!(
            Identifier::MANAGEMENT.as_bytes(),
            wire::CheckedIdentifier::MANAGEMENT.as_bytes()
        );
    }

    #[test]
    fn an_empty_identifier_is_refused() {
        assert_eq!(Identifier::new(b""), Err(IdentifierError::Empty));
    }

    #[test]
    fn one_byte_past_the_length_bound_is_refused_with_the_length_it_had() {
        let seventeen = b"abcdefghijklmnopq";
        assert_eq!(
            Identifier::new(seventeen),
            Err(IdentifierError::TooLong { len: 17 })
        );
        assert!(Identifier::new(&seventeen[..16]).is_ok());
    }

    #[test]
    fn a_length_far_beyond_the_bound_is_refused_before_the_alphabet_is_consulted() {
        let long = vec![b'!'; 4096];
        assert_eq!(
            Identifier::new(&long),
            Err(IdentifierError::TooLong { len: 4096 })
        );
    }

    #[test]
    fn a_byte_outside_the_alphabet_is_refused_and_its_position_named() {
        let cases: [(&[u8], usize); 7] = [
            (b"WAN", 0),
            (b"wA n", 1),
            (b"wan ", 3),
            (b"wan_0", 3),
            (b"wan.0", 3),
            (b"\xff", 0),
            (b"wan\n", 3),
        ];
        for (text, offset) in cases {
            assert_eq!(
                Identifier::new(text),
                Err(IdentifierError::NotInAlphabet { offset }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn each_rejection_reads_differently() {
        let mut messages: Vec<String> = [
            IdentifierError::Empty,
            IdentifierError::TooLong { len: 17 },
            IdentifierError::NotInAlphabet { offset: 2 },
        ]
        .iter()
        .map(|error| format!("{error}"))
        .collect();
        messages.sort();
        let count = messages.len();
        messages.dedup();
        assert_eq!(messages.len(), count);
    }

    #[test]
    fn identifiers_compare_by_content_not_by_the_unused_tail() {
        let short = Identifier::new(b"wan").expect("valid");
        let padded = Identifier::new(b"wan-").expect("valid");
        assert_ne!(short, padded);
        assert_eq!(short, Identifier::new(b"wan").expect("valid"));
        assert_eq!(format!("{short}"), "wan");
    }

    proptest! {
        /// Total over arbitrary bytes: every input is either a typed rejection
        /// or an identifier that reproduces exactly what it was given.
        #[test]
        fn construction_is_total_and_lossless(
            bytes in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            match Identifier::new(&bytes) {
                Ok(id) => {
                    prop_assert_eq!(id.as_bytes(), &bytes[..]);
                    prop_assert_eq!(id.as_str().as_bytes(), &bytes[..]);
                    prop_assert_eq!(id.len(), bytes.len());
                }
                Err(IdentifierError::Empty) => prop_assert!(bytes.is_empty()),
                Err(IdentifierError::TooLong { len }) => {
                    prop_assert_eq!(len, bytes.len());
                    prop_assert!(len > MAX_IDENTIFIER_LEN);
                }
                Err(IdentifierError::NotInAlphabet { offset }) => {
                    let byte = bytes.get(offset).copied().expect("the offset indexes the input");
                    prop_assert!(!matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'));
                }
            }
        }

        /// Everything the alphabet admits is accepted, so the rejection set is
        /// exactly its complement rather than something narrower.
        #[test]
        fn the_whole_alphabet_is_accepted(text in "[a-z0-9-]{1,16}") {
            let id = Identifier::new(text.as_bytes()).expect("the pattern is the alphabet");
            prop_assert_eq!(id.as_str(), text.as_str());
        }
    }
}
