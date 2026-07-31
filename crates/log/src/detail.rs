//! What a domain lifecycle point carries beyond its own name.
//!
//! A record of only `domain=` and `state=` would have cost the console three
//! payloads: the feature bitmap a driver and its device settled on, how many
//! receive descriptors were primed before the poll loop, and the whole reason a
//! start-up was refused. Each is a field of the record rather than text a call
//! site formats around it, so an exporter still sees attributes.
//!
//! # Two forms of one cause token
//!
//! A refusal names itself with text, and that text reaches this crate from two
//! directions that cannot be given one type. A call site mints a literal, which
//! is `&'static str` and is the whole reason a byte an adversary chose cannot
//! reach the field (OBS-5). A console domain reconstructs one from a shared
//! region, where the bytes are a peer's and there is no allocator to own them,
//! so it is [`Cause`] — fixed storage this crate holds to the alphabet and the
//! length the ABI carries. The type parameter on [`Refusal`] is that seam, and
//! its default keeps every minting call site writing what it wrote before.
//!
//! Both forms print through [`fmt::Display`], which is what lets the renderer
//! stay one function: a line an operator reads cannot depend on which side of a
//! shared region the event was assembled on.

use core::{fmt, num::NonZeroU64};

use lfw_clock::UtcNanos;

/// The longest `cause` token [`MAX_LINE_LEN`](crate::MAX_LINE_LEN) is derived
/// against, and the whole of a [`Cause`]'s storage.
pub const MAX_CAUSE_LEN: usize = 40;

/// Why a byte string is not a [`Cause`]. Names the position, never the byte
/// (OBS-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CauseError {
    TooLong { len: usize },
    NotInAlphabet { offset: usize },
}

impl fmt::Display for CauseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { len } => {
                write!(f, "{len} bytes exceeds the {MAX_CAUSE_LEN}-byte limit")
            }
            Self::NotInAlphabet { offset } => write!(f, "byte {offset} is outside [a-z0-9-]"),
        }
    }
}

/// A refusal cause token in storage of its own: `[a-z0-9-]{0,40}`.
///
/// [`Identifier`](crate::Identifier)'s alphabet for the reason that type gives
/// — it is what makes text safe to put on a console at all (OBS-5) — and the
/// empty token is admitted where an identifier's is not, a refusal that names
/// no cause being a record rather than a malformed one.
///
/// This is what holds a token to [`MAX_CAUSE_LEN`], which until now nothing
/// could: the literals are minted in the crates that raise the refusals, and
/// the bound lived in prose and in one test walking one of those crates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cause {
    bytes: [u8; MAX_CAUSE_LEN],
    len: usize,
}

impl Cause {
    /// A refusal that names no cause.
    pub const EMPTY: Self = Self {
        bytes: [0; MAX_CAUSE_LEN],
        len: 0,
    };

    /// # Errors
    /// [`CauseError`] for text the console grammar or the ABI cannot carry.
    pub fn new(bytes: &[u8]) -> Result<Self, CauseError> {
        let len = bytes.len();
        if len > MAX_CAUSE_LEN {
            return Err(CauseError::TooLong { len });
        }
        let mut stored = [0u8; MAX_CAUSE_LEN];
        for (slot, (offset, &byte)) in stored.iter_mut().zip(bytes.iter().enumerate()) {
            if !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-') {
                return Err(CauseError::NotInAlphabet { offset });
            }
            *slot = byte;
        }
        Ok(Self { bytes: stored, len })
    }

    /// The fallback is unreachable on [`Identifier::as_bytes`]'s terms:
    /// [`Cause::new`] is what sets `len`, and only after comparing it against
    /// the array's own size.
    ///
    /// [`Identifier::as_bytes`]: crate::Identifier::as_bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// Unreachable for the same reason plus one step: the alphabet is
    /// single-byte UTF-8 throughout.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a lifecycle point carries beyond its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainDetail<C = &'static str> {
    /// The state is the whole record.
    None,
    /// The feature bits a driver and its device settled on, as the bitmap:
    /// which bit means what is `virtio`'s vocabulary, and decoding it here
    /// would be a second copy of that vocabulary to keep in step.
    Features(u64),
    /// Receive descriptors primed before a driver entered its poll loop.
    ReceivePosted(u32),
    Refusal(Refusal<C>),
    /// What a domain established about time. The two travel together because
    /// neither is worth reading alone, and they are the measurement's own types
    /// rather than integers — `calibrate`'s and a `Calibration`'s — so a call
    /// site can report neither a zero frequency nor an instant it never derived.
    Established {
        tsc_hz: NonZeroU64,
        utc: UtcNanos,
    },
}

/// Why a domain refused to start, and what that left the hardware in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal<C = &'static str> {
    /// What was refused, as the header's two forms: a literal where a call site
    /// mints one, a [`Cause`] where a decode reconstructs one.
    ///
    /// Deliberately not an enum: the refusal trees belong to the crates that
    /// raise them, and a copy of one in this crate would drift from it with
    /// nothing failing.
    pub cause: C,
    /// The numbers `cause` names, in the order it names them.
    pub detail: RefusalDetail,
    /// Whether the device was told to stop, or was left decoding nothing.
    pub signalled: bool,
}

/// Up to two numbers a refusal carries, so it reaches an operator as the values
/// that made it one and not only as its class.
///
/// Two is the console line's budget rather than an arbitrary cut: a refusal
/// with more to say names the pair that identifies it and says at the mapping
/// which it left out, so what is missing is recorded where it is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalDetail {
    None,
    One(u64),
    Two(u64, u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{format, string::String, vec::Vec};

    #[test]
    fn the_empty_and_the_longest_admissible_causes_are_accepted() {
        for text in [&b""[..], b"a", b"not-virtio-net", &[b'a'; MAX_CAUSE_LEN]] {
            let cause = Cause::new(text).expect("within the alphabet and the length bound");
            assert_eq!(cause.as_bytes(), text);
            assert_eq!(cause.as_str().as_bytes(), text);
            assert_eq!(cause.len(), text.len());
            assert_eq!(cause.is_empty(), text.is_empty());
        }
        assert_eq!(Cause::new(b"").expect("empty is a cause"), Cause::EMPTY);
        assert!(Cause::EMPTY.is_empty());
    }

    #[test]
    fn one_byte_past_the_length_bound_is_refused_with_the_length_it_had() {
        let long = [b'a'; MAX_CAUSE_LEN + 1];
        assert_eq!(
            Cause::new(&long),
            Err(CauseError::TooLong {
                len: MAX_CAUSE_LEN + 1
            })
        );
        assert!(Cause::new(&long[..MAX_CAUSE_LEN]).is_ok());
    }

    #[test]
    fn a_byte_outside_the_alphabet_is_refused_and_its_position_named() {
        for (text, offset) in [(&b"NOT"[..], 0), (b"not virtio", 3), (b"not_virtio", 3)] {
            assert_eq!(
                Cause::new(text),
                Err(CauseError::NotInAlphabet { offset }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn each_cause_rejection_reads_differently() {
        let mut messages: Vec<String> = [
            CauseError::TooLong { len: 41 },
            CauseError::NotInAlphabet { offset: 2 },
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
    fn causes_compare_by_content_not_by_the_unused_tail() {
        let short = Cause::new(b"pool").expect("valid");
        assert_ne!(short, Cause::new(b"pool-").expect("valid"));
        assert_eq!(short, Cause::new(b"pool").expect("valid"));
        assert_eq!(format!("{short}"), "pool");
    }

    proptest! {
        /// Total over arbitrary bytes: every input is either a typed rejection
        /// or a cause that reproduces exactly what it was given.
        #[test]
        fn cause_construction_is_total_and_lossless(
            bytes in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            match Cause::new(&bytes) {
                Ok(cause) => {
                    prop_assert_eq!(cause.as_bytes(), &bytes[..]);
                    prop_assert_eq!(cause.len(), bytes.len());
                    prop_assert!(cause.len() <= MAX_CAUSE_LEN);
                }
                Err(CauseError::TooLong { len }) => {
                    prop_assert_eq!(len, bytes.len());
                    prop_assert!(len > MAX_CAUSE_LEN);
                }
                Err(CauseError::NotInAlphabet { offset }) => {
                    let byte = bytes.get(offset).copied().expect("the offset indexes the input");
                    prop_assert!(!matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'));
                }
            }
        }

        /// Everything the alphabet admits is accepted, so the rejection set is
        /// exactly its complement rather than something narrower.
        #[test]
        fn the_whole_cause_alphabet_is_accepted(text in "[a-z0-9-]{0,40}") {
            let cause = Cause::new(text.as_bytes()).expect("the pattern is the alphabet");
            prop_assert_eq!(cause.as_str(), text.as_str());
        }
    }

    #[test]
    fn a_refusal_keeps_every_field_it_was_given() {
        let refusal = Refusal {
            cause: "not-virtio-net",
            detail: RefusalDetail::Two(0x1af4, 0x1000),
            signalled: false,
        };
        assert_eq!(refusal.cause, "not-virtio-net");
        assert_eq!(refusal.detail, RefusalDetail::Two(0x1af4, 0x1000));
        assert!(!refusal.signalled);
        assert_eq!(
            DomainDetail::Refusal(refusal),
            DomainDetail::Refusal(refusal)
        );
    }

    #[test]
    fn the_four_detail_shapes_are_distinguishable() {
        let shapes = [
            DomainDetail::None,
            DomainDetail::Features(0),
            DomainDetail::ReceivePosted(0),
            DomainDetail::Refusal(Refusal {
                cause: "",
                detail: RefusalDetail::None,
                signalled: false,
            }),
        ];
        for (index, shape) in shapes.iter().enumerate() {
            for (other_index, other) in shapes.iter().enumerate() {
                assert_eq!(
                    shape == other,
                    index == other_index,
                    "{shape:?} vs {other:?}"
                );
            }
        }
    }
}
