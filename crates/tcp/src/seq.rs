//! TCP sequence numbers: the modulo-2^32 arithmetic and the four comparisons
//! RFC 793 section 3.3 states the protocol in.
//!
//! Every value here arrives from the network, so no operation may overflow and
//! none may panic. That is why the type wraps a `u32` privately and exposes no
//! `Add`, `Sub` or `Ord`: the derivable ones are all wrong. `Ord` on the
//! integer would order 0xFFFF_FFFF above 0x0000_0001, which are one apart in
//! sequence space; `Sub` would panic on the wrap it exists to cross. The
//! comparison that is correct — the sign of the wrapping difference read as
//! `i32` — is available under a name that says which direction it means.

use core::fmt;

/// A point in a TCP sequence space, modulo 2^32.
///
/// Deliberately not `Ord`: sequence space is a circle, so no total order exists
/// over the whole of it and the derived one would be wrong across the wrap. The
/// relations below hold over the half-space RFC 793 section 3.3 reasons in — two
/// numbers less than 2^31 apart — which is the only region a window can span.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SeqNumber(u32);

impl SeqNumber {
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The number as it travels on the wire.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// `self + count`, modulo 2^32 — which is what a sequence number does at
    /// the top of its space rather than an overflow to reject.
    #[must_use]
    pub const fn add(self, count: u32) -> Self {
        Self(self.0.wrapping_add(count))
    }

    /// How far `self` lies ahead of `earlier`, modulo 2^32.
    ///
    /// Unsigned, so a `self` *behind* `earlier` yields the enormous complement
    /// rather than a negative number. Callers that need to know which side of
    /// `earlier` they are on ask [`follows`](Self::follows) first; callers that
    /// have already established the order — an acknowledgement inside the send
    /// window, a payload inside the receive window — use this to size it.
    #[must_use]
    pub const fn distance_from(self, earlier: Self) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }

    /// RFC 793's `<`: whether `self` precedes `other` in sequence space.
    ///
    /// The wrapping difference read as `i32` is the whole of it — the standard
    /// reading, and exact for the half-space the protocol stays inside.
    #[must_use]
    pub const fn precedes(self, other: Self) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }

    #[must_use]
    pub const fn follows(self, other: Self) -> bool {
        other.precedes(self)
    }

    #[must_use]
    pub const fn precedes_or_equals(self, other: Self) -> bool {
        !self.follows(other)
    }

    #[must_use]
    pub const fn follows_or_equals(self, other: Self) -> bool {
        !self.precedes(other)
    }

    /// Whether `self` falls in the half-open window `[start, start + len)`.
    ///
    /// A zero-length window contains nothing, which is the case RFC 793 p.69
    /// handles separately and the reason this is not written as a pair of
    /// inequalities at the call sites: `start <= self < start` is vacuously
    /// false for the comparison above and true for a careless one.
    #[must_use]
    pub const fn in_window(self, start: Self, len: u32) -> bool {
        self.distance_from(start) < len
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The wrap is the whole reason this type exists, so it is the first thing
    /// checked: one before zero precedes zero, and the derived integer order
    /// would say the opposite.
    #[test]
    fn the_order_is_correct_across_the_wrap() {
        let last = SeqNumber::new(u32::MAX);
        let first = SeqNumber::new(0);
        assert!(last.precedes(first));
        assert!(first.follows(last));
        assert_eq!(first.distance_from(last), 1);
        assert_eq!(last.add(1), first);
    }

    #[test]
    fn a_number_neither_precedes_nor_follows_itself() {
        for raw in [0, 1, 0x8000_0000, u32::MAX] {
            let seq = SeqNumber::new(raw);
            assert!(!seq.precedes(seq));
            assert!(!seq.follows(seq));
            assert!(seq.precedes_or_equals(seq));
            assert!(seq.follows_or_equals(seq));
            assert_eq!(seq.distance_from(seq), 0);
        }
    }

    #[test]
    fn a_zero_length_window_contains_nothing() {
        let start = SeqNumber::new(7);
        for raw in [0, 6, 7, 8, u32::MAX] {
            assert!(!SeqNumber::new(raw).in_window(start, 0));
        }
    }

    #[test]
    fn a_window_that_wraps_contains_both_of_its_halves() {
        let start = SeqNumber::new(u32::MAX - 1);
        assert!(start.in_window(start, 4));
        assert!(SeqNumber::new(u32::MAX).in_window(start, 4));
        assert!(SeqNumber::new(0).in_window(start, 4));
        assert!(SeqNumber::new(1).in_window(start, 4));
        assert!(!SeqNumber::new(2).in_window(start, 4));
        assert!(!SeqNumber::new(u32::MAX - 2).in_window(start, 4));
    }

    #[test]
    fn the_raw_value_survives_a_round_trip() {
        for raw in [0, 1, 42, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            assert_eq!(SeqNumber::new(raw).raw(), raw);
        }
        assert_eq!(SeqNumber::new(3).to_string(), "3");
    }

    proptest! {
        /// Exactly one of the three relations holds for any pair inside the
        /// half-space RFC 793 reasons in, which is what makes the pair of them a
        /// decision rather than two guesses.
        ///
        /// The antipode is the one pair where it does not, and it is excluded
        /// deliberately rather than worked around: two numbers exactly 2^31
        /// apart are outside the region the relation is defined over, and both
        /// directions read as "precedes". A caller that reached it would be
        /// holding a window of two gigabytes, which no field in a TCP header can
        /// express — [`MAX_WINDOW_SCALE`](crate::segment::MAX_WINDOW_SCALE)
        /// bounds a window to 2^30 — so this is a property of the numbers rather
        /// than a gap in the code.
        #[test]
        fn precedes_follows_and_equals_partition_every_pair(a in any::<u32>(), b in any::<u32>()) {
            let (a, b) = (SeqNumber::new(a), SeqNumber::new(b));
            let relations = u8::from(a.precedes(b)) + u8::from(a.follows(b)) + u8::from(a == b);
            let antipodal = a.distance_from(b) == 0x8000_0000;
            let expected = if antipodal { 2 } else { 1 };
            prop_assert_eq!(relations, expected);
        }

        /// The antipode is reached deliberately, so the exclusion above is a
        /// stated fact rather than an untested claim.
        #[test]
        fn the_antipode_is_the_one_ambiguous_pair(base in any::<u32>()) {
            let a = SeqNumber::new(base);
            let b = a.add(0x8000_0000);
            prop_assert!(a.precedes(b));
            prop_assert!(b.precedes(a));
            prop_assert_ne!(a, b);
        }

        /// Adding a count and measuring the distance back are inverses over the
        /// whole of the space, wrap included.
        #[test]
        fn adding_and_measuring_are_inverse(start in any::<u32>(), count in any::<u32>()) {
            let start = SeqNumber::new(start);
            prop_assert_eq!(start.add(count).distance_from(start), count);
        }

        /// A number is in a window exactly when it is at or after the start and
        /// before the end — the reading RFC 793 p.69 states the acceptability
        /// test in, checked against the distance form the code uses.
        #[test]
        fn membership_agrees_with_the_two_inequalities(
            start in any::<u32>(),
            len in 1u32..=0x4000_0000,
            offset in any::<u32>(),
        ) {
            let start = SeqNumber::new(start);
            let candidate = start.add(offset);
            let end = start.add(len);
            let by_inequality = candidate.follows_or_equals(start) && candidate.precedes(end);
            prop_assert_eq!(candidate.in_window(start, len), by_inequality);
        }

        /// The relation is antisymmetric and its complement is the inclusive
        /// form, so no call site needs to spell out a negation.
        #[test]
        fn the_inclusive_forms_are_the_negations(a in any::<u32>(), b in any::<u32>()) {
            let (a, b) = (SeqNumber::new(a), SeqNumber::new(b));
            prop_assert_eq!(a.precedes_or_equals(b), !a.follows(b));
            prop_assert_eq!(a.follows_or_equals(b), !a.precedes(b));
        }

        /// Ordering is transitive over any triple inside one half-space, which
        /// is the property every window computation leans on.
        #[test]
        fn ordering_is_transitive_inside_a_half_space(
            base in any::<u32>(),
            first in 0u32..0x2000_0000,
            second in 0u32..0x2000_0000,
        ) {
            let base = SeqNumber::new(base);
            let middle = base.add(first);
            let last = middle.add(second);
            if base.precedes(middle) && middle.precedes(last) {
                prop_assert!(base.precedes(last));
            }
        }
    }
}
