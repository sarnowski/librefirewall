//! The connection's own helpers. The state machine itself is driven through
//! `crate::tests`, where a scripted peer exercises transitions as *sequences*
//! rather than as isolated calls — which is the only way a handshake or a close
//! is a real test of one.

use super::*;
use proptest::prelude::*;

#[test]
fn every_state_has_a_distinct_name() {
    let states = [
        State::SynSent,
        State::SynReceived,
        State::Established,
        State::CloseWait,
        State::LastAck,
        State::FinWait1,
        State::FinWait2,
        State::Closing,
        State::TimeWait,
        State::Closed,
    ];
    let mut names: Vec<&str> = states.iter().map(|state| state.name()).collect();
    names.sort_unstable();
    let count = names.len();
    names.dedup();
    assert_eq!(names.len(), count, "two states share a name");
    assert_eq!(State::Established.name(), "established");
    assert_eq!(State::SynSent.name(), "syn-sent");
}

/// RFC 1122 section 4.2.2.6's default when the peer offers no option, and the clamp in
/// both directions.
#[test]
fn the_segment_size_is_negotiated_between_the_offer_and_our_limit() {
    // No offer: the RFC's default, which is above the floor.
    assert_eq!(negotiated_mss(None, 1460), 536);
    // A generous offer is clamped to what this end can compose.
    assert_eq!(negotiated_mss(Some(9000), 1460), 1460);
    // A modest offer is honoured.
    assert_eq!(negotiated_mss(Some(1000), 1460), 1000);
    // An absurdly small offer is lifted to the floor a receiver must honour: a
    // one-byte segment size would turn one response into hundreds of segments.
    assert_eq!(negotiated_mss(Some(1), 1460), 536);
    assert_eq!(negotiated_mss(Some(0), 1460), 536);
    // Our own limit still wins, even below the floor: this end cannot compose
    // more than it has storage for.
    assert_eq!(negotiated_mss(Some(1460), 100), 100);
    // And a limit of zero would make every segment empty, so one byte is the
    // least a connection is given.
    assert_eq!(negotiated_mss(Some(1460), 0), 1);
}

#[test]
fn the_advertised_shift_is_the_smallest_that_expresses_the_window() {
    assert_eq!(receive_scale(0), 0);
    assert_eq!(receive_scale(8192), 0);
    assert_eq!(receive_scale(u32::from(u16::MAX)), 0);
    assert_eq!(receive_scale(u32::from(u16::MAX) + 1), 1);
    assert_eq!(receive_scale(u32::from(u16::MAX) * 2 + 2), 2);
    // The shift is bounded by RFC 7323's maximum however large the window is.
    assert_eq!(receive_scale(u32::MAX), MAX_WINDOW_SCALE);
}

#[test]
fn a_window_is_held_to_what_its_shift_can_express() {
    assert_eq!(advertisable(1000, 0), 1000);
    assert_eq!(advertisable(u32::MAX, 0), u32::from(u16::MAX));
    assert_eq!(advertisable(u32::MAX, 1), u32::from(u16::MAX) * 2);
    // A shift above the maximum is clamped rather than shifting out of range.
    assert_eq!(
        advertisable(u32::MAX, 200),
        u32::from(u16::MAX) << MAX_WINDOW_SCALE
    );
}

#[test]
fn a_peers_window_is_scaled_by_the_shift_it_offered() {
    assert_eq!(scaled_window(1000, 0), 1000);
    assert_eq!(scaled_window(1000, 3), 8000);
    assert_eq!(
        scaled_window(u16::MAX, MAX_WINDOW_SCALE),
        u32::from(u16::MAX) << MAX_WINDOW_SCALE
    );
    // Beyond the maximum the shift is clamped, so the product cannot leave
    // `u32`.
    assert_eq!(
        scaled_window(u16::MAX, 255),
        u32::from(u16::MAX) << MAX_WINDOW_SCALE
    );
}

proptest! {
    /// The advertised shift always expresses the window it was derived for, and
    /// the window advertised under it always fits the sixteen bits a header
    /// carries. A shift that did not would put a window on the wire that meant
    /// something else.
    #[test]
    fn a_window_and_its_shift_always_agree(window in any::<u32>()) {
        let scale = receive_scale(window);
        let held = advertisable(window, scale);
        prop_assert!(scale <= MAX_WINDOW_SCALE);
        prop_assert!(held <= window);
        prop_assert!((held >> scale) <= u32::from(u16::MAX));
        // And the shifted value read back as a peer would read it is no larger
        // than what this end promised.
        // Lossless by the assertion above.
        let advertised = (held >> scale) as u16;
        prop_assert!(scaled_window(advertised, scale) <= held);
    }

    /// Scaling any window by any shift stays inside `u32`, which is what keeps
    /// a peer from choosing an arithmetic fault with two header fields.
    #[test]
    fn scaling_any_window_by_any_shift_is_bounded(window in any::<u16>(), scale in any::<u8>()) {
        let scaled = scaled_window(window, scale);
        prop_assert!(scaled <= u32::from(u16::MAX) << MAX_WINDOW_SCALE);
    }

    /// Whatever a peer offers and whatever this end limits itself to, the
    /// negotiated size is inside both bounds and never zero — a zero would make
    /// every send an empty segment and no stream would ever move.
    #[test]
    fn the_negotiated_size_is_never_zero_and_never_above_our_limit(
        offered in prop::option::of(any::<u16>()),
        limit in any::<u16>(),
    ) {
        let mss = negotiated_mss(offered, limit);
        prop_assert!(mss >= 1);
        prop_assert!(mss <= limit.max(1));
    }
}
