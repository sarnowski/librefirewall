use super::*;
use lfw_clock::{Calibration, Ticks};
use proptest::prelude::*;

fn at(nanos: u64) -> Monotonic {
    use core::num::NonZeroU64;
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

fn key(client_port: u16) -> FlowKey {
    let (key, _) = FlowKey::of(
        Endpoint::new(Ipv4Address::from_octets([10, 0, 1, 1]), client_port),
        Endpoint::new(Ipv4Address::from_octets([10, 0, 2, 2]), 443),
        Protocol::TCP,
    );
    key
}

fn sequence(raw: u32) -> SeqNumber {
    SeqNumber::new(raw)
}

#[test]
fn a_vacant_entry_holds_nothing_and_is_on_no_list() {
    let entry = FlowEntry::VACANT;
    assert!(!entry.is_occupied());
    assert_eq!(entry.state(), FlowState::Vacant);
    assert_eq!(entry.link(), NO_SLOT);
    assert_eq!(entry.generation(), 0);
}

#[test]
fn opening_a_slot_records_the_key_and_bumps_the_generation() {
    let mut entry = FlowEntry::VACANT;
    let opened = key(40_000);
    entry.open(&opened, true, FlowState::SynSent, at(7));
    assert!(entry.is_occupied());
    assert_eq!(entry.state(), FlowState::SynSent);
    assert_eq!(entry.generation(), 1);
    assert_eq!(entry.key(), opened);
    assert!(entry.matches(&opened));
    assert!(!entry.matches(&key(40_001)));
    assert_eq!(entry.last_seen_nanos(), 7);
    assert_eq!(entry.direction_of_lower(), Direction::Original);
    assert_eq!(entry.direction_of(true), Direction::Original);
    assert_eq!(entry.direction_of(false), Direction::Reply);
    // The originating half is the lower one, and the replying half the upper.
    entry.halves(true).0.open(sequence(5), 100);
    assert!(entry.original().spoken());
    assert!(!entry.reply().spoken());
}

/// A flow opened from the upper endpoint reverses which orientation is original,
/// which is the whole of what the one flag carries.
#[test]
fn a_flow_opened_from_the_upper_endpoint_reverses_the_orientation() {
    let mut entry = FlowEntry::VACANT;
    entry.open(&key(40_000), false, FlowState::UdpUnreplied, at(0));
    assert_eq!(entry.direction_of_lower(), Direction::Reply);
    assert_eq!(entry.direction_of(true), Direction::Reply);
    assert_eq!(entry.direction_of(false), Direction::Original);
    // The originating half is then the upper one, and the two accessors agree
    // with the halves a packet from the upper endpoint is given.
    entry.halves(false).0.open(sequence(5), 100);
    assert!(entry.original().spoken());
    assert!(!entry.reply().spoken());
}

/// Closing a slot keeps its generation, so a handle to what was there is refused
/// rather than resolved against whatever comes next.
#[test]
fn closing_a_slot_keeps_its_generation() {
    let mut entry = FlowEntry::VACANT;
    entry.open(&key(40_000), true, FlowState::SynSent, at(1));
    entry.close();
    assert!(!entry.is_occupied());
    assert_eq!(entry.generation(), 1);
    entry.open(&key(40_002), true, FlowState::SynSent, at(2));
    assert_eq!(entry.generation(), 2);
}

/// A slot is reused with nothing of its previous occupant's sequence state.
#[test]
fn a_reused_slot_carries_nothing_of_the_flow_before_it() {
    let mut entry = FlowEntry::VACANT;
    entry.open(&key(40_000), true, FlowState::Established, at(0));
    let (sender, _) = entry.halves(true);
    sender.open(sequence(0x1234), 4096);
    sender.note_fin();
    entry.open(&key(40_001), true, FlowState::SynSent, at(1));
    let (sender, peer) = entry.sides(true);
    assert!(!sender.spoken());
    assert!(!sender.seen_fin());
    assert_eq!(sender.end(), sequence(0));
    assert!(!peer.spoken());
}

#[test]
fn idle_time_saturates_for_a_clock_that_went_backwards() {
    let mut entry = FlowEntry::VACANT;
    entry.open(&key(40_000), true, FlowState::Established, at(1_000));
    assert_eq!(entry.idle_for(at(1_500)).as_nanos(), 500);
    assert_eq!(entry.idle_for(at(0)).as_nanos(), 0);
    entry.touch(at(2_000));
    assert_eq!(entry.idle_for(at(2_000)).as_nanos(), 0);
}

#[test]
fn only_the_states_confirmed_in_both_directions_are_assured() {
    for state in FlowState::ALL {
        let assured = matches!(
            state,
            FlowState::Established
                | FlowState::FinWait
                | FlowState::CloseWait
                | FlowState::Closing
                | FlowState::UdpAssured
                | FlowState::IcmpReplied
        );
        assert_eq!(state.is_assured(), assured, "{state:?}");
    }
    // The two that are deliberately not: a flow that is over, and one that never
    // completed.
    assert!(!FlowState::TimeWait.is_assured());
    assert!(!FlowState::SynSent.is_assured());
    assert!(!FlowState::Vacant.is_assured());
}

/// Every state's index is its position in the enumeration, which is what makes an
/// occupancy table indexed by it total.
#[test]
fn every_state_indexes_its_own_position() {
    for (position, state) in FlowState::ALL.into_iter().enumerate() {
        assert_eq!(state.index(), position);
        for (other_position, other) in FlowState::ALL.into_iter().enumerate() {
            assert_eq!(
                position == other_position,
                state == other,
                "{state:?} and {other:?} are not distinct"
            );
        }
    }
}

// -------------------------------------------------------- direction state

#[test]
fn a_silent_direction_has_said_nothing() {
    let side = DirectionState::SILENT;
    assert!(!side.spoken());
    assert!(!side.seen_syn());
    assert!(!side.seen_fin());
    assert!(!side.fin_acknowledged());
    assert!(!side.scale_offered());
    assert_eq!(side.max_window(), 0);
    assert_eq!(side.scale(), 0);
    assert_eq!(side, DirectionState::default());
}

/// Opening a direction sets its own end and holds its right edge to it: nothing
/// has authorised it to go further until the peer says so.
#[test]
fn opening_a_direction_authorises_nothing_beyond_what_it_sent() {
    let mut side = DirectionState::SILENT;
    side.open(sequence(500), 0);
    assert!(side.spoken());
    assert_eq!(side.end(), sequence(500));
    assert_eq!(side.max_end(), sequence(500));
    // A window of zero is held at one, so a zero-window peer is not mistaken for
    // one that has never spoken.
    assert_eq!(side.max_window(), 1);
}

#[test]
fn the_end_and_the_window_only_ever_move_forward() {
    let mut side = DirectionState::SILENT;
    side.open(sequence(1_000), 4_096);
    side.extend_end(sequence(900));
    assert_eq!(side.end(), sequence(1_000));
    side.extend_end(sequence(1_100));
    assert_eq!(side.end(), sequence(1_100));
    side.widen_window(1_024);
    assert_eq!(side.max_window(), 4_096);
    side.widen_window(8_192);
    assert_eq!(side.max_window(), 8_192);
    side.raise_max_end(sequence(900));
    assert_eq!(side.max_end(), sequence(1_000));
    side.raise_max_end(sequence(9_000));
    assert_eq!(side.max_end(), sequence(9_000));
}

#[test]
fn a_fin_is_acknowledged_only_once_the_peer_covers_it() {
    let mut side = DirectionState::SILENT;
    side.open(sequence(100), 4_096);
    side.note_fin();
    assert!(side.seen_fin());
    side.note_acknowledged(sequence(99));
    assert!(!side.fin_acknowledged());
    side.note_acknowledged(sequence(100));
    assert!(side.fin_acknowledged());
}

/// An acknowledgement covering everything only matters where a `FIN` was sent:
/// otherwise there is nothing for it to close.
#[test]
fn an_acknowledgement_without_a_fin_closes_nothing() {
    let mut side = DirectionState::SILENT;
    side.open(sequence(100), 4_096);
    side.note_acknowledged(sequence(4_000));
    assert!(!side.fin_acknowledged());
}

#[test]
fn a_shift_is_recorded_only_where_it_was_offered_and_is_clamped() {
    let mut side = DirectionState::SILENT;
    side.note_syn(None);
    assert!(side.seen_syn());
    assert!(!side.scale_offered());
    assert_eq!(side.scale(), 0);

    let mut offered = DirectionState::SILENT;
    offered.note_syn(Some(200));
    assert!(offered.scale_offered());
    assert_eq!(offered.scale(), MAX_WINDOW_SCALE);
    offered.abandon_scaling();
    assert_eq!(offered.scale(), 0);
    // The offer is remembered even once the shift is given up, because that is
    // what the other end's silence — not this end's — is what decides.
    assert!(offered.scale_offered());
}

#[test]
fn the_closing_facts_report_both_directions() {
    let mut entry = FlowEntry::VACANT;
    entry.open(&key(40_000), true, FlowState::Established, at(0));
    assert_eq!(entry.closing_facts(), (false, false, false, false));
    let (lower, _) = entry.halves(true);
    lower.open(sequence(10), 4_096);
    lower.note_fin();
    assert_eq!(entry.closing_facts(), (true, false, false, false));
    let (lower, _) = entry.halves(true);
    lower.note_acknowledged(sequence(10));
    assert_eq!(entry.closing_facts(), (true, true, false, false));
}

#[test]
fn scaling_is_offered_only_when_both_directions_did() {
    let mut entry = FlowEntry::VACANT;
    entry.open(&key(40_000), true, FlowState::SynReceived, at(0));
    assert!(!entry.both_offered_scaling());
    entry.halves(true).0.note_syn(Some(3));
    assert!(!entry.both_offered_scaling());
    entry.halves(false).0.note_syn(Some(5));
    assert!(entry.both_offered_scaling());
    entry.abandon_scaling();
    assert_eq!(entry.sides(true).0.scale(), 0);
    assert_eq!(entry.sides(false).0.scale(), 0);
}

proptest! {
    /// The key an entry reports is the key it was opened with, for any tuple: the
    /// entry stores the canonical pair and re-forming it cannot disagree.
    #[test]
    fn an_entry_reports_the_key_it_was_opened_with(
        lower_address in any::<u32>(),
        upper_address in any::<u32>(),
        lower_port in any::<u16>(),
        upper_port in any::<u16>(),
        protocol in any::<u8>(),
    ) {
        let (key, _) = FlowKey::of(
            Endpoint::new(Ipv4Address::from_octets(lower_address.to_be_bytes()), lower_port),
            Endpoint::new(Ipv4Address::from_octets(upper_address.to_be_bytes()), upper_port),
            Protocol(protocol),
        );
        let mut entry = FlowEntry::VACANT;
        entry.open(&key, true, FlowState::UdpUnreplied, at(0));
        prop_assert_eq!(entry.key(), key);
        prop_assert!(entry.matches(&key));
    }

    /// The window and the two edges are monotone whatever order values arrive in,
    /// which is what keeps a stale segment from narrowing a window that data is
    /// already in flight under.
    #[test]
    fn a_direction_is_monotone_under_any_order(
        values in prop::collection::vec((any::<u32>(), any::<u32>()), 1..24),
    ) {
        let mut side = DirectionState::SILENT;
        let (first_end, first_window) = values.first().copied().expect("a first value");
        side.open(SeqNumber::new(first_end), first_window);
        let mut window = side.max_window();
        for (end, offered) in &values {
            let before_end = side.end();
            let before_edge = side.max_end();
            side.extend_end(SeqNumber::new(*end));
            side.widen_window(*offered);
            side.raise_max_end(SeqNumber::new(*end));
            prop_assert!(side.max_window() >= window);
            prop_assert!(side.end().follows_or_equals(before_end));
            prop_assert!(side.max_end().follows_or_equals(before_edge));
            window = side.max_window();
        }
    }
}
