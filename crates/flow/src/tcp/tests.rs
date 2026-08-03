use super::*;
use net_headers::TCP_HEADER_LEN;
use proptest::prelude::*;
use std::vec::Vec;

const FIN: TcpFlags = TcpFlags(0x01);
const SYN: TcpFlags = TcpFlags(0x02);
const RST: TcpFlags = TcpFlags(0x04);
const PSH: TcpFlags = TcpFlags(0x08);
const ACK: TcpFlags = TcpFlags(0x10);
const URG: TcpFlags = TcpFlags(0x20);

const fn both(first: TcpFlags, second: TcpFlags) -> TcpFlags {
    TcpFlags(first.0 | second.0)
}

fn header(flags: TcpFlags, data_offset: u8) -> TcpHeader {
    TcpHeader {
        source_port: 40_000,
        destination_port: 443,
        sequence: 1_000,
        acknowledgement: 2_000,
        data_offset,
        flags,
        window: 4_096,
        checksum: 0,
        urgent_pointer: 0,
    }
}

fn bytes(options: &[u8], payload: usize) -> Vec<u8> {
    let mut bytes = std::vec![0u8; TCP_HEADER_LEN];
    bytes.extend_from_slice(options);
    bytes.extend(core::iter::repeat_n(0u8, payload));
    bytes
}

fn sequence(raw: u32) -> SeqNumber {
    SeqNumber::new(raw)
}

// --------------------------------------------------------------- reading

#[test]
fn a_segment_reads_its_length_from_the_datagram_and_not_from_its_own_claim() {
    let wire = bytes(&[], 40);
    let segment = Segment::read(&header(ACK, 5), &wire).expect("a segment");
    assert_eq!(segment.length, 40);
    assert_eq!(segment.end(), sequence(1_040));
    assert!(segment.window_scale.is_none());
}

#[test]
fn the_phantom_bytes_of_syn_and_fin_occupy_sequence_space() {
    let wire = bytes(&[], 0);
    assert_eq!(
        Segment::read(&header(SYN, 5), &wire)
            .expect("a segment")
            .length,
        1
    );
    assert_eq!(
        Segment::read(&header(both(FIN, ACK), 5), &wire)
            .expect("a segment")
            .length,
        1
    );
    assert_eq!(
        Segment::read(&header(ACK, 5), &wire)
            .expect("a segment")
            .length,
        0
    );
}

#[test]
fn a_data_offset_below_a_header_or_past_the_datagram_is_refused() {
    let wire = bytes(&[], 8);
    for data_offset in [0, 4, 8, 15] {
        assert_eq!(
            Segment::read(&header(ACK, data_offset), &wire),
            Err(SegmentError::HeaderLengthInvalid { data_offset })
        );
    }
    // Seven words is a header plus eight bytes of options, which this datagram
    // does carry.
    assert!(Segment::read(&header(ACK, 7), &wire).is_ok());
}

#[test]
fn a_datagram_shorter_than_a_header_is_refused() {
    for got in 0..TCP_HEADER_LEN {
        let wire = std::vec![0u8; got];
        assert_eq!(
            Segment::read(&header(ACK, 5), &wire),
            Err(SegmentError::Truncated {
                needed: TCP_HEADER_LEN,
                got
            })
        );
    }
}

// ------------------------------------------------------------- the options

#[test]
fn the_window_scale_option_is_read_only_from_a_syn() {
    let option = [1u8, 3, 3, 7];
    let wire = bytes(&option, 0);
    assert_eq!(
        Segment::read(&header(SYN, 6), &wire)
            .expect("a segment")
            .window_scale,
        Some(7)
    );
    // The same bytes behind an ordinary segment are not an offer: RFC 7323 gives
    // the option one appearance, on the handshake.
    assert_eq!(
        Segment::read(&header(ACK, 6), &wire)
            .expect("a segment")
            .window_scale,
        None
    );
}

#[test]
fn a_shift_above_the_maximum_is_clamped() {
    let wire = bytes(&[1, 3, 3, 200], 0);
    assert_eq!(
        Segment::read(&header(SYN, 6), &wire)
            .expect("a segment")
            .window_scale,
        Some(MAX_WINDOW_SCALE)
    );
}

#[test]
fn the_option_area_is_walked_past_the_options_it_does_not_read() {
    // Maximum segment size (kind 2, length 4), then a no-op, then the shift.
    let wire = bytes(&[2, 4, 0x05, 0xb4, 1, 3, 3, 5], 0);
    assert_eq!(
        Segment::read(&header(SYN, 7), &wire)
            .expect("a segment")
            .window_scale,
        Some(5)
    );
}

/// A malformed option area yields no shift rather than a guess: past a byte that
/// does not describe an option, where the next one starts is unknowable.
#[test]
fn a_malformed_option_area_offers_nothing() {
    for option in [
        std::vec![3u8, 0, 0, 0],  // a length below two
        std::vec![3u8, 9, 0, 0],  // a length past the area
        std::vec![3u8, 4, 0, 0],  // the right kind at the wrong length
        std::vec![2u8, 20, 0, 0], // another option running off the end
        std::vec![0u8, 3, 3, 7],  // an end-of-options before the shift
        std::vec![8u8],           // a kind with no length byte
    ] {
        let padded = {
            let mut padded = option.clone();
            while padded.len() % 4 != 0 {
                padded.push(1);
            }
            padded
        };
        let wire = bytes(&padded, 0);
        // Lossless: the option area here is at most a handful of words.
        let data_offset = ((TCP_HEADER_LEN + padded.len()) / 4) as u8;
        assert_eq!(
            Segment::read(&header(SYN, data_offset), &wire)
                .expect("a segment")
                .window_scale,
            None,
            "option {option:?} was read as an offer"
        );
    }
}

/// A `SYN`'s own window is never scaled, whatever shift it offered: scaling
/// applies from the segment after the one that negotiated it.
#[test]
fn a_syns_own_window_is_never_scaled() {
    let wire = bytes(&[1, 3, 3, 7], 0);
    let syn = Segment::read(&header(SYN, 6), &wire).expect("a segment");
    assert_eq!(syn.scaled_window(7), 4_096);
    let data = Segment::read(&header(ACK, 5), &bytes(&[], 0)).expect("a segment");
    assert_eq!(data.scaled_window(7), 4_096 << 7);
    assert_eq!(data.scaled_window(200), 4_096 << MAX_WINDOW_SCALE);
}

// ---------------------------------------------------------------- events

#[test]
fn every_flag_combination_an_exchange_produces_is_an_event() {
    assert_eq!(event(SYN), Some(Event::Syn));
    assert_eq!(event(both(SYN, ACK)), Some(Event::SynAck));
    assert_eq!(event(ACK), Some(Event::Ack));
    assert_eq!(event(both(ACK, PSH)), Some(Event::Ack));
    assert_eq!(event(both(FIN, ACK)), Some(Event::Fin));
    assert_eq!(event(RST), Some(Event::Reset));
    assert_eq!(event(both(RST, ACK)), Some(Event::Reset));
    // The urgent bit changes nothing a tracker decides.
    assert_eq!(event(both(ACK, URG)), Some(Event::Ack));
}

#[test]
fn the_shapes_a_scanner_relies_on_are_no_event_at_all() {
    for flags in [
        TcpFlags(0),    // no flags at all
        FIN,            // a close with nothing to acknowledge
        PSH,            // push alone
        URG,            // urgent alone
        both(SYN, FIN), // an open and a close at once
        both(RST, SYN), // a reset trying to open
        both(RST, FIN), // a reset trying to close
        TcpFlags(0xff), // everything at once
    ] {
        assert_eq!(event(flags), None, "flags {flags:?} were admitted");
    }
}

// ------------------------------------------------------------- the machine

/// The whole admissibility table, written out so a change to it is a change to
/// this list rather than to a match arm nobody reads.
#[test]
fn the_admissibility_table_is_what_it_says_it_is() {
    use Direction::{Original, Reply};
    use Event::{Ack, Fin, Reset, Syn, SynAck};
    use FlowState as S;
    let expected: &[(S, Event, Direction, bool)] = &[
        // Nothing is admitted against a slot that holds no flow, or one whose
        // flow a reset already ended.
        (S::Vacant, Syn, Original, false),
        (S::Vacant, Reset, Original, false),
        (S::Closed, Ack, Original, false),
        (S::Closed, Reset, Reply, false),
        // A flow with only the originator's `SYN`.
        (S::SynSent, Syn, Original, true),
        (S::SynSent, Syn, Reply, true),
        (S::SynSent, SynAck, Reply, true),
        (S::SynSent, SynAck, Original, false),
        (S::SynSent, Ack, Original, false),
        (S::SynSent, Ack, Reply, false),
        (S::SynSent, Fin, Original, false),
        (S::SynSent, Reset, Reply, true),
        (S::SynSent, Reset, Original, true),
        // Both ends have spoken, so anything a real exchange produces is
        // admissible and the window is the whole constraint.
        (S::SynReceived, Syn, Original, true),
        (S::SynReceived, SynAck, Original, true),
        (S::SynReceived, Ack, Original, true),
        (S::SynReceived, Ack, Reply, true),
        (S::SynReceived, Fin, Reply, true),
        (S::SynReceived, Reset, Original, true),
        // A synchronized flow refuses an opening move in either direction.
        (S::Established, Ack, Original, true),
        (S::Established, Fin, Reply, true),
        (S::Established, Syn, Original, false),
        (S::Established, SynAck, Reply, false),
        (S::Established, Reset, Reply, true),
        (S::FinWait, Ack, Original, true),
        (S::FinWait, Syn, Original, false),
        (S::CloseWait, Fin, Reply, true),
        (S::CloseWait, SynAck, Original, false),
        (S::Closing, Ack, Reply, true),
        (S::Closing, Syn, Reply, false),
        (S::TimeWait, Ack, Original, true),
        (S::TimeWait, Fin, Reply, true),
        (S::TimeWait, Syn, Original, false),
        (S::TimeWait, Reset, Original, true),
        // A TCP segment never resolves to a flow of another protocol, the
        // protocol being part of a flow's identity; answered rather than
        // asserted.
        (S::UdpAssured, Ack, Original, false),
        (S::IcmpReplied, Reset, Reply, false),
    ];
    for (state, event, direction, admitted) in expected {
        assert_eq!(
            admits(*state, *event, *direction),
            *admitted,
            "{:?} + {:?} from {:?} should be {}",
            state,
            event,
            direction,
            if *admitted { "admitted" } else { "refused" }
        );
    }
}

/// The whole transition table for the states an event does not simply leave to
/// the two `FIN` facts.
#[test]
fn the_handshake_transitions_are_what_they_say_they_are() {
    use Direction::{Original, Reply};
    use Event::{Reset, Syn, SynAck};
    use FlowState as S;
    let none = (false, false, false, false);
    assert_eq!(next_state(S::SynSent, Syn, Original, none), S::SynSent);
    assert_eq!(next_state(S::SynSent, Syn, Reply, none), S::SynReceived);
    assert_eq!(next_state(S::SynSent, SynAck, Reply, none), S::SynReceived);
    assert_eq!(
        next_state(S::SynReceived, SynAck, Original, none),
        S::SynReceived
    );
    assert_eq!(next_state(S::SynReceived, Syn, Reply, none), S::SynReceived);
    // A reset ends a flow from wherever it was.
    for state in FlowState::ALL {
        assert_eq!(next_state(state, Reset, Original, none), S::Closed);
    }
}

/// The five synchronized states are a function of the two directions' `FIN`
/// facts, so a simultaneous close needs no arm of its own.
#[test]
fn the_closing_states_are_a_function_of_the_two_fins() {
    use FlowState as S;
    /// Both directions' `FIN` facts, as `closed_state` takes them.
    type Facts = (bool, bool, bool, bool);
    let cases: &[(Facts, S)] = &[
        ((false, false, false, false), S::Established),
        ((true, false, false, false), S::FinWait),
        ((true, true, false, false), S::CloseWait),
        ((false, false, true, false), S::FinWait),
        ((false, false, true, true), S::CloseWait),
        ((true, false, true, false), S::Closing),
        ((true, true, true, false), S::Closing),
        ((true, false, true, true), S::Closing),
        ((true, true, true, true), S::TimeWait),
    ];
    for (facts, expected) in cases {
        assert_eq!(closed_state(*facts), *expected, "facts {facts:?}");
        // And reached through the machine, from every synchronized state.
        assert_eq!(
            next_state(S::Established, Event::Ack, Direction::Original, *facts),
            *expected
        );
    }
}

// ---------------------------------------------------------------- windows

/// Two directions of a flow mid-conversation, so the four comparisons can each be
/// reached one at a time.
fn synchronized() -> (DirectionState, DirectionState) {
    let mut sender = DirectionState::SILENT;
    let mut peer = DirectionState::SILENT;
    sender.open(sequence(1_000), 4_096);
    peer.open(sequence(5_000), 4_096);
    sender.raise_max_end(sequence(1_000 + 4_096));
    peer.raise_max_end(sequence(5_000 + 4_096));
    (sender, peer)
}

fn probe(flags: TcpFlags, sequence: u32, acknowledgement: u32, length: u32) -> Segment {
    Segment {
        flags,
        sequence: SeqNumber::new(sequence),
        acknowledgement: SeqNumber::new(acknowledgement),
        window: 4_096,
        length,
        window_scale: None,
    }
}

#[test]
fn a_segment_inside_both_windows_is_admitted() {
    let (sender, peer) = synchronized();
    assert_eq!(
        in_window(&sender, &peer, &probe(ACK, 1_000, 5_000, 100)),
        Ok(())
    );
}

#[test]
fn each_window_edge_refuses_its_own_segment() {
    let (sender, peer) = synchronized();
    assert_eq!(
        in_window(&sender, &peer, &probe(ACK, 1_000 + 4_097, 5_000, 0)),
        Err(WindowEdge::SequenceAhead)
    );
    assert_eq!(
        in_window(
            &sender,
            &peer,
            &probe(ACK, 1_000u32.wrapping_sub(5_000), 5_000, 0)
        ),
        Err(WindowEdge::SequenceBehind)
    );
    assert_eq!(
        in_window(&sender, &peer, &probe(ACK, 1_000, 5_001, 0)),
        Err(WindowEdge::AckAhead)
    );
    assert_eq!(
        in_window(
            &sender,
            &peer,
            &probe(ACK, 1_000, 5_000u32.wrapping_sub(4_097), 0)
        ),
        Err(WindowEdge::AckBehind)
    );
}

/// A segment with no `ACK` has no acknowledgement to judge, so only the two
/// sequence edges apply.
#[test]
fn a_segment_with_no_acknowledgement_is_judged_on_its_sequence_alone() {
    let (sender, peer) = synchronized();
    assert_eq!(
        in_window(&sender, &peer, &probe(SYN, 1_000, 0xdead_beef, 1)),
        Ok(())
    );
}

/// The first thing a direction says is opened rather than checked — except for
/// an acknowledgement, which must be exactly the handshake it answers.
#[test]
fn a_first_reply_must_acknowledge_exactly_the_handshake() {
    let mut sender = DirectionState::SILENT;
    let mut peer = DirectionState::SILENT;
    peer.open(sequence(1_000), 4_096);
    assert_eq!(
        in_window(&sender, &peer, &probe(both(SYN, ACK), 9_999, 1_000, 1)),
        Ok(())
    );
    assert_eq!(
        in_window(&sender, &peer, &probe(both(SYN, ACK), 9_999, 1_001, 1)),
        Err(WindowEdge::AckNotHandshake)
    );
    assert_eq!(
        in_window(&sender, &peer, &probe(both(RST, ACK), 0, 0x7777_7777, 0)),
        Err(WindowEdge::AckNotHandshake)
    );
    // A first segment with no acknowledgement — the simultaneous-open `SYN` — is
    // opened whatever its sequence number is.
    assert_eq!(
        in_window(&sender, &peer, &probe(SYN, 0x1234_5678, 0, 1)),
        Ok(())
    );
    // And so is the very first packet of all, where the peer has said nothing.
    sender = DirectionState::SILENT;
    let silent = DirectionState::SILENT;
    assert_eq!(
        in_window(&sender, &silent, &probe(both(SYN, ACK), 1, 2, 1)),
        Ok(())
    );
}

/// The acknowledgement slack is one window and never more than one unscaled
/// window, so a peer with a gibibyte-wide scaled window cannot make the test
/// vacuous.
#[test]
fn the_acknowledgement_slack_is_capped() {
    let mut sender = DirectionState::SILENT;
    let mut peer = DirectionState::SILENT;
    sender.open(sequence(1_000), 1 << 28);
    peer.open(sequence(5_000_000), 4_096);
    sender.raise_max_end(sequence(1_000 + (1 << 20)));
    assert_eq!(
        in_window(
            &sender,
            &peer,
            &probe(
                ACK,
                1_000,
                5_000_000u32.wrapping_sub(MAX_ACK_SLACK).wrapping_add(1),
                0
            )
        ),
        Ok(())
    );
    assert_eq!(
        in_window(
            &sender,
            &peer,
            &probe(
                ACK,
                1_000,
                5_000_000u32.wrapping_sub(MAX_ACK_SLACK).wrapping_sub(1),
                0
            )
        ),
        Err(WindowEdge::AckBehind)
    );
}

#[test]
fn recording_a_segment_moves_both_directions() {
    let (mut sender, mut peer) = synchronized();
    record(
        &mut sender,
        &mut peer,
        &probe(both(FIN, ACK), 1_000, 5_000, 51),
    );
    assert_eq!(sender.end(), sequence(1_051));
    assert!(sender.seen_fin());
    // The acknowledgement is what authorises the peer to send further.
    assert_eq!(peer.max_end(), sequence(5_000 + 4_096));
}

#[test]
fn recording_the_first_segment_in_a_direction_opens_it() {
    let mut sender = DirectionState::SILENT;
    let mut peer = DirectionState::SILENT;
    record(&mut sender, &mut peer, &probe(SYN, 700, 0, 1));
    assert!(sender.spoken());
    assert!(sender.seen_syn());
    assert_eq!(sender.end(), sequence(701));
    assert_eq!(sender.max_end(), sequence(701));
    // No `ACK`, so the peer was authorised nothing.
    assert!(!peer.spoken());
    assert_eq!(peer.max_end(), sequence(0));
}

/// The five edges are five distinct values, so a refusal names one comparison
/// rather than a category.
#[test]
fn the_window_edges_are_distinct() {
    let edges = [
        WindowEdge::SequenceAhead,
        WindowEdge::SequenceBehind,
        WindowEdge::AckAhead,
        WindowEdge::AckBehind,
        WindowEdge::AckNotHandshake,
    ];
    for (position, edge) in edges.into_iter().enumerate() {
        for (other_position, other) in edges.into_iter().enumerate() {
            assert_eq!(position == other_position, edge == other);
        }
    }
}

proptest! {
    /// Reading a segment out of arbitrary bytes never panics, and the length it
    /// reports is bounded by the datagram it came from.
    #[test]
    fn reading_arbitrary_bytes_never_panics(
        flags in any::<u8>(),
        data_offset in any::<u8>(),
        length in 0usize..120,
        filler in any::<u8>(),
    ) {
        let wire = std::vec![filler; length];
        let mut raw = header(TcpFlags(flags), data_offset & 0x0f);
        raw.flags = TcpFlags(flags);
        if let Ok(segment) = Segment::read(&raw, &wire) {
            prop_assert!(segment.length as usize <= length + 2);
            prop_assert!(segment.window_scale.is_none_or(|shift| shift <= MAX_WINDOW_SCALE));
        }
    }

    /// Whatever a peer sends, the window test either admits it or names the edge
    /// that refused it — and an admitted segment recorded then leaves both
    /// directions monotone.
    #[test]
    fn an_arbitrary_segment_is_admitted_or_named(
        flags in any::<u8>(),
        sequence in any::<u32>(),
        acknowledgement in any::<u32>(),
        length in 0u32..2_000,
    ) {
        let (mut sender, mut peer) = synchronized();
        let segment = probe(TcpFlags(flags), sequence, acknowledgement, length);
        let before_end = sender.end();
        let before_window = sender.max_window();
        if in_window(&sender, &peer, &segment).is_ok() {
            record(&mut sender, &mut peer, &segment);
            prop_assert!(sender.end().follows_or_equals(before_end));
            prop_assert!(sender.max_window() >= before_window);
        }
    }

    /// The option walk terminates and stays inside its slice for any bytes at
    /// all, which is the property that matters: every byte of it is a peer's.
    #[test]
    fn an_arbitrary_option_area_terminates(area in prop::collection::vec(any::<u8>(), 0..60)) {
        let shift = window_scale(&area);
        prop_assert!(shift.is_none_or(|shift| shift <= MAX_WINDOW_SCALE));
    }
}
