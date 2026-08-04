use super::*;

/// Every state has an interval, and the lookup is total: a state added without
/// one would not compile, and this holds the answers to being sane rather than
/// merely present.
#[test]
fn every_state_has_an_interval_and_only_vacancy_has_none() {
    for state in FlowState::ALL {
        let span = timeout(state);
        if matches!(state, FlowState::Vacant) {
            assert_eq!(span.as_nanos(), 0, "a vacant slot holds nothing to keep");
        } else {
            assert!(span.as_nanos() > 0, "{state:?} may be held forever");
        }
    }
}

/// The half-open states are the shortest of the TCP intervals, because they are
/// the ones a flood fills the table with. A change that made either of them
/// longer than a closing interval would silently make a flood cheaper.
#[test]
fn the_half_open_states_are_reclaimed_soonest() {
    for closing in [
        FIN_WAIT_TIMEOUT,
        CLOSE_WAIT_TIMEOUT,
        CLOSING_TIMEOUT,
        TIME_WAIT_TIMEOUT,
        ESTABLISHED_TIMEOUT,
    ] {
        assert!(SYN_SENT_TIMEOUT <= closing);
        assert!(SYN_RECEIVED_TIMEOUT <= closing);
    }
}

/// The established interval is the longest, so nothing else in the table can
/// outlive a live connection.
#[test]
fn nothing_outlives_an_established_flow() {
    for state in FlowState::ALL {
        assert!(
            timeout(state) <= ESTABLISHED_TIMEOUT,
            "{state:?} outlives an established flow"
        );
    }
}

/// The interval is anchored on RFC 1122's keepalive interval, and the anchor is
/// what makes it defensible: a change to a round number would pass every other
/// test here.
#[test]
fn the_established_interval_is_the_keepalive_interval() {
    assert_eq!(ESTABLISHED_TIMEOUT.as_nanos(), 2 * 60 * 60 * 1_000_000_000);
}

/// The wait after a close is twice the maximum segment lifetime the appliance's
/// own transport is stated against, so the two cannot drift apart unnoticed.
#[test]
fn the_wait_after_closing_is_twice_a_segment_lifetime() {
    assert_eq!(TIME_WAIT_TIMEOUT, lfw_tcp::TIME_WAIT_DURATION);
}
