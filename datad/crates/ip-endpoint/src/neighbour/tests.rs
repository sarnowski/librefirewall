//! The cache driven as a cache: resolutions as *sequences*, and every way a peer
//! can try to place an entry in one.

use super::*;
use core::num::NonZeroU64;
use lfw_clock::{Calibration, Ticks};
use proptest::prelude::*;

const GATEWAY: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);
const ROUTER_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x02]);
const IMPOSTOR_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0xde, 0xad, 0x01]);

/// An instant `nanos` after boot, built the way this crate's callers build one.
fn at(nanos: u64) -> Monotonic {
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

/// Resolve a neighbour the ordinary way: ask once, answer once.
fn resolved(cache: &mut NeighbourCache, now: Monotonic, address: Ipv4Address, mac: MacAddress) {
    assert_eq!(cache.resolve(now, address), Resolution::Ask);
    assert_eq!(cache.learn(now, address, mac), Learned::Resolved);
    assert_eq!(cache.resolve(now, address), Resolution::Known(mac));
}

#[test]
fn a_next_hop_is_asked_about_once_and_then_known() {
    let mut cache = NeighbourCache::new();
    assert_eq!(cache.held(), 0);

    assert_eq!(cache.resolve(at(0), GATEWAY), Resolution::Ask);
    assert_eq!(cache.held(), 1, "the request was not recorded");
    // Asked and not yet due, so nothing more goes on the wire: a caller polled
    // between the request and its answer must not flood the link.
    assert_eq!(cache.resolve(at(1_000), GATEWAY), Resolution::Waiting);
    assert_eq!(cache.counters().requested, 1);

    assert_eq!(
        cache.learn(at(2_000), GATEWAY, ROUTER_MAC),
        Learned::Resolved
    );
    assert_eq!(
        cache.resolve(at(3_000), GATEWAY),
        Resolution::Known(ROUTER_MAC)
    );
    assert_eq!(cache.counters().learned, 1);
    assert_eq!(cache.counters().refused(), 0);
}

/// A request that goes unanswered is re-sent a bounded number of times and then
/// the resolution is reported as failed — the caller must learn, because one left
/// waiting would hold a dial open on an address nothing answers for.
#[test]
fn an_unanswered_request_is_retried_a_bounded_number_of_times_and_then_reported() {
    let mut cache = NeighbourCache::new();
    let mut elapsed = 0u64;
    let mut asked = 0;
    assert_eq!(cache.resolve(at(elapsed), GATEWAY), Resolution::Ask);
    asked += 1;

    for _ in 1..MAX_REQUESTS {
        // Before the timeout nothing is re-sent, however often the caller asks.
        elapsed += REQUEST_TIMEOUT.as_nanos() - 1;
        assert_eq!(cache.resolve(at(elapsed), GATEWAY), Resolution::Waiting);
        elapsed += 1;
        assert_eq!(cache.resolve(at(elapsed), GATEWAY), Resolution::Ask);
        asked += 1;
    }
    assert_eq!(asked, MAX_REQUESTS);
    assert_eq!(cache.counters().requested, u64::from(MAX_REQUESTS));

    elapsed += REQUEST_TIMEOUT.as_nanos();
    assert_eq!(cache.resolve(at(elapsed), GATEWAY), Resolution::Unreachable);
    assert_eq!(cache.counters().abandoned, 1);
    assert_eq!(cache.held(), 0, "an abandoned resolution held its slot");

    // Reported once. The next attempt is a fresh resolution, because whether to
    // try again is the caller's decision and its own backoff.
    assert_eq!(cache.resolve(at(elapsed), GATEWAY), Resolution::Ask);
    assert_eq!(cache.counters().abandoned, 1);
}

/// The classic poisoning primitive, and it is inert: a reply nothing was waiting
/// on changes nothing. So a flood of distinct addresses cannot insert a single
/// entry, whatever its rate.
#[test]
fn an_unsolicited_reply_is_never_learned_and_a_flood_of_them_inserts_nothing() {
    let mut cache = NeighbourCache::new();
    assert_eq!(
        cache.learn(at(0), GATEWAY, ROUTER_MAC),
        Learned::Unsolicited
    );
    assert_eq!(cache.held(), 0);

    for index in 0..255u8 {
        let address = Ipv4Address::from_octets([10, 0, 2, index]);
        let mac = MacAddress([0x52, 0x54, 0x00, 0x00, 0x01, index]);
        assert_eq!(cache.learn(at(0), address, mac), Learned::Unsolicited);
        assert_eq!(cache.held(), 0, "a flood placed an entry");
    }
    assert_eq!(cache.counters().unsolicited, 256);
    assert_eq!(cache.counters().learned, 0);

    // And the address this end does ask about is still resolvable afterwards, so
    // the flood did not consume the table either.
    resolved(&mut cache, at(0), GATEWAY, ROUTER_MAC);
}

/// A resolved entry is immutable for its lifetime, so a second answer cannot
/// re-bind a next hop the appliance is using — and the cost of that is bounded:
/// the entry expires and the address is learned again.
#[test]
fn a_resolved_entry_is_never_replaced_and_expires_instead() {
    let mut cache = NeighbourCache::new();
    resolved(&mut cache, at(0), GATEWAY, ROUTER_MAC);

    assert_eq!(
        cache.learn(at(1_000), GATEWAY, IMPOSTOR_MAC),
        Learned::AlreadyResolved
    );
    assert_eq!(
        cache.resolve(at(1_000), GATEWAY),
        Resolution::Known(ROUTER_MAC),
        "a second answer re-bound a live next hop"
    );
    assert_eq!(cache.counters().rebinding_refused, 1);

    // One nanosecond short of the lifetime the entry still stands.
    let almost = ENTRY_LIFETIME.as_nanos() - 1;
    assert_eq!(
        cache.resolve(at(almost), GATEWAY),
        Resolution::Known(ROUTER_MAC)
    );
    assert_eq!(cache.counters().expired, 0);

    // And at it the entry is gone, so the address is asked about again — which is
    // what bounds the cost of immutability to one lifetime.
    assert_eq!(
        cache.resolve(at(ENTRY_LIFETIME.as_nanos()), GATEWAY),
        Resolution::Ask
    );
    assert_eq!(cache.counters().expired, 1);
    assert_eq!(
        cache.learn(at(ENTRY_LIFETIME.as_nanos()), GATEWAY, IMPOSTOR_MAC),
        Learned::Resolved,
        "an expired address must be learnable again"
    );
}

/// A hardware address no frame may be addressed to is refused before anything
/// else is considered: a broadcast or multicast entry would turn one outbound
/// segment into a frame every station on the link receives.
#[test]
fn a_reply_naming_a_hardware_address_no_frame_may_go_to_is_refused() {
    let mut cache = NeighbourCache::new();
    assert_eq!(cache.resolve(at(0), GATEWAY), Resolution::Ask);
    for mac in [
        MacAddress::BROADCAST,
        MacAddress([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]),
    ] {
        assert_eq!(cache.learn(at(0), GATEWAY, mac), Learned::NotUnicast);
    }
    assert_eq!(cache.counters().not_unicast, 2);
    assert_eq!(
        cache.resolve(at(0), GATEWAY),
        Resolution::Waiting,
        "a refused reply advanced the resolution"
    );
    assert_eq!(cache.learn(at(0), GATEWAY, ROUTER_MAC), Learned::Resolved);
}

/// The table is a fixed array, and a next hop it has no room for is *reported*
/// rather than made room for: evicting a live entry would let a new resolution
/// take the appliance's current next hop away from it.
#[test]
fn a_full_table_refuses_a_new_neighbour_and_recovers_when_one_expires() {
    let mut cache = NeighbourCache::new();
    for index in 0..NEIGHBOURS {
        // Lossless: `NEIGHBOURS` is far below 256.
        let address = Ipv4Address::from_octets([10, 0, 2, 10 + index as u8]);
        let mac = MacAddress([0x52, 0x54, 0x00, 0x00, 0x02, index as u8]);
        resolved(&mut cache, at(0), address, mac);
    }
    assert_eq!(cache.held(), NEIGHBOURS);

    assert_eq!(cache.resolve(at(1_000), GATEWAY), Resolution::NoRoom);
    assert_eq!(cache.counters().no_room, 1);
    assert_eq!(cache.held(), NEIGHBOURS, "a refusal evicted an entry");

    // Every entry's lifetime has run out, so the table recovers on its own.
    assert_eq!(
        cache.resolve(at(ENTRY_LIFETIME.as_nanos()), GATEWAY),
        Resolution::Ask
    );
    assert_eq!(cache.counters().expired, NEIGHBOURS as u64);
}

/// A caller's clock is the caller's, and a reading that goes backwards must not
/// be read as an enormous elapsed span: an entry dropped by a backwards reading
/// would be dropped by a clock rather than by time passing.
#[test]
fn a_clock_that_goes_backwards_neither_expires_an_entry_nor_re_sends_a_request() {
    let mut cache = NeighbourCache::new();
    resolved(
        &mut cache,
        at(ENTRY_LIFETIME.as_nanos() * 2),
        GATEWAY,
        ROUTER_MAC,
    );
    assert_eq!(cache.resolve(at(0), GATEWAY), Resolution::Known(ROUTER_MAC));
    assert_eq!(cache.counters().expired, 0);

    let other = Ipv4Address::from_octets([10, 0, 2, 3]);
    assert_eq!(
        cache.resolve(at(ENTRY_LIFETIME.as_nanos() * 2), other),
        Resolution::Ask
    );
    assert_eq!(cache.resolve(at(0), other), Resolution::Waiting);
    assert_eq!(cache.counters().requested, 2);
}

#[test]
fn the_refusal_total_spans_every_refusal_and_nothing_else() {
    let counters = NeighbourCounters {
        requested: 1_000,
        learned: 1_000,
        unsolicited: 1,
        rebinding_refused: 2,
        not_unicast: 4,
        expired: 1_000,
        abandoned: 1_000,
        no_room: 1_000,
    };
    assert_eq!(counters.refused(), 7);
    assert_eq!(NeighbourCounters::default().refused(), 0);
    let mut count = u64::MAX;
    NeighbourCounters::bump(&mut count);
    assert_eq!(count, u64::MAX);
}

proptest! {
    /// Whatever a peer replies with, at whatever instant, an entry is only ever
    /// one this end asked about: no sequence of replies places a hardware address
    /// for an address no resolution is running for, and the table never exceeds
    /// its capacity. This is the poisoning invariant, and a bare no-panic run
    /// would not see it.
    #[test]
    fn no_stream_of_replies_ever_places_an_unasked_entry(
        replies in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u16>()), 0..64),
    ) {
        let mut cache = NeighbourCache::new();
        // The one address this end is resolving. Everything else in the stream is
        // an address it never asked about.
        prop_assert_eq!(cache.resolve(at(0), GATEWAY), Resolution::Ask);
        for (host, mac_tail, span) in &replies {
            let address = Ipv4Address::from_octets([10, 0, 2, *host]);
            let mac = MacAddress([0x52, 0x54, 0x00, 0x00, 0x03, *mac_tail]);
            let now = at(u64::from(*span) * 1_000_000);
            let learned = cache.learn(now, address, mac);
            if learned == Learned::Resolved {
                prop_assert_eq!(
                    address, GATEWAY,
                    "an address nothing asked about became an entry"
                );
            }
            prop_assert!(cache.held() <= NEIGHBOURS);
        }
        // And the only address that can be known is the one asked about.
        for host in 0..=255u8 {
            let address = Ipv4Address::from_octets([10, 0, 2, host]);
            let now = at(0);
            if let Resolution::Known(_) = cache.resolve(now, address) {
                prop_assert_eq!(address, GATEWAY);
            }
        }
    }

    /// Every resolution ends. Whatever instants a caller polls at, a next hop that
    /// answers nothing reaches `Unreachable` and gives its slot back — so a table
    /// cannot be left holding a resolution that neither completes nor fails.
    #[test]
    fn a_resolution_that_is_never_answered_always_ends(
        polls in prop::collection::vec(0u64..5_000, 0..32),
    ) {
        let mut cache = NeighbourCache::new();
        let mut elapsed = 0u64;
        prop_assert_eq!(cache.resolve(at(0), GATEWAY), Resolution::Ask);
        for step in &polls {
            elapsed = elapsed.saturating_add(*step * 1_000_000);
            let resolution = cache.resolve(at(elapsed), GATEWAY);
            prop_assert!(
                matches!(
                    resolution,
                    Resolution::Ask | Resolution::Waiting | Resolution::Unreachable
                ),
                "an unanswered resolution reported {resolution:?}"
            );
            // Work is bounded by the number of calls: no single poll composes more
            // than one request, whatever instant it names.
            prop_assert!(cache.counters().requested <= polls.len() as u64 + 1);
        }
        // Driven on past every deadline, the resolution ends — and it ends by
        // being reported rather than by the harness giving up.
        let mut settled = false;
        for _ in 0..=MAX_REQUESTS + 1 {
            elapsed = elapsed.saturating_add(REQUEST_TIMEOUT.as_nanos());
            match cache.resolve(at(elapsed), GATEWAY) {
                Resolution::Unreachable => {
                    settled = true;
                    break;
                }
                Resolution::Ask | Resolution::Waiting => {}
                other => prop_assert!(false, "an unanswered resolution reported {other:?}"),
            }
        }
        prop_assert!(settled, "the resolution did not settle");
        prop_assert_eq!(cache.held(), 0, "an abandoned resolution held its slot");
    }
}
