//! `lfw_ip_endpoint::neighbour` under the adversary that writes into it.
//!
//! # The adversary and the surface
//!
//! The neighbour cache is the one structure in the endpoint a peer **writes
//! into**: every other part of it answers a frame and forgets it, while an entry
//! here outlives the frame that made it and decides where a frame the appliance
//! *originates* is sent. An attacker that could place an entry could redirect the
//! appliance's own outbound traffic, which is the whole of what ARP poisoning is
//! — so what this target attacks is not "does it panic" but "can a reply that
//! answers nothing ever become an entry".
//!
//! # Modelling authority, not politeness
//!
//! Every value crossing the boundary is taken unreduced. The addresses replied
//! for are arbitrary and include the one address the harness is actually
//! resolving, so the *race* a real poisoner runs — answer first, answer again,
//! answer for something else — is reachable rather than filtered out. Hardware
//! addresses include broadcast and multicast, which no correct station would
//! send. And the instant is arbitrary and may move **backwards**: a peer cannot
//! move a real counter, but a cache that assumed monotonicity would be assuming
//! something no type here promises.
//!
//! Nothing filters a shape for being implausible: a reply for an address nobody
//! asked about is exactly what an attacker sends.
//!
//! # What is asserted
//!
//! * **Only a solicited reply is ever learned.** The harness resolves exactly one
//!   address, and any entry the cache reports as known must be that one — whatever
//!   stream of replies arrived, in whatever order, at whatever instants. This is
//!   the poisoning invariant.
//! * **A resolved entry is never re-bound.** Once the resolved address is known,
//!   the hardware address it is known at never changes for the rest of the entry's
//!   life, so no later answer wins a race against the first.
//! * **State is bounded.** The table never exceeds its capacity, whatever stream
//!   of distinct addresses arrives.
//! * **Work is bounded by the caller.** No single call composes more than one
//!   request, so a peer cannot make one poll flood the link.
//! * **Every decision is counted.** A reply is learned or refused, and the totals
//!   move by exactly one per reply — the counters being the only evidence a port
//!   is refusing anything.

use arbitrary::Unstructured;
use lfw_clock::{Calibration, Monotonic, Ticks};
use lfw_ip_endpoint::neighbour::{
    Learned, NEIGHBOURS, NeighbourCache, REQUEST_TIMEOUT, Resolution,
};
use net_headers::{Ipv4Address, MacAddress};
use std::num::NonZeroU64;

use crate::{MAX_OPERATIONS, any_u16, any_u32, next_op};

/// The one address this harness resolves, and so the only one any entry may ever
/// be known at.
const RESOLVING: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

/// Drive an operation stream of replies and polls against one cache.
pub fn neighbour_cache_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let mut cache = NeighbourCache::new();
    // The resolution under attack is begun here rather than by the input, so
    // every entry in the stream is either its answer or an attempt to place one
    // beside it.
    let opened = cache.resolve(instant(0), RESOLVING);
    assert_eq!(opened, Resolution::Ask, "a fresh cache refused to ask");

    // The hardware address the resolved entry was first learned at. Once set it
    // must never change: a resolved entry is immutable for its lifetime, which is
    // what keeps a later answer from winning a race against the first.
    let mut bound: Option<MacAddress> = None;
    let mut operations = 0usize;
    while let Some(op) = next_op(&mut unstructured) {
        operations += 1;
        let now = instant(any_u32(&mut unstructured));
        let requests_before = cache.counters().requested;
        match op % 3 {
            0 => {
                // A reply, for an arbitrary address at an arbitrary hardware
                // address — including the address being resolved, which is the
                // race a real poisoner runs.
                let address = any_address(&mut unstructured);
                let mac = any_mac(&mut unstructured);
                let counters = cache.counters();
                let refused = counters.refused();
                let learned = counters.learned;
                let outcome = cache.learn(now, address, mac);
                let after = cache.counters();
                match outcome {
                    Learned::Resolved => {
                        assert_eq!(
                            address, RESOLVING,
                            "an address nothing asked about became an entry"
                        );
                        assert_eq!(after.learned, learned + 1);
                    }
                    Learned::Unsolicited | Learned::AlreadyResolved | Learned::NotUnicast => {
                        assert_eq!(
                            after.refused(),
                            refused + 1,
                            "a refused reply went uncounted"
                        );
                    }
                }
            }
            1 => {
                // A poll of the address under attack, which is where an entry
                // becomes visible and where a request is composed.
                match cache.resolve(now, RESOLVING) {
                    Resolution::Known(mac) => match bound {
                        Some(first) => assert_eq!(
                            mac, first,
                            "a resolved entry was re-bound to another hardware address"
                        ),
                        None => bound = Some(mac),
                    },
                    // The entry is gone, so a later answer may legitimately bind
                    // it again: that is what the lifetime and the give-up are for.
                    Resolution::Unreachable => bound = None,
                    Resolution::Ask | Resolution::Waiting | Resolution::NoRoom => {}
                }
            }
            _ => {
                // A poll of some other address, which is how the table is driven
                // to its edge by this end's own requests.
                let address = any_address(&mut unstructured);
                let resolution = cache.resolve(now, address);
                if let Resolution::Known(_) = resolution {
                    assert_eq!(
                        address, RESOLVING,
                        "an address nothing asked about became an entry"
                    );
                }
            }
        }
        assert!(
            cache.held() <= NEIGHBOURS,
            "the neighbour table exceeded its capacity"
        );
        assert!(
            cache.counters().requested <= requests_before + 1,
            "one call composed more than one request"
        );
        if operations >= MAX_OPERATIONS {
            break;
        }
    }

    // And the closing statement the whole stream is judged by: whatever it did,
    // the only address that can be known is the one this end asked about.
    for host in 0..=255u8 {
        let address = Ipv4Address::from_octets([10, 0, 2, host]);
        if let Resolution::Known(_) = cache.resolve(instant(0), address) {
            assert_eq!(address, RESOLVING, "an unasked address ended up resolved");
        }
    }
}

/// An address out of a small set, so a stream both answers the resolution under
/// attack and floods the table with addresses beside it.
fn any_address(unstructured: &mut Unstructured<'_>) -> Ipv4Address {
    // Lossless by the truncation: the point is a small, colliding set.
    Ipv4Address::from_octets([10, 0, 2, any_u16(unstructured) as u8])
}

/// A hardware address, unreduced: broadcast and multicast included, because no
/// correct station sends one and the cache's refusal of them is the property.
fn any_mac(unstructured: &mut Unstructured<'_>) -> MacAddress {
    let first = any_u16(unstructured) as u8;
    let last = any_u16(unstructured) as u8;
    MacAddress([first, 0x54, 0x00, 0x00, 0x04, last])
}

/// An instant, which may be anywhere — including behind a previous one. A peer
/// cannot move a real counter; a cache that assumed it could not is assuming what
/// no type promises.
fn instant(nanos: u32) -> Monotonic {
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    // Scaled so a stream reaches both sides of the request timeout rather than
    // living inside one of them.
    let step = REQUEST_TIMEOUT.as_nanos() / 4;
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(u64::from(nanos).saturating_mul(step.max(1))))
}
