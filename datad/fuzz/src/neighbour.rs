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
//! * **Only a solicited reply is ever learned.** Any entry the cache reports as
//!   known must be for an address *this end asked about* — whatever stream of
//!   replies arrived, in whatever order, at whatever instants. This is the
//!   poisoning invariant, and solicitation is what it is about: this end asks
//!   about more than one address, because a poll of any address begins a
//!   resolution for it, so which addresses were asked about is tracked rather
//!   than assumed to be the single one under attack.
//! * **A resolved entry is never re-bound.** For as long as the cache keeps
//!   reporting the address under attack as known, the hardware address it is
//!   known at never changes, so no later answer wins a race against the first.
//!   An outcome other than known says no entry stands — it expired, was given up,
//!   or never got a slot — and the next answer then binds afresh, which is not a
//!   re-binding and is what bounds the cost of that immutability to one lifetime.
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

/// The address whose resolution is under attack: the one this end asks about
/// before reading a byte of input, so every reply in the stream is either its
/// answer or an attempt to place an entry beside it.
const RESOLVING: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

/// Which addresses this end has asked about, indexed by the one octet
/// [`any_address`] varies.
///
/// The poisoning invariant is about *solicitation*, and this end solicits more
/// than the address under attack: polling any address begins a resolution for
/// it, so a reply answering that poll is solicited and learning it is correct.
/// Asserting instead that only [`RESOLVING`] may ever be learned would be
/// asserting something this harness's own polls disprove.
type Asked = [bool; 256];

/// Drive an operation stream of replies and polls against one cache.
pub fn neighbour_cache_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let mut cache = NeighbourCache::new();
    let mut asked: Asked = [false; 256];
    // The resolution under attack is begun here rather than by the input, so
    // every entry in the stream is either its answer or an attempt to place one
    // beside it.
    let opened = cache.resolve(instant(0), RESOLVING);
    assert_eq!(opened, Resolution::Ask, "a fresh cache refused to ask");
    record(&mut asked, RESOLVING, opened);

    // The hardware address the entry under attack is currently bound at, held
    // only for as long as the cache keeps reporting it known — see `observe`.
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
                        assert!(
                            asked[host(address)],
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
                let resolution = cache.resolve(now, RESOLVING);
                observe(resolution, &mut bound);
                record(&mut asked, RESOLVING, resolution);
            }
            _ => {
                // A poll of some other address, which is how the table is driven
                // to its edge by this end's own requests — and, when the input
                // names the address under attack, how its resolution is begun
                // again after one ended.
                let address = any_address(&mut unstructured);
                let resolution = cache.resolve(now, address);
                if let Resolution::Known(_) = resolution {
                    assert!(
                        asked[host(address)],
                        "an address nothing asked about became an entry"
                    );
                }
                if address == RESOLVING {
                    observe(resolution, &mut bound);
                }
                record(&mut asked, address, resolution);
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
    // the only address that can be known is one this end asked about. The polls
    // below begin resolutions of their own, which is why they are judged against
    // the set as the stream left it and never extend it.
    for octet in 0..=255u8 {
        let address = Ipv4Address::from_octets([10, 0, 2, octet]);
        if let Resolution::Known(_) = cache.resolve(instant(0), address) {
            assert!(
                asked[usize::from(octet)],
                "an unasked address ended up resolved"
            );
        }
    }
}

/// Fold one resolution of the address under attack into the binding this harness
/// holds the cache to.
///
/// `Known` is the only outcome that says an entry stands. Every other one says
/// none does right now — it expired, every request went unanswered, or the table
/// had no slot to give — so the next answer binds afresh rather than re-binding a
/// live entry, and holding it to the previous hardware address would be asserting
/// an immutability the cache never claimed beyond one entry's life.
fn observe(resolution: Resolution, bound: &mut Option<MacAddress>) {
    match resolution {
        Resolution::Known(mac) => match *bound {
            Some(first) => assert_eq!(
                mac, first,
                "a resolved entry was re-bound to another hardware address"
            ),
            None => *bound = Some(mac),
        },
        Resolution::Ask | Resolution::Waiting | Resolution::Unreachable | Resolution::NoRoom => {
            *bound = None;
        }
    }
}

/// Record what one resolution says about whether this end is asking about an
/// address.
///
/// `Ask`, `Waiting` and `Known` each mean an entry for it exists, so a reply
/// answering it is solicited. `Unreachable` and `NoRoom` mean there is none —
/// given up, or never granted a slot — so a reply would be unsolicited again.
///
/// One case is deliberately not tracked: a *resolved* entry reaching the end of
/// its life makes the address unsolicited without any call reporting it, so the
/// set can name an address the cache no longer asks about. That direction is the
/// safe one — a superset can only miss a defect, never invent one — and the
/// alternative is restating the cache's own expiry arithmetic here, which would
/// make this harness agree with a copy of the code under test.
fn record(asked: &mut Asked, address: Ipv4Address, resolution: Resolution) {
    match resolution {
        Resolution::Ask | Resolution::Waiting | Resolution::Known(_) => {
            asked[host(address)] = true;
        }
        Resolution::Unreachable | Resolution::NoRoom => asked[host(address)] = false,
    }
}

/// The one octet [`any_address`] varies, which is the whole of the address space
/// this harness reaches.
fn host(address: Ipv4Address) -> usize {
    usize::from(address.octets()[3])
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
