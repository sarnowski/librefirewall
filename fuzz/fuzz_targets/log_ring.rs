#![no_main]

//! Persistent fuzz target for the two regions a `wire` log ring is laid across,
//! each of which a byzantine peer protection domain owns one side of. The input
//! drives both halves of the ring against a peer that forges either published
//! cursor and the drop count, overwrites any slot with 192 unreduced bytes, and
//! rewrites a single atomic of a slot to tear a record in two — including
//! between two steps of one live drain. The harness asserts each side reads and
//! writes only its own private position, that a delivered record is exactly
//! what some write put in that slot, that a torn or twice-delivered record
//! always has an adversary action to account for it, and that a drain is
//! bounded by the ring's own capacity constant and never by a cursor the peer
//! publishes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::log_ring::log_ring_harness(data);
});
