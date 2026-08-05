#![no_main]

//! Persistent fuzz target for the endpoint's neighbour cache: the one structure
//! in the endpoint a peer writes into. The input is a stream of ARP replies and
//! polls at arbitrary instants; the harness asserts that only a reply this end
//! asked for is ever learned, that a resolved entry is never re-bound, and that
//! the table and the requests it composes stay bounded.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::neighbour::neighbour_cache_harness(data);
});
