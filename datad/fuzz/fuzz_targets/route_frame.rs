#![no_main]

//! Persistent fuzz target for the untrusted-network parser and the forwarding
//! decision above it. The input is the frame itself; the harness asserts the
//! parse is total, a forward verdict is internally consistent with the
//! topology, and the rewrite it authorises conserves everything but the four
//! fields it names.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::frame::frame_routing_harness(data);
});
