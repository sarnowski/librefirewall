#![no_main]

//! Persistent fuzz target for the appliance's TCP: arbitrary segments at
//! arbitrary instants against a listening stack and an established one, with a
//! caller's own sends, closes and retransmissions interleaved. The harness
//! asserts the boundedness of the table, the containment of every answer, and the
//! unpredictability of an initial sequence number — not merely the absence of a
//! panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::tcp::tcp_segments_harness(data);
});
