#![no_main]

//! Persistent fuzz target for the shared SPSC ring under a peer that owns both
//! published cursors and every slot. The harness asserts each side reads and
//! writes only its own private position — the property that stops a rewound
//! cursor from redelivering a descriptor or overwriting an unread one — and
//! that `drain` never yields past its limit.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::spsc_ring::spsc_ring_harness(data);
});
