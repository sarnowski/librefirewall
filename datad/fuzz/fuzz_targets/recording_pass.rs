#![no_main]

//! Persistent fuzz target for the recorder's pass, driven by all three of its
//! adversaries at once: a forwarder publishing arbitrary annotations and
//! payloads into the tap, a management domain demanding arbitrary offsets of
//! either recording, and a medium that refuses submits, fails transfers and
//! answers jobs nothing is waiting on. The harness asserts containment and
//! sector discipline on every transfer, the pass's own bounds on every step,
//! and that no drained record and no demand is silently lost.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::recording::recording_pass(data);
});
