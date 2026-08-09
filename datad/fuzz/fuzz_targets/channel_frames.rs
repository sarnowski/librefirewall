//! libFuzzer entry point for the management channel's framing.
//!
//! The body lives in the harness library so the identical code path is driven
//! both here and by the seed-corpus smoke tests, which is what keeps a target
//! the sandbox cannot execute from going unexercised.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::channel_frames::channel_frames_harness(data);
});
