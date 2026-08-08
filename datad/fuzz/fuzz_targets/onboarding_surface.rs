#![no_main]

//! Persistent fuzz target for the onboarding request surface: the head parsed
//! out of a plaintext stream, the body handed on to an upload as it arrives, and
//! the decision each request settles on. The input is the stream itself plus the
//! cuts the network put in it, because the pacing is half of what this surface
//! faces.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::onboarding_surface::onboarding_surface_harness(data);
});
