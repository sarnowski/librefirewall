#![no_main]

//! Persistent fuzz target for the onboarding TLS server. Every byte is an
//! unauthenticated management-plane attacker's, and so is where the deliveries
//! fall — so the harness asserts that the answer stays inside the buffer it was
//! given, that neither direction outgrows its bound, that no record reaches the
//! protocol above an unestablished handshake, and that the outcome settles once
//! and a finished session stays finished.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::onboarding_tls::onboarding_tls_harness(data);
});
