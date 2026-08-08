#![no_main]

//! Persistent fuzz target for the onboarding package reader: the tar framing,
//! the armour around the two certificates, the walk that finds the key one
//! binds, the endpoint line, and the configuration reader underneath. The input
//! is the uploaded archive itself, and the harness asserts that nothing is ever
//! yielded unless every rule passed and the injected verifier accepted.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::onboarding_package::onboarding_package_harness(data);
});
