#![no_main]

//! Persistent fuzz target for the store domain's install path: the staged
//! region, the length a peer claims about it, the whole package contract read
//! again, and the one signature this appliance verifies for itself. The input is
//! a four-byte stated length followed by the region, so a claim past what was
//! staged is an ordinary input rather than something the harness cannot express.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::onboarding_install::onboarding_install_harness(data);
});
