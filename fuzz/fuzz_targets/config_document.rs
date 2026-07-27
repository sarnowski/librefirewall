#![no_main]

//! Persistent fuzz target for the configuration document reader and everything
//! that reads a model out of it, the surface the management-plane attacker
//! chooses every byte of. The input is the document itself; the harness asserts
//! reading it is total and bounded, that a rejection points into the document,
//! that an accepted document reads the same way twice, and that the artifacts
//! it builds are accepted by the domain that consumes them.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::document::document_harness(data);
});
