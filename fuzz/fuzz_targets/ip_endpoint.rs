#![no_main]

//! Persistent fuzz target for the addressed management endpoint: the parsers a
//! frame reaches and the reply composed out of it. The input is the frame itself;
//! the harness asserts every reply is contained, addressed to the station that
//! asked, and counted — and that a refusal is attributable to the bytes that
//! caused it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::ip_endpoint::ip_endpoint_harness(data);
});
