#![no_main]

//! Persistent fuzz target for the management server's request parser:
//! arbitrary bytes cut into arbitrary segments and fed in the way a TCP
//! connection feeds them. The harness asserts that the verdict does not depend
//! on where the segments fall, and that every bound the parser declares holds —
//! not merely the absence of a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::http_request::http_request_harness(data);
});
