#![no_main]

//! Persistent fuzz target for the whole configuration submission path: the body
//! a client `POST`s, the region it crosses between two protection domains, the
//! copy the deciding domain takes out of it, the commit, and the answer that
//! comes back. The input is the document, so any real configuration file is a
//! seed and any malformed one is too; the harness asserts that what was decided
//! on is what was submitted, that a refusal changes nothing, and that every
//! answer is one a client can be sent.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::config_submission::config_submission_harness(data);
});
