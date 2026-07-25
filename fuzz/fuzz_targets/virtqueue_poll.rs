#![no_main]

//! Persistent fuzz target for the split-virtqueue reap path. The fuzzer input
//! drives how many receive descriptors are posted and supplies the untrusted
//! device (used-ring) bytes; the harness asserts `poll`/`recycle` never panic,
//! terminate, and never hand out an out-of-range or double-owned descriptor.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::virtqueue_poll_harness(data);
});
