#![no_main]

//! Persistent fuzz target for the driver's steady-state paths under a hostile
//! device and a byzantine forwarder at once. The harness asserts the driver's
//! own invariant faults stay at zero, that no DMA target leaves the pool, and
//! that no buffer reaches the forwarder twice without a return.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::driver::driver_paths_harness(data);
});
