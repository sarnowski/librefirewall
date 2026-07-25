#![no_main]

//! Persistent fuzz target for the inter-PD pool-ownership protocol. The input
//! drives arbitrary peer returns, forged cursors, and scribbled slots through
//! `alloc`/`lend`/`reclaim` and the forwarding stage; the harness asserts work
//! stays bounded, the owner set is conserved, and no address handed out falls
//! outside the pool.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::pipeline::pipeline_harness(data);
});
