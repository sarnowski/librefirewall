#![no_main]

//! Persistent fuzz target for the packet-buffer ownership ledger, the trust
//! boundary a byzantine peer's buffer returns cross. The input drives arbitrary
//! `u32` indices in arbitrary order — duplicates, forged values, and stale
//! tokens included; the harness asserts every outcome against a model and that
//! the pool's indices are neither invented, lost, nor free twice.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::free_list::free_list_harness(data);
});
