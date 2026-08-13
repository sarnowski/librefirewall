#![no_main]

//! Persistent fuzz target for the management channel's stepped configuration
//! transaction: stage, commit, confirm and revert in whatever order a compromised
//! management server chooses. The harness and what it asserts are
//! `librefirewall_fuzz::config_transaction`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::config_transaction::config_transaction_harness(data);
});
