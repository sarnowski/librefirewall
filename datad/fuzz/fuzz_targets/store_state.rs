#![no_main]

//! Persistent fuzz target for the appliance's own state record, read back off
//! the store medium. Every byte is a physical attacker's — a fresh disk, a
//! mis-addressed sector, a previous deployment's record, or a whole store
//! composed offline with the decoder's source in hand — so the harness asserts
//! that a decode either refuses or yields a state that survives its own
//! re-encoding, and that the identity behind an accepted record is held to
//! itself rather than believed.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::store_state::store_state_harness(data);
});
