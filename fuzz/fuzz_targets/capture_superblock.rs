#![no_main]

//! Persistent fuzz target for the superblock a recording ring reads back off
//! its medium. Every byte is the device's — a fresh disk, a neighbouring
//! sector, the other image's slot, or an extent someone composed offline — so
//! the harness asserts that a decode either refuses or yields a state that
//! round-trips and describes a ring, and never something in between.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::recording::capture_superblock(data);
});
