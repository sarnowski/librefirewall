#![no_main]

//! Persistent fuzz target for one recording sink: the tap's annotations and
//! frame bytes, encoded into a staging buffer and placed as whole sectors of a
//! small extent. The annotations are a byzantine forwarder's and the frames are
//! the network's, and the *ordering* of the sink's four obligations — record,
//! seal, close, begin — is the caller's, so every interleaving of them is
//! generated. The harness asserts that no placement leaves the extent or lands
//! in the superblock's segment, that no write leaves the staging buffer, and
//! that no snapshot promises a byte the device has not been handed.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::recording::recorder_sink(data);
});
