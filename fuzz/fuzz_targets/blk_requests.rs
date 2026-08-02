#![no_main]

//! Persistent fuzz target for the virtio-blk request state machine and the
//! staging window under it. The input drives the driver's `submit`/`poll` calls
//! and a device that owns every byte of the shared DMA region; the harness
//! asserts slot conservation, range acceptance, completion attribution and the
//! reported byte count against an independent model, so a forged, replayed or
//! over-reported completion that is *accepted* fails as loudly as a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::blk::blk_requests_harness(data);
});
