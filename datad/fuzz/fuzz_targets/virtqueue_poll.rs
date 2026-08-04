#![no_main]

//! Persistent fuzz target for the split-virtqueue descriptor lifecycle. The
//! input drives the driver's `add`/`poll`/`recycle` calls and a device that
//! owns every byte of the shared region; the harness asserts the full lifecycle
//! against an independent model, so a forged, replayed, or out-of-range
//! completion that is *accepted* fails as loudly as a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::virtqueue::virtqueue_poll_harness(data);
});
