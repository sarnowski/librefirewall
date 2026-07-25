#![no_main]

//! Persistent fuzz target for the virtio PCI capability walk. The fuzzer input
//! is interpreted as a device-controlled 4 KiB PCI configuration space; the
//! harness asserts the walk never panics or reads out of bounds and that any
//! successful parse yields a valid BAR index.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::find_virtio_caps_harness(data);
});
