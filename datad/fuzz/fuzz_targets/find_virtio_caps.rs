#![no_main]

//! Persistent fuzz target for the virtio PCI capability walk and the bring-up
//! chain that consumes it. The input is a device-controlled 4 KiB PCI
//! configuration space plus the BAR window the driver maps over it; the harness
//! asserts the bounds predicates are total and monotone, that the typed BAR
//! index boundary holds, and that `identify` really establishes the
//! precondition `PlacedBar::map`'s safety comment names.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::virtio_pci::find_virtio_caps_harness(data);
});
