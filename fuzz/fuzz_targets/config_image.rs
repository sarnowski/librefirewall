#![no_main]

//! Persistent fuzz target for the configuration handover image, the region a
//! byzantine peer protection domain fills. The input is the region's bytes laid
//! over the ABI unreduced — counts past capacity, `enabled` bytes that are no
//! boolean, unknown ports, over-long prefixes, MACs that are not unicast — and
//! the harness asserts every outcome against an independent restatement of the
//! ABI's own rules, that the entries are bounded by capacity rather than by the
//! writer's count, and that the slots past the counts are never read.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::handover::handover_harness(data);
});
