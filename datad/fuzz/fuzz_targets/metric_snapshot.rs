#![no_main]

//! Persistent fuzz target for the metric-reading codec: arbitrary bytes out of a
//! recording, and arbitrary counters into one. The harness asserts totality,
//! that padding is never read as a reading, that a foreign catalogue yields no
//! values at all, and containment of every write — not merely the absence of a
//! panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::metric_snapshot::metric_snapshot_harness(data);
});
