#![no_main]

//! Persistent fuzz target for the metric exposition renderer: arbitrary counter
//! values in every shard, rendered into storage of an arbitrary size. The
//! harness asserts containment, refusal-rather-than-truncation, and that no name
//! or label outside the declared catalogue can reach the output — not merely the
//! absence of a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::metrics_render::metrics_render_harness(data);
});
