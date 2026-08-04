#![no_main]

//! Persistent fuzz target for the connection tracker: arbitrary packets at
//! arbitrary instants against a table that already holds an established
//! connection, with ICMP errors quoting that connection interleaved. The harness
//! asserts the boundedness of the table, that admitting a new flow never
//! displaces an assured one, and that every packet is accounted for — not merely
//! the absence of a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::flow::flow_table_harness(data);
});
