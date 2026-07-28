#![no_main]

//! Persistent fuzz target for the log record a byzantine writing domain leaves
//! in a slot of the console's records region, and for the console line a
//! decoded one becomes. The input is the record's bytes laid over the ABI
//! unreduced — kinds that name no event, vocabulary tokens past their
//! cardinality, value tags that name no value, text lengths past their storage,
//! text bytes that are ESC or newline — and the harness asserts every outcome
//! against an independent restatement of the ABI's own rules and their order,
//! that an accepted body carries only the fields its kind names, and that the
//! console line an accepted record renders to is printable ASCII throughout
//! (OBS-5): no control character, no escape sequence, and no newline but the
//! single terminator the console appends.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::log_record::log_record_harness(data);
});
