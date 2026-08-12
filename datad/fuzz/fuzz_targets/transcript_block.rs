#![no_main]

//! Persistent fuzz target for the console-transcript ABIs: arbitrary bytes out of
//! a recording, and arbitrary lines through the relay region that carries them to
//! the domain writing the medium. The harness asserts totality, that padding and
//! a metric reading are never read as a transcript, that every line a caller is
//! handed is printable, that a full relay counts a drop and never waits, that a
//! peeked batch releases nothing, and containment of every write.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::transcript_block::transcript_block_harness(data);
});
