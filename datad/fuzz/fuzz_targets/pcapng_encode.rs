#![no_main]

//! Persistent fuzz target for the pcapng block encoders. Their arguments are
//! first-party values, but two of the numbers among them are not: a frame's
//! length on the wire and an annotation's bytes reach the encoder from the
//! network and from a peer protection domain, and both become a length field.
//! The harness surrounds every buffer with guard bytes, holds each `*_len`
//! against the write it predicts, and walks the blocks it produced by their
//! own lengths from the front to exactly the end.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::pcapng::pcapng_encode_harness(data);
});
