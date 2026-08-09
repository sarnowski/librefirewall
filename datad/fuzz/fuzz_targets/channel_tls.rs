#![no_main]

//! Persistent fuzz target for the management channel's TLS client. Every byte
//! is a management server's — one that may be compromised — and so is where the
//! deliveries fall, and so are the anchor and the certificate a package
//! installed. The harness asserts that the answer stays inside the buffer it
//! was given, that neither direction outgrows its bound, that no record reaches
//! the protocol above an unconfirmed handshake, that the outcome settles once
//! and a finished session stays finished, and that a peer's fatal alert is
//! never displaced by an established channel.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    librefirewall_fuzz::channel_tls::channel_tls_harness(data);
});
