#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Onboarding as an administrator drives it: the page they land on, the
//! certificate signing request they carry away, and the configuration package
//! they bring back — all over the TLS session the onboarding port terminates.
//!
//! It is the whole of the flow's appliance side and it ends the flow. The
//! administrator verifies the appliance's fingerprint out of band against the
//! console, fetches the first two things, takes the request to the management
//! application, and uploads what comes back. An appliance that accepts one has
//! an owner, and an appliance with an owner serves none of this again — the
//! surface is shut, on this boot and on every one after it.
//!
//! # Where it sits
//!
//! Above `lfw_tls`'s record layer and below nothing: the plaintext a session
//! produces comes in, the plaintext it should send goes out, and the transport
//! underneath is somebody else's problem. That is what makes the whole surface
//! host-testable against composed bytes — there is no socket, no allocator and
//! no clock of its own in it.
//!
//! Two crates do the parts that are not this one's. `lfw_http` reads the
//! request head, which is fuzzed and total over arbitrary bytes; `lfw_x509`
//! writes and armours the certificate signing request, which happens once at
//! bring-up rather than per request. What is left here is which resources
//! exist, under which method, how often, and what an operator is told when the
//! answer is no.
//!
//! **The package itself is a third crate's, and its bytes never rest here.** A
//! body is handed on segment by segment to the [`Upload`] the caller supplied
//! and is read by whoever that caller hands it to; nothing in this crate holds
//! an archive, parses a member, or knows what one is.
//!
//! # Adversary
//!
//! An **unauthenticated management-plane attacker**. The session that carries
//! these bytes authenticates the *appliance to the administrator* and nobody to
//! the appliance, deliberately — an unonboarded appliance holds no anchor to
//! judge a client against, and physical control of the port is what stands in
//! for it. So every byte reaching this crate is hostile until the flow is over,
//! and the module headers below state what each part does about it.

mod limiter;
mod page;
mod surface;
mod upload;

#[cfg(test)]
mod tests;

// The instant type this crate's own surface takes, re-exported because it is in
// that signature: a caller that could name `Onboarding::take` and not the
// argument it takes would have to reach past this crate for it.
pub use lfw_clock::Monotonic;
pub use limiter::{BASE_INTERVAL, BURST, Limiter, MAX_BACKOFF_SHIFT, Throttle};
pub use page::{MAX_PAGE_LEN, PageDoesNotFit, write_page};
pub use surface::{
    Decision, Identity, MAX_BODY_LEN, MAX_RESPONSE_LEN, MAX_UPLOAD_LEN, Onboarding,
    REQUEST_CAPACITY, REQUEST_RECORDS,
};
pub use upload::{Upload, UploadRefused};
