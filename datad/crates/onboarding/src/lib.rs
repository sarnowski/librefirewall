#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! The read-only half of onboarding: the page an administrator lands on and the
//! certificate signing request they carry away, served over the TLS session the
//! onboarding port terminates.
//!
//! It is one step of a longer flow and stops exactly where that step does. The
//! administrator verifies the appliance's fingerprint out of band against the
//! console, fetches these two things, and takes the request to the management
//! application; what comes back is a configuration package, and **this build
//! does not take one**. The page says so rather than offering a control that
//! would fail.
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

#[cfg(test)]
mod tests;

// The instant type this crate's own surface takes, re-exported because it is in
// that signature: a caller that could name `Onboarding::take` and not the
// argument it takes would have to reach past this crate for it.
pub use lfw_clock::Monotonic;
pub use limiter::{BASE_INTERVAL, BURST, Limiter, MAX_BACKOFF_SHIFT, Throttle};
pub use page::{MAX_PAGE_LEN, PageDoesNotFit, write_page};
pub use surface::{
    Decision, Identity, MAX_BODY_LEN, MAX_RESPONSE_LEN, Onboarding, REQUEST_CAPACITY,
    REQUEST_RECORDS,
};
