#![cfg_attr(not(test), no_std)]

//! TLS 1.3 for the management channel: the crypto provider that binds this
//! appliance's cryptography into the adopted TLS library, the bounded arena
//! that library needs, and the session that proves both.
//!
//! # What is adopted and what is written here
//!
//! The protocol is adopted whole. Nothing in this crate parses a handshake
//! message, derives a traffic key, or validates a certificate chain — the
//! library does all of it, and it is not in the trusted computing base either:
//! what it computes is held to published vectors on the shipped image like
//! every other adopted implementation. What is written here is the shape:
//! the hash, the MAC and the key schedule over it, the record-layer AEAD, the
//! hybrid key exchange, the one signature algorithm, and the plumbing that
//! turns a private key into something that signs. That is trait glue, and it
//! is the one part of a TLS stack that cannot be adopted, because it is where
//! a particular set of primitives meets a particular library.
//!
//! # The allocator, which is a necessity and not a feature
//!
//! A proven TLS implementation requires an allocator, so the domain that runs
//! this one has the appliance's only allocator. Every property that makes that
//! acceptable is here: [`Bump`] is bounded, refuses rather than grows, and
//! reports what it was asked for; and [`STEP_RESERVE`] is the headroom a
//! session checks *before* a step, because a failed allocation inside one has
//! no return path in this language. A session that finds itself short refuses
//! and closes, which is a typed answer on a live connection rather than a
//! fault.
//!
//! # Adversary
//!
//! **Untrusted network traffic** and a **management-plane attacker up to and
//! including a compromised management server**. Every byte a peer sends
//! reaches the adopted library through this crate's record layer and key
//! exchange, so the refusals here are the ones that matter: a key share of the
//! wrong length, a public value that forces a shared secret the peer alone
//! chose, an encapsulation key that is not canonically encoded, a signature
//! that does not verify. All are typed, none is a panic, and none tells the
//! peer which of its several possible mistakes it made.
//!
//! The peer being authenticated does not make it trusted: a compromised
//! management server holds a valid certificate, and what bounds it is the
//! arena and the session's own limits rather than the handshake.

extern crate alloc;

mod arena;
mod identity;
mod kx;
mod provider;
mod session;
mod sign;
mod suite;
mod verify;

#[cfg(test)]
mod tests;

pub use arena::{ArenaExhausted, Bump, MAX_ALIGN};
pub use identity::{Identity, IdentityError};
pub use provider::{Clock, provider};
pub use session::{Negotiated, STEP_RESERVE, SessionError, prove_session};
pub use sign::{EcdsaP256SigningKey, LocalKey, SignOperation, SignRefused};
pub use suite::TLS13_CHACHA20_POLY1305_SHA256;
