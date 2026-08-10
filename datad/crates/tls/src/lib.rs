#![cfg_attr(not(test), no_std)]

//! TLS 1.3 for the management channel: the crypto provider that binds this
//! appliance's cryptography into the adopted TLS library, the bounded arena
//! that library needs, the session that proves both, and the two incremental
//! ends the appliance meets a management plane on.
//!
//! # Three shapes of one stack, and why all three are here
//!
//! [`prove_session`] runs both halves of one handshake in a single call over a
//! transport that is two buffers, which is what lets a boot settle the whole
//! stack against itself before there is a network.
//!
//! [`OnboardingServer`] and [`ChannelClient`] are the other shape: one half,
//! driven a delivery at a time, against a peer whose every byte and every pause
//! is its own. They are the two halves of one appliance's life — the server is
//! what an administrator reaches before the appliance is owned, the client is
//! what the appliance dials once it is, and the two never run at once because
//! the onboarding surface shuts for good at the moment ownership is taken.
//! Both terminate the record layer and nothing above it — plaintext is offered
//! to its owner and taken from its owner — and both answer how the handshake
//! ended in a vocabulary with one value per cause.
//!
//! The two vocabularies are separate types rather than one, because the two
//! ends do not fail identically: only the client validates a peer against an
//! anchor somebody delivered to it, and only the server sees the list a peer
//! offered before deciding against it. A single enum would carry each end's
//! unreachable arms, and an unreachable arm on an operator surface is a token
//! nothing can ever explain.
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
mod chain;
mod client;
mod identity;
mod kx;
mod provider;
mod server;
mod session;
mod sign;
mod suite;
mod verify;

#[cfg(test)]
mod tests;

pub use arena::{ArenaExhausted, Bump, MAX_ALIGN};
pub use chain::DeliveredAnchor;
pub use client::{CHANNEL_OUTCOME_RECORDS, ChannelClient, ClientOutcome};
pub use identity::{Identity, IdentityError};
// Two types this crate's public signature carries but does not declare: the
// kind of certificate an identity binds, and the assembled provider a session
// is given. Re-exported so a caller names them from here rather than needing
// the crate each one comes from.
pub use lfw_x509::CertificateKind;
pub use provider::{Clock, provider};
pub use rustls::crypto::CryptoProvider;
pub use server::{
    OFFER_KEPT, OUTCOME_RECORDS, Offered, OnboardingServer, PeerOffer, ServerOutcome,
};
pub use session::{
    Established, HELD_MAX, Negotiated, STEP_RESERVE, ServerKey, SessionError, Turn, prove_session,
};
pub use sign::{EcdsaP256SigningKey, LocalKey, SignOperation, SignRefused};
pub use suite::TLS13_CHACHA20_POLY1305_SHA256;
