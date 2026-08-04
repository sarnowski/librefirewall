#![cfg_attr(not(test), no_std)]

//! The certificates and certificate signing requests the management plane
//! runs on, written to the profile the two components share.
//!
//! Everything here emits DER; nothing here reads it. That asymmetry is the
//! design and not an omission: the appliance mints its own identity and hands
//! it upward, and the only party that reads a certificate on the appliance is
//! the adopted chain validator, which is a proven parser and not one written
//! here.
//!
//! # Why first-party, when a certificate generator exists
//!
//! `rcgen` is the rustls family's generator and was the intended choice. It
//! cannot be used: its ASN.1 back end is pulled in with that crate's `std`
//! feature unconditionally, and there is no feature combination that drops it
//! — so it does not build for a target with no operating system, whatever
//! signing back end it is driven with. What is written here instead is the
//! four DER structures the profile fixes, which are small, fully specified,
//! and carry no algorithm of their own: every signature over them comes from
//! the adopted cryptography.
//!
//! # Adversary
//!
//! None reaches this crate today. Every value it encodes is one the appliance
//! minted — its own key, its own device identifier, a window from its own
//! clock — and the bytes it produces are handed to a signer and to a chain
//! validator, not parsed back. It is held to the standard for an
//! external-input path regardless: every length is bounded, every refusal is
//! typed, and nothing indexes.

mod der;
mod profile;
mod time;

#[cfg(test)]
mod tests;

pub use der::{DerError, Writer};
pub use profile::{
    Certificate, CertificateKind, DEVICE_ID_LEN, DeviceId, FINGERPRINT_LEN, MAX_CERTIFICATE_LEN,
    MAX_CSR_LEN, Profile, ProfileError, SPKI_LEN, Serial, Validity, fingerprint_hex, spki,
    spki_fingerprint, write_certificate, write_csr,
};
pub use time::Utc;
