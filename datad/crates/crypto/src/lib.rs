#![cfg_attr(not(test), no_std)]

//! The appliance's only door to cryptography: SHA-256, HMAC-SHA-256,
//! HKDF-SHA-256, the two AEADs, the deterministic random bit generator that
//! keys them, and the three asymmetric primitives a mutually-authenticated
//! session needs — ECDSA over P-256, X25519, and ML-KEM-768 — over adopted
//! implementations, never a first-party one.
//!
//! Nothing here computes a cryptographic primitive. Every algorithm is a
//! pinned third-party crate, and what this crate adds is the shape the
//! appliance needs on top of it: fixed-size key and nonce types instead of
//! runtime length checks, a typed refusal for every way a call can be
//! answered no, in-place work on caller-owned buffers so no allocator is
//! reached for, and one proof runner both the host suite and the cryptography
//! protection domain drive over the same published vectors.
//!
//! # What is exposed, and what deliberately is not
//!
//! SHA-384 is absent: the management channel's one cipher suite is
//! `TLS_CHACHA20_POLY1305_SHA256` and its certificates are ECDSA P-256 with
//! SHA-256, so nothing on any planned path derives from a wider hash.
//! AES-128-GCM is absent for the same reason — the channel never negotiates
//! it, and the inspected path that would is not built. AES-256-GCM *is* here
//! though the channel does not use it either, because it is the primitive the
//! hardware baseline exists for: it is what proves, on the shipped image, that
//! the AES-NI and carry-less-multiply backends are the ones running.
//!
//! Post-quantum *signatures* are absent deliberately and not for want of a
//! crate: the certificate ecosystem the appliance's identity has to interope-
//! rate with has not moved, so ML-KEM is here for key exchange and nothing
//! signs with anything but P-256.
//!
//! # Which ML-KEM, and why not the formally verified one
//!
//! The post-quantum primitive is the RustCrypto `ml-kem` crate and not
//! `libcrux-ml-kem`, whose formal verification would have been the stronger
//! assurance. libcrux was investigated and builds cleanly for this target;
//! what it costs is the dependency policy. Its transitive `libcrux-traits`
//! takes an unconditional dependency on a random-number crate a major version
//! ahead of the one the elliptic-curve crates here use, which puts two
//! versions of it in the graph — a duplicate the policy denies — and it pulls
//! a libc binding into an appliance that has no libc. The crate adopted
//! instead is audited and final against its standard, and stands on the same
//! terms as every other crate here: pinned, and proved on the shipped image
//! against the published known-answer tests rather than trusted.
//!
//! # Adversary
//!
//! A **compromised parser or inspection domain**, and through the eventual
//! transport, **untrusted network traffic**: a caller here may be handing over
//! bytes an attacker chose, and the tag on them may be a forgery. So no input
//! is trusted for its length or its content. Lengths that are part of an
//! algorithm's contract are types rather than checks — a key is `[u8; 32]`, a
//! nonce `[u8; 12]` — and the lengths that remain runtime are bounded and
//! refused by [`CryptoError`] rather than clamped, truncated or panicked on.
//! An authentication failure is [`CryptoError::NotAuthentic`] and nothing
//! else: it never yields a plaintext, never a partial one, and never a
//! distinguishable timing, the adopted crates comparing tags in constant time.
//!
//! No byte of key material reaches an error, a `Debug` rendering or any
//! observable surface. That is why nothing here derives `Debug` over a key.
//!
//! # Why the hardware `unsafe` is not here
//!
//! Not one `unsafe` block, and not one CPUID query. A crate that reached for a
//! hardware instruction could not be host-tested, so that authority lives in
//! the protection domain instead — the same split the transport crate was
//! built under. What decides the backend here is the *target specification*
//! the domain compiles this crate with: with AES-NI and carry-less multiply
//! enabled at compile time, the adopted crates' runtime detection folds to a
//! constant and only the accelerated code is emitted. The portable fallback is
//! not slower on the shipped image; it is absent from it.

mod aead;
mod drbg;
mod ecdsa;
mod entropy;
mod error;
mod hash;
mod kdf;
mod mac;
mod mlkem;
mod proof;
pub mod vectors;
mod x25519;

#[cfg(test)]
mod tests;

pub use aead::{Aes256Gcm, ChaCha20Poly1305, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use drbg::{Drbg, RESEED_INTERVAL, SEED_LEN};
pub use ecdsa::{
    P256_MAX_SIGNATURE_LEN, P256_PUBLIC_LEN, P256_SECRET_LEN, P256SecretKey, p256_verify,
};
pub use entropy::Entropy;
pub use error::CryptoError;
pub use hash::{DIGEST_LEN, Sha256, sha256};
pub use kdf::{MAX_DERIVED_LEN, Prk, hkdf_expand, hkdf_extract};
pub use mac::{HmacContext, HmacKey, MAC_LEN, hmac_sha256, hmac_sha256_verify};
pub use mlkem::{
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_DECAPSULATION_KEY_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN,
    ML_KEM_768_SEED_LEN, ML_KEM_768_SHARED_SECRET_LEN, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey,
};
pub use proof::{
    VectorFailure, prove_aes_256_gcm, prove_chacha20, prove_chacha20_poly1305, prove_drbg,
    prove_ecdsa_p256, prove_hkdf_sha256, prove_hmac_sha256, prove_ml_kem_768, prove_sha256,
    prove_x25519,
};
pub use x25519::{X25519_LEN, X25519Secret};
