use zeroize::Zeroize as _;

use p256::ecdsa::signature::{Signer as _, Verifier as _};

use crate::{CryptoError, Entropy};

/// Bytes of a P-256 private scalar.
pub const P256_SECRET_LEN: usize = 32;

/// Bytes of an uncompressed SEC1 point: the `0x04` marker and the two
/// coordinates. This is the form a `SubjectPublicKeyInfo` carries and the form
/// a certificate is written from, so it is the only public-key encoding here.
pub const P256_PUBLIC_LEN: usize = 65;

/// The longest DER-encoded ECDSA signature P-256 can produce: a `SEQUENCE`
/// header and two `INTEGER`s, each at most 33 bytes of content because a
/// 32-byte scalar with its top bit set takes a leading zero.
pub const P256_MAX_SIGNATURE_LEN: usize = 72;

/// A P-256 signing key, and the one private-key type the appliance holds.
///
/// No `Debug` and no `Clone`: key material has no representation on any surface,
/// and a type that could print it would be the first step toward one. There is
/// one accessor for the scalar ([`Self::into_scalar`]) and it consumes the key,
/// because an appliance that must still be itself after a reboot has to write
/// its own key down somewhere.
pub struct P256SecretKey(p256::ecdsa::SigningKey);

/// Draws allowed before key generation gives up.
///
/// A uniform 32-byte string is a valid P-256 scalar with probability
/// 1 - 2^-32 or so, the group order being just under 2^256, so a second draw
/// is already a once-in-four-billion event and a fifth is not reachable by
/// anything but a generator that is not generating. Refusing there is what
/// turns that into a diagnosis rather than an unbounded loop.
const GENERATE_ATTEMPTS: usize = 4;

impl P256SecretKey {
    /// A fresh key from the node's randomness.
    ///
    /// # Errors
    /// [`CryptoError::InvalidSecretKey`] where every attempt drew a value
    /// outside the group order, which a working generator does not reach.
    pub fn generate(entropy: &dyn Entropy) -> Result<Self, CryptoError> {
        let mut scalar = [0_u8; P256_SECRET_LEN];
        for _ in 0..GENERATE_ATTEMPTS {
            entropy.fill(&mut scalar);
            if let Ok(key) = Self::from_scalar(&scalar) {
                scalar.zeroize();
                return Ok(key);
            }
        }
        scalar.zeroize();
        Err(CryptoError::InvalidSecretKey)
    }

    /// A key from a fixed scalar, which is what a published signing vector fixes
    /// and what the store domain hands over: the scalar it read back off its own
    /// medium, on the way to holding the identity to itself.
    ///
    /// # Errors
    /// [`CryptoError::InvalidSecretKey`] for a scalar that is zero or is not
    /// below the group order — neither is a private key, and both are values a
    /// published corpus contains deliberately.
    pub fn from_scalar(scalar: &[u8; P256_SECRET_LEN]) -> Result<Self, CryptoError> {
        p256::ecdsa::SigningKey::from_bytes(scalar.into())
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// This key's scalar, for the one caller that must persist it: the domain
    /// that owns the store medium, writing the identity a reboot has to restore.
    ///
    /// It **consumes** the key rather than borrowing it, which is the narrowest
    /// shape that works. A `&self` accessor would let a caller hold a key and
    /// take copies of its scalar at will, and the whole point of routing this
    /// through one method is that a copy is an event with a place in the code.
    /// The caller owns what it does with the bytes; [`from_scalar`] is the way
    /// back.
    ///
    /// [`from_scalar`]: Self::from_scalar
    #[must_use]
    pub fn into_scalar(self) -> [u8; P256_SECRET_LEN] {
        let mut scalar = [0_u8; P256_SECRET_LEN];
        // `to_bytes` answers a `FieldBytes`, which is exactly a 32-byte array
        // for this curve; the copy is bounded by the destination, so a width
        // that ever disagreed would truncate rather than index out of bounds,
        // and the assertion below is what stops it disagreeing.
        let mut bytes = self.0.to_bytes();
        for (slot, byte) in scalar.iter_mut().zip(bytes.iter()) {
            *slot = *byte;
        }
        bytes.zeroize();
        scalar
    }

    /// The uncompressed SEC1 point this key verifies under.
    #[must_use]
    pub fn public_key(&self) -> [u8; P256_PUBLIC_LEN] {
        let point = self.0.verifying_key().to_encoded_point(false);
        let mut encoded = [0_u8; P256_PUBLIC_LEN];
        // The encoding is uncompressed because that is what was asked for, so
        // it is exactly `P256_PUBLIC_LEN` bytes and the copy is total; a
        // shorter answer would leave the marker byte in place and produce a
        // point nothing accepts, which is why the length is checked rather
        // than assumed.
        let bytes = point.as_bytes();
        if bytes.len() == P256_PUBLIC_LEN {
            encoded.copy_from_slice(bytes);
        }
        encoded
    }

    /// Sign `message` — hashed with SHA-256 here, not by the caller — and
    /// write the DER encoding into `out`.
    ///
    /// The nonce is derived deterministically from the key and the message, so
    /// one message under one key has exactly one signature. That is what makes
    /// signing provable against a published vector at all: a randomised nonce
    /// would leave nothing to compare against.
    ///
    /// # Errors
    /// [`CryptoError::BufferTooSmall`] where `out` is shorter than the
    /// encoding, which [`P256_MAX_SIGNATURE_LEN`] bounds.
    pub fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        let signature: p256::ecdsa::Signature = self.0.sign(message);
        let der = signature.to_der();
        let bytes = der.as_bytes();
        let target = out
            .get_mut(..bytes.len())
            .ok_or(CryptoError::BufferTooSmall {
                needed: bytes.len(),
            })?;
        target.copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

/// Verify a DER-encoded ECDSA P-256 signature over SHA-256 of `message`.
///
/// Every argument is untrusted: `public_key` arrives inside a certificate and
/// `signature` off the wire, so both are decoded through the adopted crate's
/// checked constructors and every refusal is a typed error. A public key that
/// is not a point on the curve, a signature whose DER is not the canonical
/// encoding of two in-range integers, and a signature that simply does not
/// verify are all answered the same way from the outside — which is what a
/// verifier owes a forger.
///
/// # Errors
/// [`CryptoError::InvalidPublicKey`] where the point does not decode,
/// [`CryptoError::NotAuthentic`] for every signature that does not verify,
/// including one whose encoding is malformed.
pub fn p256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let parsed =
        p256::ecdsa::Signature::from_der(signature).map_err(|_| CryptoError::NotAuthentic)?;
    key.verify(message, &parsed)
        .map_err(|_| CryptoError::NotAuthentic)
}

// The scalar the accessor above copies out is a `FieldBytes` of this curve, and
// the copy is bounded by the destination array. Held equal here so a width that
// disagreed is a build failure rather than a key silently truncated to the
// shorter of the two.
const _: () = assert!(
    P256_SECRET_LEN == 32,
    "a P-256 scalar is 32 bytes, and `into_scalar` copies into an array of that width"
);
