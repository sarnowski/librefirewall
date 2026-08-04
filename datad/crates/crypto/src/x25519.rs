use zeroize::Zeroize as _;

use crate::{CryptoError, Entropy};

/// Bytes of an X25519 scalar, public value and shared secret alike — the
/// function is defined on one length throughout.
pub const X25519_LEN: usize = 32;

/// One side of an X25519 exchange.
///
/// The secret outlives the call that publishes the public value, because the
/// two halves of a key exchange happen at different times: a share goes out in
/// a handshake message and the peer's arrives later. No `Debug` and no
/// accessor for the scalar, on the same terms as the signing key.
pub struct X25519Secret(x25519_dalek::StaticSecret);

impl X25519Secret {
    /// A fresh scalar from the node's randomness. Every 32-byte string is
    /// one, so this is a draw and not a search.
    pub fn generate(entropy: &dyn Entropy) -> Self {
        let mut scalar = [0_u8; X25519_LEN];
        entropy.fill(&mut scalar);
        let secret = Self::from_scalar(&scalar);
        scalar.zeroize();
        secret
    }

    /// A scalar fixed by a published vector. Every 32-byte string is a valid
    /// X25519 scalar — the function clamps rather than rejects — so there is
    /// nothing here to refuse.
    #[must_use]
    pub fn from_scalar(scalar: &[u8; X25519_LEN]) -> Self {
        Self(x25519_dalek::StaticSecret::from(*scalar))
    }

    /// The public value to publish for this scalar.
    #[must_use]
    pub fn public_key(&self) -> [u8; X25519_LEN] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }

    /// The shared secret with `peer`, whose value is chosen by the peer and is
    /// therefore untrusted.
    ///
    /// # Errors
    /// [`CryptoError::NonContributory`] where the result is all zeroes. X25519
    /// answers a small-order public value with a zero shared secret rather
    /// than an error, and a zero secret is one the peer fixed without knowing
    /// our scalar — so it is refused here instead of being keyed from. This is
    /// the check the published corpus's low-order rows exist to demand.
    pub fn agree(&self, peer: &[u8; X25519_LEN]) -> Result<[u8; X25519_LEN], CryptoError> {
        let shared = self.0.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributory);
        }
        Ok(shared.to_bytes())
    }
}
