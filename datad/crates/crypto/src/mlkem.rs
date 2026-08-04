use ml_kem::{
    EncapsulateDeterministic as _, EncodedSizeUser as _, KemCore as _, array::Array,
    kem::Decapsulate as _,
};
use zeroize::Zeroize as _;

use crate::{CryptoError, Entropy};

/// Bytes of an ML-KEM-768 encapsulation key — the value a peer publishes.
pub const ML_KEM_768_ENCAPSULATION_KEY_LEN: usize = 1184;

/// Bytes of an ML-KEM-768 decapsulation key, in the encoding the algorithm
/// defines: the decryption key, the encapsulation key, its hash, and the
/// implicit-rejection secret.
pub const ML_KEM_768_DECAPSULATION_KEY_LEN: usize = 2400;

/// Bytes of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;

/// Bytes of the shared secret either side derives.
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

/// Bytes of each seed the algorithm's deterministic entry points take.
pub const ML_KEM_768_SEED_LEN: usize = 32;

/// The private half of an ML-KEM-768 key pair.
///
/// No `Debug` and no `Clone`, on the same terms as the other two private
/// types. It does expose its own encoding, because the published corpus fixes
/// a decapsulation key by its bytes and a proof that cannot reconstruct one
/// cannot use those rows.
pub struct MlKem768DecapsulationKey(<ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey);

impl MlKem768DecapsulationKey {
    /// A fresh key pair from the node's randomness.
    ///
    /// The two seeds are drawn and handed to the algorithm's own deterministic
    /// entry point, which is exactly what its randomised one does — so this
    /// takes one randomness interface rather than a second one shaped like the
    /// adopted crate's.
    pub fn generate(entropy: &dyn Entropy) -> Self {
        let mut d = [0_u8; ML_KEM_768_SEED_LEN];
        let mut z = [0_u8; ML_KEM_768_SEED_LEN];
        entropy.fill(&mut d);
        entropy.fill(&mut z);
        let key = Self::from_seeds(&d, &z);
        d.zeroize();
        z.zeroize();
        key
    }

    /// The key pair the algorithm defines for a fixed pair of seeds, which is
    /// what a published key-generation vector fixes.
    #[must_use]
    pub fn from_seeds(d: &[u8; ML_KEM_768_SEED_LEN], z: &[u8; ML_KEM_768_SEED_LEN]) -> Self {
        let (decapsulation, _) = ml_kem::MlKem768::generate_deterministic(&Array(*d), &Array(*z));
        Self(decapsulation)
    }

    /// Rebuild a key from its own encoding.
    #[must_use]
    pub fn from_bytes(encoded: &[u8; ML_KEM_768_DECAPSULATION_KEY_LEN]) -> Self {
        Self(<ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey::from_bytes(&Array(*encoded)))
    }

    /// This key's own encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ML_KEM_768_DECAPSULATION_KEY_LEN] {
        self.0.as_bytes().0
    }

    /// The encapsulation key to publish.
    #[must_use]
    pub fn encapsulation_key(&self) -> [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN] {
        self.0.encapsulation_key().as_bytes().0
    }

    /// The shared secret a `ciphertext` carries.
    ///
    /// The ciphertext is the peer's and is therefore untrusted, and the only
    /// thing about it that can be wrong is its length: the algorithm answers
    /// every well-sized ciphertext, returning a secret derived from this key's
    /// implicit-rejection value where the ciphertext does not decrypt. That is
    /// deliberate in the algorithm and is not papered over here — an attacker
    /// must not be able to tell a bad ciphertext from a good one by the
    /// answer, so a wrong secret and not a refusal is the correct outcome.
    ///
    /// # Errors
    /// [`CryptoError::InvalidCiphertext`] for a ciphertext of the wrong
    /// length, which is the one thing the algorithm does not define an answer
    /// for.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<[u8; ML_KEM_768_SHARED_SECRET_LEN], CryptoError> {
        let sized: [u8; ML_KEM_768_CIPHERTEXT_LEN] =
            ciphertext
                .try_into()
                .map_err(|_| CryptoError::InvalidCiphertext {
                    bytes: ciphertext.len(),
                })?;
        self.0
            .decapsulate(&Array(sized))
            .map(|secret| secret.0)
            .map_err(|()| CryptoError::InvalidCiphertext {
                bytes: ciphertext.len(),
            })
    }
}

/// The public half, as a peer published it.
///
/// Constructed only through [`MlKem768EncapsulationKey::from_bytes`], which is
/// where the encoding is checked, so a value of this type is one that survived
/// that check.
pub struct MlKem768EncapsulationKey(<ml_kem::MlKem768 as ml_kem::KemCore>::EncapsulationKey);

impl MlKem768EncapsulationKey {
    /// Decode a peer's encapsulation key, rejecting one that is not the
    /// canonical encoding of a key.
    ///
    /// The check is the round trip the algorithm's own specification states:
    /// the key's coefficients are packed twelve bits at a time, so a byte
    /// string can decode to coefficients that are not reduced and would
    /// re-encode differently. Re-encoding and comparing is what refuses those,
    /// and it is a comparison rather than an implementation of the check.
    ///
    /// # Errors
    /// [`CryptoError::InvalidPublicKey`] for the wrong length or a
    /// non-canonical encoding.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, CryptoError> {
        let sized: [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN] = encoded
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let key =
            <ml_kem::MlKem768 as ml_kem::KemCore>::EncapsulationKey::from_bytes(&Array(sized));
        if key.as_bytes().0 != sized {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    /// A ciphertext for this key and the shared secret it carries.
    ///
    /// # Errors
    /// [`CryptoError::EncapsulationFailed`] where the adopted implementation
    /// refuses, which its own contract says it does not do — carried because
    /// the call is fallible and an adopted crate disagreeing with its contract
    /// is a thing to surface rather than panic on.
    pub fn encapsulate(
        &self,
        entropy: &dyn Entropy,
    ) -> Result<
        (
            [u8; ML_KEM_768_CIPHERTEXT_LEN],
            [u8; ML_KEM_768_SHARED_SECRET_LEN],
        ),
        CryptoError,
    > {
        let mut message = [0_u8; ML_KEM_768_SEED_LEN];
        entropy.fill(&mut message);
        let outcome = self.encapsulate_deterministic(&message);
        message.zeroize();
        outcome
    }

    /// The same, for the fixed message a published vector names.
    ///
    /// # Errors
    /// [`CryptoError::EncapsulationFailed`], on the same terms.
    pub fn encapsulate_deterministic(
        &self,
        message: &[u8; ML_KEM_768_SEED_LEN],
    ) -> Result<
        (
            [u8; ML_KEM_768_CIPHERTEXT_LEN],
            [u8; ML_KEM_768_SHARED_SECRET_LEN],
        ),
        CryptoError,
    > {
        self.0
            .encapsulate_deterministic(&Array(*message))
            .map(|(ciphertext, secret)| (ciphertext.0, secret.0))
            .map_err(|_| CryptoError::EncapsulationFailed)
    }
}
