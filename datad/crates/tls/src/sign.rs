use alloc::{boxed::Box, sync::Arc, vec::Vec};

use lfw_crypto::{P256_MAX_SIGNATURE_LEN, P256SecretKey};
use rustls::{
    Error, SignatureAlgorithm, SignatureScheme,
    sign::{Signer, SigningKey},
};

/// A private key the appliance authenticates with, wherever it lives.
///
/// This is the seam the identity split is built around, and it is a trait for
/// exactly one reason: the device key belongs to the domain that owns the
/// storage it is written on, and that domain is not this one. Today the only
/// implementation holds the key in memory beside its caller; when the store
/// domain exists, a second implementation will forward the same call over a
/// channel and return the same bytes, and nothing above this line changes —
/// the TLS stack never sees a key, only something that signs.
///
/// One method and one algorithm, because the profile fixes both: everything
/// the management plane signs is ECDSA over P-256 with SHA-256, and a trait
/// that could express a second algorithm would be inviting a caller to pick
/// one.
pub trait SignOperation: Send + Sync {
    /// Sign `message` — which is hashed by the implementation, not the caller
    /// — writing the DER encoding into `out` and answering its length.
    ///
    /// # Errors
    /// [`SignRefused`], which carries nothing. A signer that cannot sign gives
    /// a caller here nothing to act on: the handshake fails either way, and a
    /// richer error would be a description of a remote domain's internals
    /// arriving on a path that faces the network.
    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, SignRefused>;
}

/// The signing capability said no. A unit struct rather than an enum, because
/// there is exactly one thing a caller does about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignRefused;

/// The signer that holds its own key, which is what the appliance uses until
/// the store domain owns the key instead.
pub struct LocalKey(P256SecretKey);

impl LocalKey {
    #[must_use]
    pub const fn new(key: P256SecretKey) -> Self {
        Self(key)
    }
}

impl SignOperation for LocalKey {
    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, SignRefused> {
        self.0.sign(message, out).map_err(|_| SignRefused)
    }
}

/// A [`SignOperation`] in the shape the TLS library resolves a certificate's
/// key to.
pub struct EcdsaP256SigningKey {
    operation: Arc<dyn SignOperation>,
}

impl EcdsaP256SigningKey {
    #[must_use]
    pub fn new(operation: Arc<dyn SignOperation>) -> Self {
        Self { operation }
    }
}

impl core::fmt::Debug for EcdsaP256SigningKey {
    /// Names the algorithm and nothing else. The library requires a rendering
    /// of this type and the only thing inside it is a way to use a private
    /// key, which has none.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ECDSA_NISTP256_SHA256")
    }
}

/// The one scheme this key answers to.
const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

impl SigningKey for EcdsaP256SigningKey {
    /// The peer offers a list and gets this key's one scheme if it is in it,
    /// and nothing if it is not — which fails the handshake rather than
    /// signing under something neither side asked for.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SCHEME).then(|| {
            Box::new(EcdsaP256Signer {
                operation: Arc::clone(&self.operation),
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

/// One signature to produce.
///
/// It owns a share of the signing capability rather than borrowing the key,
/// because the library's trait hands back an owned signer from a shared
/// borrow and there is no lifetime to attach. A reference count is what makes
/// that safe rather than a pointer with a prose lifetime claim, and it costs
/// one atomic per handshake.
struct EcdsaP256Signer {
    operation: Arc<dyn SignOperation>,
}

impl core::fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ECDSA_NISTP256_SHA256")
    }
}

impl Signer for EcdsaP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut encoded = [0_u8; P256_MAX_SIGNATURE_LEN];
        let len = self
            .operation
            .sign(message, &mut encoded)
            .map_err(|SignRefused| Error::General("the signing key refused".into()))?;
        Ok(encoded.get(..len).unwrap_or_default().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}
