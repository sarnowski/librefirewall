use lfw_crypto::p256_verify;
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};

/// The only way a signature is checked anywhere in this stack: on a
/// certificate in a chain, and on the handshake signature a peer proves
/// possession of its key with.
///
/// One algorithm, because the certificate profile fixes one. A verifier that
/// accepted a second would accept a chain issued under it, and the set of
/// algorithms a chain may be issued under is a product decision rather than a
/// library default.
#[derive(Debug)]
struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    /// The public key arrives inside a certificate and the signature off the
    /// wire, so both are untrusted and every way either can be wrong is one
    /// answer. That the answer carries nothing is the point: a verifier that
    /// distinguished a malformed encoding from a wrong scalar would be telling
    /// a forger which of the two it had produced.
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        p256_verify(public_key, message, signature).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;

/// What the chain validator and the handshake-signature check are given.
///
/// The mapping is one entry, so the list a peer is told this end accepts is
/// one scheme long — which is what makes a downgrade to a weaker signature
/// algorithm not a thing this connection can be talked into.
pub static SUPPORTED_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ECDSA_P256_SHA256],
    mapping: &[(SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256])],
};
