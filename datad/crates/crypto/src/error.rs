use core::fmt;

/// Every way a call into this crate is answered no.
///
/// The refusals a cryptographic API usually carries are unrepresentable here:
/// a wrong key length for a fixed-key construction cannot be built, nor a
/// wrong nonce length, nor a wrong tag length. What remains are the lengths an
/// algorithm itself bounds, the answers an adversary can provoke, and the ones
/// an adopted crate could give that its own contract says it will not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// An adopted keyed construction refused a key length its own definition
    /// admits. HMAC is defined for every key length, so nothing here should
    /// ever produce this — it is carried because the adopted constructor is
    /// fallible and an adopted crate disagreeing with its contract is a thing
    /// to surface, not to assume away or panic on.
    KeyRejected { length: usize },
    /// More output was asked of HKDF-Expand than the construction defines.
    /// The limit is 255 hash outputs, because the expand loop's counter is one
    /// byte; asking past it has no answer, so it is refused rather than
    /// wrapped to a shorter one an attacker could collide against.
    DerivedKeyTooLong { requested: usize },
    /// A message exceeded what the AEAD's block counter can address. Refused
    /// rather than truncated: a silently shortened encryption returns a
    /// ciphertext that decrypts to something the caller never sent.
    MessageTooLong { bytes: usize },
    /// The tag did not authenticate the ciphertext and its associated data.
    /// The buffer's contents after this are not a plaintext and are not
    /// readable as one — this is the answer a forgery gets, and it carries
    /// nothing about which byte differed. A signature that does not verify is
    /// answered with this too: the caller learns that authentication failed
    /// and nothing about the step it failed at.
    NotAuthentic,
    /// A public value a peer chose is not one of its algorithm's: a point that
    /// is not on the curve, or a key whose packing is not the canonical one.
    /// Carries nothing about the value — it is the peer's byte string and an
    /// operator surface is not where it belongs.
    InvalidPublicKey,
    /// A private scalar outside the range its group defines. Reachable only
    /// from a fixed scalar a caller supplied, never from a generated one.
    InvalidSecretKey,
    /// An X25519 exchange whose result is all zeroes, which a peer can force
    /// with a small-order public value. Refused rather than keyed from: the
    /// secret would be one the peer fixed without knowing ours.
    NonContributory,
    /// A key-encapsulation ciphertext of a length the algorithm does not
    /// define. Every well-sized ciphertext has an answer — a wrong one, where
    /// it does not decrypt — so the length is the only thing to refuse.
    InvalidCiphertext { bytes: usize },
    /// An adopted key-encapsulation implementation refused to encapsulate,
    /// which its own contract says it does not do. Carried for the same reason
    /// [`CryptoError::KeyRejected`] is.
    EncapsulationFailed,
    /// A caller's output buffer is shorter than the value that would go in it.
    /// Refused rather than truncated: a signature cut short is a signature
    /// nothing can verify and everything downstream would carry the confusion.
    BufferTooSmall { needed: usize },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyRejected { length } => {
                write!(f, "the keyed construction refused a {length}-byte key")
            }
            Self::DerivedKeyTooLong { requested } => write!(
                f,
                "{requested} bytes of derived key were asked for and the construction defines at \
                 most {}",
                crate::MAX_DERIVED_LEN
            ),
            Self::MessageTooLong { bytes } => {
                write!(
                    f,
                    "a {bytes}-byte message is past what this AEAD can address"
                )
            }
            Self::NotAuthentic => f.write_str("the tag did not authenticate what it was given"),
            Self::InvalidPublicKey => f.write_str("the public value is not one of its algorithm's"),
            Self::InvalidSecretKey => f.write_str("the scalar is outside the group order"),
            Self::NonContributory => {
                f.write_str("the key exchange produced a secret the peer alone fixed")
            }
            Self::InvalidCiphertext { bytes } => write!(
                f,
                "a {bytes}-byte ciphertext is not a length this encapsulation defines"
            ),
            Self::EncapsulationFailed => {
                f.write_str("the encapsulation refused, which its contract says it does not")
            }
            Self::BufferTooSmall { needed } => {
                write!(f, "the output buffer is shorter than the {needed} bytes")
            }
        }
    }
}
