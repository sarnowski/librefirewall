use core::fmt;

/// Every way a call into this crate is answered no.
///
/// Four variants and no more, because the refusals a cryptographic API usually
/// carries are unrepresentable here: a wrong key length for a fixed-key
/// construction cannot be built, nor a wrong nonce length, nor a wrong tag
/// length. What remains are the two lengths an algorithm itself bounds, the
/// one answer an adversary can provoke, and one an adopted crate could give
/// that its own contract says it will not.
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
    /// nothing about which byte differed.
    NotAuthentic,
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
        }
    }
}
