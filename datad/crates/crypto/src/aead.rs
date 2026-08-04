use aes_gcm::aead::{AeadCore, AeadInPlace as _, KeyInit as _};
use chacha20::cipher::Unsigned as _;

use crate::CryptoError;

/// Bytes a key occupies. Both constructions here take 256-bit keys, which is
/// what lets one constant serve them and a caller hold one key type.
pub const KEY_LEN: usize = 32;

/// Bytes a nonce occupies. Ninety-six bits for both, which is the only nonce
/// size TLS 1.3 uses and the only one either construction is exposed with.
pub const NONCE_LEN: usize = 12;

/// Bytes an authentication tag occupies. Full length always — a truncated tag
/// is not constructible here, and truncation is what the published forgery
/// vectors most often exercise.
pub const TAG_LEN: usize = 16;

/// The pair of operations both constructions offer, so the vector runner can
/// hold one row-checking routine instead of two that must stay identical. Not
/// public: a caller names the construction it means, and an abstraction over
/// the two would invite a call site that does not know which one it got.
pub(crate) trait AeadOps {
    fn seal_in(
        &self,
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], CryptoError>;

    fn open_in(
        &self,
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError>;
}

/// Declares one AEAD over an adopted implementation.
///
/// Both constructions get the identical surface — in-place on the caller's own
/// buffer, detached tag, nothing allocated — so writing it twice would be two
/// things to keep in step for no difference a caller can see.
macro_rules! aead {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Holds an expanded key schedule and derives no `Debug`: it is key
        /// material, and no surface carries key material.
        pub struct $name($inner);

        impl $name {
            #[must_use]
            pub fn new(key: &[u8; KEY_LEN]) -> Self {
                Self(<$inner>::new(key.into()))
            }

            /// Encrypt `buffer` where it lies and return its tag.
            ///
            /// # Errors
            /// [`CryptoError::MessageTooLong`] when the buffer is past what
            /// the construction's block counter addresses.
            pub fn seal(
                &self,
                nonce: &[u8; NONCE_LEN],
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> Result<[u8; TAG_LEN], CryptoError> {
                let bytes = buffer.len();
                self.0
                    .encrypt_in_place_detached(nonce.into(), associated_data, buffer)
                    .map(Into::into)
                    .map_err(|_| CryptoError::MessageTooLong { bytes })
            }

            /// Authenticate `tag` over `buffer` and its associated data, and
            /// decrypt in place only if it holds.
            ///
            /// # Errors
            /// [`CryptoError::NotAuthentic`] on a forgery. The adopted
            /// implementation authenticates before it decrypts, so the buffer
            /// still holds the ciphertext — but a caller that reads a buffer
            /// it was refused has already lost the property this refusal
            /// exists for, so it is specified as unreadable rather than as
            /// unchanged.
            pub fn open(
                &self,
                nonce: &[u8; NONCE_LEN],
                associated_data: &[u8],
                buffer: &mut [u8],
                tag: &[u8; TAG_LEN],
            ) -> Result<(), CryptoError> {
                self.0
                    .decrypt_in_place_detached(nonce.into(), associated_data, buffer, tag.into())
                    .map_err(|_| CryptoError::NotAuthentic)
            }
        }

        impl AeadOps for $name {
            fn seal_in(
                &self,
                nonce: &[u8; NONCE_LEN],
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> Result<[u8; TAG_LEN], CryptoError> {
                self.seal(nonce, associated_data, buffer)
            }

            fn open_in(
                &self,
                nonce: &[u8; NONCE_LEN],
                associated_data: &[u8],
                buffer: &mut [u8],
                tag: &[u8; TAG_LEN],
            ) -> Result<(), CryptoError> {
                self.open(nonce, associated_data, buffer, tag)
            }
        }
    };
}

aead!(
    ChaCha20Poly1305,
    chacha20poly1305::ChaCha20Poly1305,
    "ChaCha20-Poly1305: the management channel's cipher suite, and the one \
     construction here whose speed does not depend on a hardware instruction."
);

aead!(
    Aes256Gcm,
    aes_gcm::Aes256Gcm,
    "AES-256-GCM: the construction the hardware baseline exists for. Nothing \
     the appliance speaks today negotiates it; what it is here for is to be \
     measured on the shipped image, because its throughput is the evidence \
     that the AES-NI and carry-less-multiply backends are the ones running."
);

/// The sizes above are what callers are written against, not the adopted
/// types' own associated constants. Holding the two together here is what
/// makes a dependency bump that changed either fail this build rather than
/// the wire.
const _: () = {
    assert!(<chacha20poly1305::ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE == NONCE_LEN);
    assert!(<chacha20poly1305::ChaCha20Poly1305 as AeadCore>::TagSize::USIZE == TAG_LEN);
    assert!(<aes_gcm::Aes256Gcm as AeadCore>::NonceSize::USIZE == NONCE_LEN);
    assert!(<aes_gcm::Aes256Gcm as AeadCore>::TagSize::USIZE == TAG_LEN);
};
