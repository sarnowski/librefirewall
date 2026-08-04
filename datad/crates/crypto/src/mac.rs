use hmac::Mac as _;

use crate::CryptoError;

/// Bytes an HMAC-SHA-256 tag occupies.
pub const MAC_LEN: usize = 32;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// HMAC accepts a key of any length by definition — shorter than the hash's
/// block is zero-padded, longer is hashed first — so there is no length here
/// this crate would refuse. The adopted constructor is nonetheless fallible,
/// and its refusal is surfaced rather than assumed away: an adopted crate that
/// stopped agreeing with HMAC's own contract is a finding to report, not one
/// to panic on and not one to paper over with a key it did not ask for.
fn keyed(key: &[u8]) -> Result<HmacSha256, CryptoError> {
    HmacSha256::new_from_slice(key).map_err(|_| CryptoError::KeyRejected { length: key.len() })
}

/// The tag over one contiguous message.
///
/// # Errors
/// [`CryptoError::KeyRejected`], on the terms above.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; MAC_LEN], CryptoError> {
    let mut mac = keyed(key)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Whether `tag` is the authentic tag for `message` under `key`.
///
/// This exists rather than leaving callers to compare [`hmac_sha256`]'s output
/// themselves, because a `==` between two byte arrays is exactly the
/// comparison that leaks which byte differed. The one here is the adopted
/// crate's constant-time verifier.
///
/// # Errors
/// [`CryptoError::NotAuthentic`] when the tag is a forgery, and
/// [`CryptoError::KeyRejected`] on the terms above. A tag of the wrong length
/// is not representable.
pub fn hmac_sha256_verify(
    key: &[u8],
    message: &[u8],
    tag: &[u8; MAC_LEN],
) -> Result<(), CryptoError> {
    let mut mac = keyed(key)?;
    mac.update(message);
    mac.verify_slice(tag).map_err(|_| CryptoError::NotAuthentic)
}

/// A key prepared once and used many times, which is what a key schedule
/// wants: the same secret authenticates a dozen messages in one handshake, and
/// preparing the key per message would redo the block-sized padding each time.
///
/// It holds the initialised state and hands out a clone of it per message,
/// which is exactly what "prepared" means for HMAC — the inner hash's state
/// after the padded key, and nothing more.
///
/// Infallible where [`hmac_sha256`] is not, because a caller of this type is
/// inside a key schedule and has nothing to do with a refusal. The refusal the
/// adopted constructor reserves the right to give is still not assumed away:
/// it becomes a key that authenticates nothing, whose tags are all zeroes, so
/// an exchange under it fails at the first tag comparison rather than
/// proceeding under a key the caller did not choose.
#[derive(Clone)]
pub struct HmacKey(Option<HmacSha256>);

impl HmacKey {
    /// Prepare a key of any length.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self(keyed(key).ok())
    }

    /// A message in progress under this key.
    #[must_use]
    pub fn start(&self) -> HmacContext {
        HmacContext(self.0.clone())
    }
}

/// One message being authenticated, fed in pieces.
pub struct HmacContext(Option<HmacSha256>);

impl HmacContext {
    pub fn update(&mut self, chunk: &[u8]) {
        if let Some(mac) = &mut self.0 {
            mac.update(chunk);
        }
    }

    #[must_use]
    pub fn finish(self) -> [u8; MAC_LEN] {
        self.0
            .map_or([0; MAC_LEN], |mac| mac.finalize().into_bytes().into())
    }
}
