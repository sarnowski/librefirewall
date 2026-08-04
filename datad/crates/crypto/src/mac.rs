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
