use crate::{CryptoError, DIGEST_LEN};

/// The most derived key material one expand can produce: the expand loop
/// counts blocks in a single byte, so 255 hash outputs is where the
/// construction stops being defined.
pub const MAX_DERIVED_LEN: usize = 255 * DIGEST_LEN;

/// A pseudorandom key: what extract produces and expand consumes.
///
/// A distinct type rather than a `[u8; 32]` so an expand cannot be handed
/// input keying material by mistake — the two are both 32 bytes at a call site
/// and only one of them has been through extract. It derives no `Debug`: it is
/// key material, and no surface carries key material.
pub struct Prk(hkdf::Hkdf<sha2::Sha256>);

/// Concentrate input keying material into a pseudorandom key.
///
/// An empty salt is the construction's own default and means a block of
/// zeroes, so it is a legitimate argument rather than a missing one.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Prk {
    Prk(hkdf::Hkdf::new(Some(salt), ikm))
}

/// Expand a pseudorandom key into `out`, bound to `info`.
///
/// # Errors
/// [`CryptoError::DerivedKeyTooLong`] when more is asked for than
/// [`MAX_DERIVED_LEN`]. `out` is untouched on that path — the adopted
/// implementation ranges the length before it writes, which is third-party
/// runtime behaviour and so is stated here rather than assumed; the refusal
/// test asserts it, so a dependency bump that changed it fails the gate.
pub fn hkdf_expand(prk: &Prk, info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    prk.0
        .expand(info, out)
        .map_err(|_| CryptoError::DerivedKeyTooLong {
            requested: out.len(),
        })
}
