use crate::{
    Aes256Gcm, ChaCha20Poly1305, CryptoError, Drbg, MAC_LEN, SEED_LEN,
    aead::AeadOps,
    hkdf_expand, hkdf_extract, hmac_sha256, hmac_sha256_verify, sha256,
    vectors::{
        AES_256_GCM_VECTORS, AeadVector, CHACHA20_POLY1305_VECTORS, CHACHA20_STREAM_VECTORS,
        DRBG_VECTORS, DrbgVector, HKDF_SHA256_VECTORS, HMAC_SHA256_VECTORS, HashVector, KdfVector,
        MacVector, SHA256_VECTORS, StreamVector,
    },
};
use chacha20::cipher::{KeyIvInit as _, StreamCipher as _, StreamCipherSeek as _};

/// Which published row disagreed with this build.
///
/// Both fields are carried because the two readers need different halves: a
/// host test prints `vector` and names the published row, while the
/// cryptography protection domain has only a console record's two numbers and
/// reports `index`. Neither is derivable from the other on the side that
/// wants it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorFailure {
    /// Position in the table, so a console record can name it.
    pub index: u32,
    /// The published row's own identifier, so a developer can open the source
    /// file and read the case that failed.
    pub vector: &'static str,
}

/// The widest buffer any authenticated-encryption or derivation row needs.
///
/// Derived from the tables rather than chosen, so a vector added past it fails
/// the build here instead of overflowing a scratch buffer on a booted node.
pub(crate) const SCRATCH_LEN: usize = 160;

const _: () = assert!(widest_row() <= SCRATCH_LEN);

/// The widest row any table carries, walked at compile time so
/// [`SCRATCH_LEN`] is derived from the vectors rather than chosen beside them.
/// A row added past the buffer fails the build here, which is the only place
/// it can fail safely — on a booted node it would be a buffer overrun.
///
/// `const fn` and not a `const`, so a host test can call it and hold the
/// derivation to a second walk written differently.
pub(crate) const fn widest_row() -> usize {
    let mut widest = 0;
    let mut at = 0;
    while at < AES_256_GCM_VECTORS.len() {
        widest = larger(widest, AES_256_GCM_VECTORS[at].ciphertext.len());
        at += 1;
    }
    at = 0;
    while at < CHACHA20_POLY1305_VECTORS.len() {
        widest = larger(widest, CHACHA20_POLY1305_VECTORS[at].ciphertext.len());
        at += 1;
    }
    at = 0;
    while at < CHACHA20_STREAM_VECTORS.len() {
        widest = larger(widest, CHACHA20_STREAM_VECTORS[at].keystream.len());
        at += 1;
    }
    at = 0;
    while at < HKDF_SHA256_VECTORS.len() {
        widest = larger(widest, HKDF_SHA256_VECTORS[at].okm.len());
        at += 1;
    }
    at = 0;
    while at < DRBG_VECTORS.len() {
        widest = larger(widest, DRBG_VECTORS[at].first_output.len());
        at += 1;
    }
    widest
}

const fn larger(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// `outcome` held, or the failure naming this row.
fn row(index: usize, vector: &'static str, outcome: bool) -> Result<(), VectorFailure> {
    if outcome {
        return Ok(());
    }
    Err(VectorFailure {
        // Every table is a compile-time constant of a few dozen rows, so the
        // cast is exact; `try_into` here would be a refusal path no table can
        // reach and no test could cover.
        index: index as u32,
        vector,
    })
}

/// Prove SHA-256 against every row of its table.
///
/// # Errors
/// The first row whose digest this build does not reproduce.
pub fn prove_sha256() -> Result<u32, VectorFailure> {
    prove_sha256_in(SHA256_VECTORS)
}

/// The same run over a caller's table, which is how the failure arms above
/// are reached from a test: every committed row passes, so a corrupted table
/// is the only way to exercise the answer this crate gives when one does not.
pub(crate) fn prove_sha256_in(table: &[HashVector]) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        row(
            index,
            vector.id,
            sha256(vector.message) == vector.digest && streamed(vector.message) == vector.digest,
        )?;
    }
    Ok(table.len() as u32)
}

/// The same digest taken a byte at a time, so the chunked path is proved by
/// the same published rows as the contiguous one rather than by agreement with
/// it. A single-byte chunk is the shape that most reliably breaks a block
/// buffer, and every row is short enough to pay for it.
fn streamed(message: &[u8]) -> [u8; crate::DIGEST_LEN] {
    let mut hasher = crate::Sha256::new();
    for byte in message {
        hasher.update(core::slice::from_ref(byte));
    }
    hasher.finish()
}

/// Prove HMAC-SHA-256, including the forgeries a verifier must refuse.
///
/// # Errors
/// The first row this build answers differently from the published one.
pub fn prove_hmac_sha256() -> Result<u32, VectorFailure> {
    prove_hmac_sha256_in(HMAC_SHA256_VECTORS)
}

pub(crate) fn prove_hmac_sha256_in(table: &[MacVector]) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        let verified = hmac_sha256_verify(vector.key, vector.message, &vector.tag);
        let held = match (vector.authentic, verified) {
            (true, Ok(())) => matches!(
                hmac_sha256(vector.key, vector.message),
                Ok(tag) if tag == vector.tag
            ),
            (false, Err(CryptoError::NotAuthentic)) => {
                // A forgery must also not be what this build computes, or the
                // row would be proving the verifier against a tag it agrees
                // with and the refusal would be the bug.
                !matches!(
                    hmac_sha256(vector.key, vector.message),
                    Ok(tag) if tag == vector.tag
                )
            }
            _ => false,
        };
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

/// Prove HKDF-SHA-256 extract-and-expand.
///
/// # Errors
/// The first row whose derived key this build does not reproduce.
pub fn prove_hkdf_sha256() -> Result<u32, VectorFailure> {
    prove_hkdf_sha256_in(HKDF_SHA256_VECTORS)
}

pub(crate) fn prove_hkdf_sha256_in(table: &[KdfVector]) -> Result<u32, VectorFailure> {
    let mut derived = [0_u8; SCRATCH_LEN];
    for (index, vector) in table.iter().enumerate() {
        let want = vector.okm.len();
        let prk = hkdf_extract(vector.salt, vector.ikm);
        let out = &mut derived[..want];
        out.fill(0);
        let held = hkdf_expand(&prk, vector.info, out).is_ok() && &derived[..want] == vector.okm;
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

/// Prove the raw ChaCha20 keystream — the primitive the generator is built on.
///
/// # Errors
/// The first row whose keystream this build does not reproduce.
pub fn prove_chacha20() -> Result<u32, VectorFailure> {
    prove_chacha20_in(CHACHA20_STREAM_VECTORS)
}

pub(crate) fn prove_chacha20_in(table: &[StreamVector]) -> Result<u32, VectorFailure> {
    let mut produced = [0_u8; SCRATCH_LEN];
    for (index, vector) in table.iter().enumerate() {
        let want = vector.keystream.len();
        let out = &mut produced[..want];
        out.fill(0);
        let mut cipher = chacha20::ChaCha20::new(&vector.key.into(), &vector.nonce.into());
        // The counter is a block index and the seek is in bytes, so a row
        // naming block one starts 64 bytes in.
        cipher.seek(u64::from(vector.counter) * 64);
        cipher.apply_keystream(out);
        row(index, vector.id, &produced[..want] == vector.keystream)?;
    }
    Ok(table.len() as u32)
}

/// Prove ChaCha20-Poly1305 both ways, forgeries included.
///
/// # Errors
/// The first row this build answers differently from the published one.
pub fn prove_chacha20_poly1305() -> Result<u32, VectorFailure> {
    prove_chacha20_poly1305_in(CHACHA20_POLY1305_VECTORS)
}

pub(crate) fn prove_chacha20_poly1305_in(table: &[AeadVector]) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        row(
            index,
            vector.id,
            aead_row(vector, &ChaCha20Poly1305::new(&vector.key)),
        )?;
    }
    Ok(table.len() as u32)
}

/// Prove AES-256-GCM both ways, forgeries included.
///
/// # Errors
/// The first row this build answers differently from the published one.
pub fn prove_aes_256_gcm() -> Result<u32, VectorFailure> {
    prove_aes_256_gcm_in(AES_256_GCM_VECTORS)
}

pub(crate) fn prove_aes_256_gcm_in(table: &[AeadVector]) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        row(
            index,
            vector.id,
            aead_row(vector, &Aes256Gcm::new(&vector.key)),
        )?;
    }
    Ok(table.len() as u32)
}

/// One authenticated-encryption row, for either construction.
///
/// An accepting row must seal to exactly the published ciphertext and tag and
/// then open back to the plaintext; a refusing row must be refused, and must
/// stay refused when its tag is what an attacker would have flipped. The two
/// constructions share this because the property is the AEAD contract's, not
/// either cipher's.
fn aead_row<A: AeadOps>(vector: &AeadVector, cipher: &A) -> bool {
    let bytes = vector.ciphertext.len();
    if bytes > SCRATCH_LEN {
        return false;
    }
    let mut buffer = [0_u8; SCRATCH_LEN];
    if vector.authentic {
        buffer[..bytes].copy_from_slice(vector.plaintext);
        let Ok(tag) = cipher.seal_in(&vector.nonce, vector.associated_data, &mut buffer[..bytes])
        else {
            return false;
        };
        if tag != vector.tag || &buffer[..bytes] != vector.ciphertext {
            return false;
        }
        return cipher
            .open_in(
                &vector.nonce,
                vector.associated_data,
                &mut buffer[..bytes],
                &vector.tag,
            )
            .is_ok()
            && &buffer[..bytes] == vector.plaintext;
    }
    buffer[..bytes].copy_from_slice(vector.ciphertext);
    matches!(
        cipher.open_in(
            &vector.nonce,
            vector.associated_data,
            &mut buffer[..bytes],
            &vector.tag,
        ),
        Err(CryptoError::NotAuthentic)
    )
}

/// Prove the generator's first draw against its seeded keystream.
///
/// # Errors
/// The first seed whose output this build does not reproduce.
pub fn prove_drbg() -> Result<u32, VectorFailure> {
    prove_drbg_in(DRBG_VECTORS)
}

pub(crate) fn prove_drbg_in(table: &[DrbgVector]) -> Result<u32, VectorFailure> {
    let mut produced = [0_u8; SCRATCH_LEN];
    for (index, vector) in table.iter().enumerate() {
        let want = vector.first_output.len();
        let out = &mut produced[..want];
        out.fill(0);
        let mut seed = [0_u8; SEED_LEN];
        seed[..vector.key.len()].copy_from_slice(&vector.key);
        seed[vector.key.len()..].copy_from_slice(&vector.nonce);
        let mut generator = Drbg::from_seed(&seed);
        generator.fill(out);
        row(index, vector.id, &produced[..want] == vector.first_output)?;
    }
    Ok(table.len() as u32)
}

/// The tag length the AEAD rows compare against, restated nowhere: this holds
/// the table's own array size to the crate's constant, so a vector file
/// regenerated against a different tag size fails here.
const _: () = assert!(MAC_LEN == crate::DIGEST_LEN);
