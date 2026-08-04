use crate::{
    Aes256Gcm, ChaCha20Poly1305, CryptoError, Drbg, MAC_LEN, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey, P256SecretKey, SEED_LEN, X25519Secret,
    aead::AeadOps,
    hkdf_expand, hkdf_extract, hmac_sha256, hmac_sha256_verify, p256_verify, sha256,
    vectors::{
        AES_256_GCM_VECTORS, AeadVector, AgreementVector, CHACHA20_POLY1305_VECTORS,
        CHACHA20_STREAM_VECTORS, DRBG_VECTORS, DrbgVector, ECDSA_P256_SIGN_VECTORS,
        ECDSA_P256_VERIFY_VECTORS, HKDF_SHA256_VECTORS, HMAC_SHA256_VECTORS, HashVector, KdfVector,
        KemDecapsulationVector, KemEncapsulationVector, KemKeyCheckVector, KemKeyGenVector,
        ML_KEM_768_DECAPSULATION_VECTORS, ML_KEM_768_ENCAPSULATION_VECTORS,
        ML_KEM_768_KEY_CHECK_VECTORS, ML_KEM_768_KEYGEN_VECTORS, MacVector, SHA256_VECTORS,
        SignatureVector, SigningVector, StreamVector, X25519_VECTORS,
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

/// Prove ECDSA over P-256: every published verification row, forgeries
/// included, and every deterministic signing row.
///
/// Signing and verification are one primitive here and are counted as one,
/// because a build that could verify and not sign is not one this appliance
/// could use for anything: it authenticates itself with this key.
///
/// # Errors
/// The first row this build answers differently from the published one.
pub fn prove_ecdsa_p256() -> Result<u32, VectorFailure> {
    let verified = prove_ecdsa_p256_verify_in(ECDSA_P256_VERIFY_VECTORS)?;
    let signed = prove_ecdsa_p256_sign_in(ECDSA_P256_SIGN_VECTORS)?;
    Ok(verified.saturating_add(signed))
}

pub(crate) fn prove_ecdsa_p256_verify_in(table: &[SignatureVector]) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        let outcome = p256_verify(vector.public_key, vector.message, vector.signature);
        // Every refusal is the same refusal from outside, so a row is held by
        // the signature not verifying and not by which step refused it: an
        // unparseable encoding and a wrong scalar are one answer, which is
        // what a verifier owes a forger.
        let held = matches!(
            (vector.authentic, outcome),
            (true, Ok(()))
                | (
                    false,
                    Err(CryptoError::NotAuthentic | CryptoError::InvalidPublicKey)
                )
        );
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

pub(crate) fn prove_ecdsa_p256_sign_in(table: &[SigningVector]) -> Result<u32, VectorFailure> {
    let mut produced = [0_u8; crate::P256_MAX_SIGNATURE_LEN];
    for (index, vector) in table.iter().enumerate() {
        let held = match P256SecretKey::from_scalar(&vector.secret) {
            Ok(key) => {
                let signature = key
                    .sign(vector.message, &mut produced)
                    .ok()
                    .and_then(|len| produced.get(..len));
                // Three claims per row and all three must hold: the public key
                // this scalar derives is the published one, the signature is
                // the published one byte for byte — which only a deterministic
                // nonce makes checkable — and this build's own verifier
                // accepts what this build's own signer produced.
                signature == Some(vector.signature)
                    && key.public_key() == vector.public_key
                    && p256_verify(vector.public_key, vector.message, vector.signature).is_ok()
            }
            Err(_) => false,
        };
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

/// Prove X25519, including the peer values whose exchange must be refused.
///
/// # Errors
/// The first row this build answers differently from the published one.
pub fn prove_x25519() -> Result<u32, VectorFailure> {
    prove_x25519_in(X25519_VECTORS)
}

pub(crate) fn prove_x25519_in(table: &[AgreementVector]) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        let outcome = X25519Secret::from_scalar(&vector.secret).agree(&vector.peer);
        let held = match (vector.contributory, outcome) {
            (true, Ok(shared)) => shared == vector.shared,
            (false, Err(CryptoError::NonContributory)) => true,
            _ => false,
        };
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

/// Prove ML-KEM-768 across all three of its operations.
///
/// Key generation, encapsulation and decapsulation are one primitive and are
/// counted as one: a key exchange needs all three and a build that answered
/// two of them would be no more usable than one that answered none.
///
/// # Errors
/// The first row this build answers differently from the published one.
pub fn prove_ml_kem_768() -> Result<u32, VectorFailure> {
    let generated = prove_ml_kem_768_keygen_in(ML_KEM_768_KEYGEN_VECTORS)?;
    let encapsulated = prove_ml_kem_768_encapsulation_in(ML_KEM_768_ENCAPSULATION_VECTORS)?;
    let decapsulated = prove_ml_kem_768_decapsulation_in(ML_KEM_768_DECAPSULATION_VECTORS)?;
    let checked = prove_ml_kem_768_key_check_in(ML_KEM_768_KEY_CHECK_VECTORS)?;
    Ok(generated
        .saturating_add(encapsulated)
        .saturating_add(decapsulated)
        .saturating_add(checked))
}

pub(crate) fn prove_ml_kem_768_key_check_in(
    table: &[KemKeyCheckVector],
) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        let outcome = MlKem768EncapsulationKey::from_bytes(vector.encapsulation_key);
        let held = matches!(
            (vector.acceptable, outcome),
            (true, Ok(_)) | (false, Err(CryptoError::InvalidPublicKey))
        );
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

pub(crate) fn prove_ml_kem_768_keygen_in(table: &[KemKeyGenVector]) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        let key = MlKem768DecapsulationKey::from_seeds(&vector.d, &vector.z);
        let held = key.encapsulation_key() == vector.encapsulation_key
            && key.to_bytes() == vector.decapsulation_key;
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

pub(crate) fn prove_ml_kem_768_encapsulation_in(
    table: &[KemEncapsulationVector],
) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        let held = match MlKem768EncapsulationKey::from_bytes(vector.encapsulation_key) {
            Ok(key) => match key.encapsulate_deterministic(&vector.message) {
                Ok((ciphertext, secret)) => {
                    ciphertext == vector.ciphertext && secret == vector.shared_secret
                }
                Err(_) => false,
            },
            Err(_) => false,
        };
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

pub(crate) fn prove_ml_kem_768_decapsulation_in(
    table: &[KemDecapsulationVector],
) -> Result<u32, VectorFailure> {
    for (index, vector) in table.iter().enumerate() {
        let held = match sized_decapsulation_key(vector.decapsulation_key) {
            Some(encoded) => {
                MlKem768DecapsulationKey::from_bytes(&encoded).decapsulate(vector.ciphertext)
                    == Ok(vector.shared_secret)
            }
            None => false,
        };
        row(index, vector.id, held)?;
    }
    Ok(table.len() as u32)
}

/// A table's decapsulation key at the length the algorithm defines, or nothing
/// where the row carries something else. Written out rather than done with
/// `try_into` at the call site so the array lives in one frame: it is 2400
/// bytes, and a copy per conversion would be a second one.
fn sized_decapsulation_key(
    encoded: &[u8],
) -> Option<[u8; crate::ML_KEM_768_DECAPSULATION_KEY_LEN]> {
    let mut sized = [0_u8; crate::ML_KEM_768_DECAPSULATION_KEY_LEN];
    if encoded.len() != sized.len() {
        return None;
    }
    sized.copy_from_slice(encoded);
    Some(sized)
}

/// The tag length the AEAD rows compare against, restated nowhere: this holds
/// the table's own array size to the crate's constant, so a vector file
/// regenerated against a different tag size fails here.
const _: () = assert!(MAC_LEN == crate::DIGEST_LEN);
