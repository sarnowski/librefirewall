use std::sync::Mutex;

use proptest::prelude::*;

use crate::{
    Aes256Gcm, ChaCha20Poly1305, CryptoError, DIGEST_LEN, Drbg, KEY_LEN, MAC_LEN, MAX_DERIVED_LEN,
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_DECAPSULATION_KEY_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN,
    MlKem768DecapsulationKey, MlKem768EncapsulationKey, NONCE_LEN, P256_MAX_SIGNATURE_LEN,
    P256_PUBLIC_LEN, P256SecretKey, RESEED_INTERVAL, SEED_LEN, Sha256, TAG_LEN, X25519Secret,
    hkdf_expand, hkdf_extract, hmac_sha256, hmac_sha256_verify, p256_verify, prove_aes_256_gcm,
    prove_chacha20, prove_chacha20_poly1305, prove_drbg, prove_ecdsa_p256, prove_hkdf_sha256,
    prove_hmac_sha256, prove_ml_kem_768, prove_sha256, prove_x25519, sha256,
    vectors::{
        AES_256_GCM_VECTORS, CHACHA20_POLY1305_VECTORS, CHACHA20_STREAM_VECTORS, DRBG_VECTORS,
        ECDSA_P256_SIGN_VECTORS, ECDSA_P256_VERIFY_VECTORS, HKDF_SHA256_VECTORS,
        HMAC_SHA256_VECTORS, ML_KEM_768_DECAPSULATION_VECTORS, ML_KEM_768_ENCAPSULATION_VECTORS,
        ML_KEM_768_KEY_CHECK_VECTORS, ML_KEM_768_KEYGEN_VECTORS, SHA256_VECTORS, X25519_VECTORS,
    },
};

// ---------------------------------------------------------------------------
// The published vectors, which are the whole of the correctness claim
// ---------------------------------------------------------------------------

/// The same ten runs the cryptography domain makes at bring-up, here on the
/// host. Both must pass and neither substitutes for the other: this one proves
/// the code, the domain's proves the instructions the code was compiled to.
#[test]
fn every_published_vector_answers_on_the_host() {
    type Run = fn() -> Result<u32, crate::VectorFailure>;
    let ml_kem_rows = ML_KEM_768_KEYGEN_VECTORS.len()
        + ML_KEM_768_ENCAPSULATION_VECTORS.len()
        + ML_KEM_768_DECAPSULATION_VECTORS.len()
        + ML_KEM_768_KEY_CHECK_VECTORS.len();
    let runs: [(&str, Run, usize); 10] = [
        ("sha-256", prove_sha256, SHA256_VECTORS.len()),
        ("hmac-sha-256", prove_hmac_sha256, HMAC_SHA256_VECTORS.len()),
        ("hkdf-sha-256", prove_hkdf_sha256, HKDF_SHA256_VECTORS.len()),
        ("chacha20", prove_chacha20, CHACHA20_STREAM_VECTORS.len()),
        (
            "chacha20-poly1305",
            prove_chacha20_poly1305,
            CHACHA20_POLY1305_VECTORS.len(),
        ),
        ("aes-256-gcm", prove_aes_256_gcm, AES_256_GCM_VECTORS.len()),
        ("chacha20-drbg", prove_drbg, DRBG_VECTORS.len()),
        (
            "ecdsa-p256",
            prove_ecdsa_p256,
            ECDSA_P256_VERIFY_VECTORS.len() + ECDSA_P256_SIGN_VECTORS.len(),
        ),
        ("x25519", prove_x25519, X25519_VECTORS.len()),
        ("ml-kem-768", prove_ml_kem_768, ml_kem_rows),
    ];
    let mut total = 0;
    for (primitive, run, rows) in runs {
        let proved = run().unwrap_or_else(|failure| {
            panic!(
                "{primitive} disagreed with published row {}",
                failure.vector
            )
        });
        assert_eq!(proved as usize, rows, "{primitive} skipped a row");
        assert!(rows > 0, "{primitive} has no rows, so it proves nothing");
        total += rows;
    }
    assert_eq!(total, 154, "the committed vector corpus changed size");
}

/// A table that carried only accepting rows would prove a verifier that always
/// says yes. Both authenticated constructions and the MAC carry forgeries, and
/// this is what keeps them there.
#[test]
fn every_authenticating_table_carries_forgeries_to_refuse() {
    let forged = |authentic: &[bool]| authentic.iter().filter(|held| !**held).count();
    let mac: Vec<bool> = HMAC_SHA256_VECTORS.iter().map(|v| v.authentic).collect();
    let gcm: Vec<bool> = AES_256_GCM_VECTORS.iter().map(|v| v.authentic).collect();
    let chacha: Vec<bool> = CHACHA20_POLY1305_VECTORS
        .iter()
        .map(|v| v.authentic)
        .collect();
    assert!(forged(&mac) >= 4, "hmac carries too few forgeries");
    assert!(forged(&gcm) >= 4, "aes-gcm carries too few forgeries");
    assert!(forged(&chacha) >= 4, "chacha carries too few forgeries");

    // The asymmetric tables carry the same obligation, in the shape each of
    // them refuses in: a signature that must not verify, a key exchange whose
    // result the peer alone fixed, and an encapsulation key the decode must
    // reject.
    let signatures: Vec<bool> = ECDSA_P256_VERIFY_VECTORS
        .iter()
        .map(|v| v.authentic)
        .collect();
    let exchanges: Vec<bool> = X25519_VECTORS.iter().map(|v| v.contributory).collect();
    let keys: Vec<bool> = ML_KEM_768_KEY_CHECK_VECTORS
        .iter()
        .map(|v| v.acceptable)
        .collect();
    assert!(forged(&signatures) >= 8, "ecdsa carries too few forgeries");
    assert!(
        forged(&exchanges) >= 4,
        "x25519 carries too few refusable exchanges"
    );
    assert!(
        forged(&keys) >= 2,
        "ml-kem carries too few refusable encapsulation keys"
    );
}

/// Every row names the published case it came from, so a failure on a booted
/// node can be traced to a line in a NIST or Wycheproof file.
#[test]
fn every_vector_carries_its_provenance() {
    let ids = SHA256_VECTORS
        .iter()
        .map(|v| v.id)
        .chain(HMAC_SHA256_VECTORS.iter().map(|v| v.id))
        .chain(HKDF_SHA256_VECTORS.iter().map(|v| v.id))
        .chain(CHACHA20_STREAM_VECTORS.iter().map(|v| v.id))
        .chain(CHACHA20_POLY1305_VECTORS.iter().map(|v| v.id))
        .chain(AES_256_GCM_VECTORS.iter().map(|v| v.id))
        .chain(DRBG_VECTORS.iter().map(|v| v.id))
        .chain(ECDSA_P256_VERIFY_VECTORS.iter().map(|v| v.id))
        .chain(ECDSA_P256_SIGN_VECTORS.iter().map(|v| v.id))
        .chain(X25519_VECTORS.iter().map(|v| v.id))
        .chain(ML_KEM_768_KEYGEN_VECTORS.iter().map(|v| v.id))
        .chain(ML_KEM_768_ENCAPSULATION_VECTORS.iter().map(|v| v.id))
        .chain(ML_KEM_768_DECAPSULATION_VECTORS.iter().map(|v| v.id))
        .chain(ML_KEM_768_KEY_CHECK_VECTORS.iter().map(|v| v.id));
    for id in ids {
        assert!(!id.is_empty(), "a vector carries no identifier");
        assert!(
            id.starts_with("cavp-")
                || id.starts_with("wycheproof-")
                || id.starts_with("rfc8439-")
                || id.starts_with("rfc6979-")
                || id.starts_with("acvp-")
                || matches!(id, "zero-seed" | "counting-seed" | "ones-seed"),
            "{id} names no published source"
        );
    }
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

#[test]
fn the_streaming_digest_agrees_with_the_contiguous_one_at_every_split() {
    let message: Vec<u8> = (0..=255_u16).map(|b| b as u8).collect();
    let want = sha256(&message);
    for split in 0..message.len() {
        let mut hasher = Sha256::new();
        hasher.update(&message[..split]);
        hasher.update(&message[split..]);
        assert_eq!(hasher.finish(), want, "split at {split}");
    }
}

#[test]
fn a_default_hasher_is_a_new_one() {
    assert_eq!(Sha256::default().finish(), sha256(&[]));
    assert_eq!(sha256(&[]).len(), DIGEST_LEN);
}

// ---------------------------------------------------------------------------
// HMAC-SHA-256
// ---------------------------------------------------------------------------

/// HMAC's key preparation is the one place a length is not a type here, and
/// its contract is that every length has an answer. This is the enforcer test
/// the fallible constructor's refusal path is documented against.
#[test]
fn every_key_length_across_the_hash_block_boundary_is_accepted() {
    for length in 0_usize..=256 {
        let key = vec![0xA5_u8; length];
        let tag = hmac_sha256(&key, b"message").expect("hmac accepts every key length");
        assert_eq!(tag.len(), MAC_LEN);
        hmac_sha256_verify(&key, b"message", &tag).expect("its own tag verifies");
    }
}

#[test]
fn a_flipped_bit_anywhere_in_a_tag_is_refused() {
    let tag = hmac_sha256(b"key", b"message").expect("a tag");
    for byte in 0..MAC_LEN {
        for bit in 0..8 {
            let mut forged = tag;
            forged[byte] ^= 1 << bit;
            assert_eq!(
                hmac_sha256_verify(b"key", b"message", &forged),
                Err(CryptoError::NotAuthentic),
                "byte {byte} bit {bit}"
            );
        }
    }
}

#[test]
fn a_tag_under_another_key_or_over_another_message_is_refused() {
    let tag = hmac_sha256(b"key", b"message").expect("a tag");
    assert_eq!(
        hmac_sha256_verify(b"keys", b"message", &tag),
        Err(CryptoError::NotAuthentic)
    );
    assert_eq!(
        hmac_sha256_verify(b"key", b"messages", &tag),
        Err(CryptoError::NotAuthentic)
    );
}

// ---------------------------------------------------------------------------
// HKDF-SHA-256
// ---------------------------------------------------------------------------

#[test]
fn hkdf_expand_refuses_beyond_the_construction_limit() {
    let prk = hkdf_extract(b"salt", b"ikm");
    let mut out = vec![0_u8; MAX_DERIVED_LEN + 1];
    assert_eq!(
        hkdf_expand(&prk, b"info", &mut out),
        Err(CryptoError::DerivedKeyTooLong {
            requested: MAX_DERIVED_LEN + 1
        })
    );
    assert!(
        out.iter().all(|byte| *byte == 0),
        "a refused expand wrote into the buffer"
    );
    let mut edge = vec![0_u8; MAX_DERIVED_LEN];
    hkdf_expand(&prk, b"info", &mut edge).expect("the limit itself is derivable");
    assert!(edge.iter().any(|byte| *byte != 0));
}

#[test]
fn hkdf_binds_its_output_to_every_input_it_is_given() {
    let mut base = [0_u8; 32];
    hkdf_expand(&hkdf_extract(b"salt", b"ikm"), b"info", &mut base).expect("derivable");
    for (salt, ikm, info) in [
        (&b"salts"[..], &b"ikm"[..], &b"info"[..]),
        (b"salt", b"ikms", b"info"),
        (b"salt", b"ikm", b"infos"),
        (b"", b"ikm", b"info"),
        (b"salt", b"ikm", b""),
    ] {
        let mut other = [0_u8; 32];
        hkdf_expand(&hkdf_extract(salt, ikm), info, &mut other).expect("derivable");
        assert_ne!(other, base, "a changed input produced the same key");
    }
}

#[test]
fn a_zero_length_derivation_is_allowed_and_writes_nothing() {
    let prk = hkdf_extract(b"salt", b"ikm");
    let mut empty: [u8; 0] = [];
    hkdf_expand(&prk, b"info", &mut empty).expect("zero bytes is derivable");
}

// ---------------------------------------------------------------------------
// The two AEADs
// ---------------------------------------------------------------------------

/// The properties are the AEAD contract's, so both constructions are held to
/// exactly the same ones rather than to two lists that could drift apart.
macro_rules! aead_suite {
    ($module:ident, $cipher:ty) => {
        mod $module {
            use super::*;

            fn cipher() -> $cipher {
                <$cipher>::new(&[0x42; KEY_LEN])
            }

            #[test]
            fn a_sealed_message_opens_back_to_itself() {
                for length in [0_usize, 1, 15, 16, 17, 63, 64, 65, 128] {
                    let plaintext: Vec<u8> = (0..length).map(|at| at as u8).collect();
                    let mut buffer = plaintext.clone();
                    let tag = cipher()
                        .seal(&[7; NONCE_LEN], b"aad", &mut buffer)
                        .expect("sealable");
                    assert_eq!(tag.len(), TAG_LEN);
                    if length > 0 {
                        assert_ne!(buffer, plaintext, "the buffer was left in the clear");
                    }
                    cipher()
                        .open(&[7; NONCE_LEN], b"aad", &mut buffer, &tag)
                        .expect("openable");
                    assert_eq!(buffer, plaintext);
                }
            }

            #[test]
            fn a_flipped_bit_in_the_tag_is_refused() {
                let mut buffer = *b"payload";
                let tag = cipher()
                    .seal(&[7; NONCE_LEN], b"aad", &mut buffer)
                    .expect("sealable");
                for byte in 0..TAG_LEN {
                    let mut forged = tag;
                    forged[byte] ^= 0x01;
                    assert_eq!(
                        cipher().open(&[7; NONCE_LEN], b"aad", &mut buffer.clone(), &forged),
                        Err(CryptoError::NotAuthentic),
                        "tag byte {byte}"
                    );
                }
            }

            #[test]
            fn a_changed_ciphertext_nonce_or_associated_data_is_refused() {
                let mut sealed = *b"payload";
                let tag = cipher()
                    .seal(&[7; NONCE_LEN], b"aad", &mut sealed)
                    .expect("sealable");

                let mut flipped = sealed;
                flipped[0] ^= 0x80;
                assert_eq!(
                    cipher().open(&[7; NONCE_LEN], b"aad", &mut flipped, &tag),
                    Err(CryptoError::NotAuthentic)
                );

                let mut other_nonce = sealed;
                assert_eq!(
                    cipher().open(&[8; NONCE_LEN], b"aad", &mut other_nonce, &tag),
                    Err(CryptoError::NotAuthentic)
                );

                let mut other_aad = sealed;
                assert_eq!(
                    cipher().open(&[7; NONCE_LEN], b"aaD", &mut other_aad, &tag),
                    Err(CryptoError::NotAuthentic)
                );

                let mut no_aad = sealed;
                assert_eq!(
                    cipher().open(&[7; NONCE_LEN], b"", &mut no_aad, &tag),
                    Err(CryptoError::NotAuthentic)
                );
            }

            #[test]
            fn another_key_cannot_open_what_this_one_sealed() {
                let mut buffer = *b"payload";
                let tag = cipher()
                    .seal(&[7; NONCE_LEN], b"", &mut buffer)
                    .expect("sealable");
                let other = <$cipher>::new(&[0x43; KEY_LEN]);
                assert_eq!(
                    other.open(&[7; NONCE_LEN], b"", &mut buffer, &tag),
                    Err(CryptoError::NotAuthentic)
                );
            }

            proptest! {
                /// Arbitrary input never panics, and what seals opens.
                #[test]
                fn arbitrary_messages_round_trip(
                    plaintext in prop::collection::vec(any::<u8>(), 0..512),
                    associated_data in prop::collection::vec(any::<u8>(), 0..64),
                    key: [u8; KEY_LEN],
                    nonce: [u8; NONCE_LEN],
                ) {
                    let cipher = <$cipher>::new(&key);
                    let mut buffer = plaintext.clone();
                    let tag = cipher.seal(&nonce, &associated_data, &mut buffer)
                        .expect("sealable");
                    cipher.open(&nonce, &associated_data, &mut buffer, &tag)
                        .expect("openable");
                    prop_assert_eq!(buffer, plaintext);
                }

                /// An arbitrary tag over arbitrary bytes is refused, not read.
                #[test]
                fn an_arbitrary_tag_is_refused(
                    ciphertext in prop::collection::vec(any::<u8>(), 0..256),
                    key: [u8; KEY_LEN],
                    nonce: [u8; NONCE_LEN],
                    tag: [u8; TAG_LEN],
                ) {
                    let mut buffer = ciphertext;
                    let refused = <$cipher>::new(&key)
                        .open(&nonce, b"", &mut buffer, &tag);
                    // A forged tag that happens to authenticate is a 2^-128
                    // event; what is asserted is that the only other answer is
                    // the typed refusal, never a panic and never a partial
                    // decrypt reported as success.
                    prop_assert!(
                        refused.is_ok() || refused == Err(CryptoError::NotAuthentic)
                    );
                }
            }
        }
    };
}

aead_suite!(chacha20_poly1305, ChaCha20Poly1305);
aead_suite!(aes_256_gcm, Aes256Gcm);

// ---------------------------------------------------------------------------
// The generator
// ---------------------------------------------------------------------------

fn seed(fill: u8) -> [u8; SEED_LEN] {
    [fill; SEED_LEN]
}

#[test]
fn the_same_seed_generates_the_same_bytes_and_a_different_one_does_not() {
    let mut a = [0_u8; 64];
    let mut b = [0_u8; 64];
    Drbg::from_seed(&seed(1)).fill(&mut a);
    Drbg::from_seed(&seed(1)).fill(&mut b);
    assert_eq!(a, b, "the generator is not deterministic in its seed");
    let mut c = [0_u8; 64];
    Drbg::from_seed(&seed(2)).fill(&mut c);
    assert_ne!(a, c, "two seeds produced one stream");
}

#[test]
fn successive_draws_never_repeat_and_never_return_the_key_they_kept() {
    let mut generator = Drbg::from_seed(&seed(3));
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for _ in 0..64 {
        let mut draw = [0_u8; 32];
        generator.fill(&mut draw);
        assert!(!seen.contains(&draw), "a draw repeated an earlier one");
        assert_ne!(draw, [0_u8; 32], "a draw was all zeroes");
        seen.push(draw);
    }
    // The first 32 bytes of the seeded keystream are the next key and are
    // never emitted. Recomputing that keystream here is what proves it: the
    // key must appear nowhere in what the generator handed back.
    let mut keystream = [0_u8; 64];
    {
        use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
        let mut cipher =
            chacha20::ChaCha20::new(&[3_u8; KEY_LEN].into(), &[3_u8; NONCE_LEN].into());
        cipher.apply_keystream(&mut keystream);
    }
    let withheld: [u8; 32] = keystream[..32].try_into().expect("32 bytes");
    assert!(
        !seen.contains(&withheld),
        "the generator emitted the key it had kept"
    );
    assert_eq!(
        seen[0],
        keystream[32..64],
        "the first draw is not the keystream past the key"
    );
}

#[test]
fn a_draw_longer_than_one_pass_is_served_and_rekeys_between_passes() {
    let mut generator = Drbg::from_seed(&seed(4));
    let mut long = vec![0_u8; 1024];
    generator.fill(&mut long);
    assert!(long.iter().any(|byte| *byte != 0));
    // Each 256-byte pass is keyed afresh, so no two passes are the same bytes
    // — which is what a counter that failed to advance, or a key that failed
    // to rotate, would produce.
    let passes: Vec<&[u8]> = long.chunks(256).collect();
    for (at, pass) in passes.iter().enumerate() {
        for other in &passes[at + 1..] {
            assert_ne!(pass, other, "two passes produced identical bytes");
        }
    }
}

#[test]
fn a_zero_length_draw_is_allowed() {
    let mut generator = Drbg::from_seed(&seed(5));
    let mut empty: [u8; 0] = [];
    generator.fill(&mut empty);
}

#[test]
fn a_reseed_becomes_due_only_after_the_interval() {
    let mut generator = Drbg::from_seed(&seed(6));
    assert!(!generator.reseed_due());
    let mut draw = [0_u8; 1];
    for _ in 0..16 {
        generator.fill(&mut draw);
    }
    assert!(
        !generator.reseed_due(),
        "the interval is not a handful of draws"
    );
    const {
        assert!(
            RESEED_INTERVAL > 1024,
            "the interval is too short to be a backstop"
        )
    };
}

proptest! {
    /// Arbitrary seeds and arbitrary lengths: never a panic, and the stream is
    /// a function of the seed alone.
    #[test]
    fn arbitrary_seeds_and_lengths_are_deterministic(
        seed: [u8; SEED_LEN],
        length in 0_usize..1024,
    ) {
        let mut first = vec![0_u8; length];
        let mut again = vec![0_u8; length];
        Drbg::from_seed(&seed).fill(&mut first);
        Drbg::from_seed(&seed).fill(&mut again);
        prop_assert_eq!(first, again);
    }
}

// ---------------------------------------------------------------------------
// The typed refusals
// ---------------------------------------------------------------------------

#[test]
fn every_refusal_says_what_was_refused() {
    let rendered = |error: CryptoError| format!("{error}");
    assert!(rendered(CryptoError::KeyRejected { length: 7 }).contains("7-byte key"));
    assert!(
        rendered(CryptoError::DerivedKeyTooLong { requested: 9000 })
            .contains(&MAX_DERIVED_LEN.to_string())
    );
    assert!(rendered(CryptoError::MessageTooLong { bytes: 5 }).contains("5-byte message"));
    assert!(rendered(CryptoError::NotAuthentic).contains("did not authenticate"));
}

// ---------------------------------------------------------------------------
// What the provers answer when a row does not hold
// ---------------------------------------------------------------------------

/// Every committed row passes, so the only way to reach the answer a prover
/// gives when one does not is to hand it a row that cannot. Each table below
/// carries one deliberately wrong value; the run must stop on it and name it,
/// because a prover that reported success on a corrupted table would report
/// success on a broken cipher.
mod a_corrupted_table {
    use crate::{
        ML_KEM_768_DECAPSULATION_KEY_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN,
        proof::{
            prove_aes_256_gcm_in, prove_chacha20_in, prove_chacha20_poly1305_in, prove_drbg_in,
            prove_ecdsa_p256_sign_in, prove_ecdsa_p256_verify_in, prove_hkdf_sha256_in,
            prove_hmac_sha256_in, prove_ml_kem_768_decapsulation_in,
            prove_ml_kem_768_encapsulation_in, prove_ml_kem_768_key_check_in,
            prove_ml_kem_768_keygen_in, prove_sha256_in, prove_x25519_in,
        },
        vectors::{
            AES_256_GCM_VECTORS, AeadVector, AgreementVector, CHACHA20_POLY1305_VECTORS,
            DrbgVector, ECDSA_P256_SIGN_VECTORS, ECDSA_P256_VERIFY_VECTORS, HashVector, KdfVector,
            KemDecapsulationVector, KemEncapsulationVector, KemKeyCheckVector, KemKeyGenVector,
            ML_KEM_768_ENCAPSULATION_VECTORS, ML_KEM_768_KEYGEN_VECTORS, MacVector,
            SignatureVector, SigningVector, StreamVector, X25519_VECTORS,
        },
    };

    #[test]
    fn a_wrong_digest_is_named() {
        let failure = prove_sha256_in(&[HashVector {
            id: "deliberately-wrong",
            message: b"",
            digest: [0; 32],
        }])
        .expect_err("a wrong digest");
        assert_eq!(failure.index, 0);
        assert_eq!(failure.vector, "deliberately-wrong");
    }

    #[test]
    fn a_wrong_tag_is_named_whichever_way_the_row_claims_it() {
        // Claimed authentic and is not: the verifier refuses and the row fails.
        let forged = prove_hmac_sha256_in(&[MacVector {
            id: "claimed-authentic",
            key: b"key",
            message: b"message",
            tag: [0; 32],
            authentic: true,
        }])
        .expect_err("a forged tag claimed authentic");
        assert_eq!(forged.vector, "claimed-authentic");

        // Claimed a forgery and is in fact the authentic tag: the row fails
        // too, because otherwise a table could "prove" a verifier by handing
        // it tags it already agrees with.
        let genuine = crate::hmac_sha256(b"key", b"message").expect("a tag");
        let mislabelled = prove_hmac_sha256_in(&[MacVector {
            id: "claimed-forged",
            key: b"key",
            message: b"message",
            tag: genuine,
            authentic: false,
        }])
        .expect_err("an authentic tag claimed forged");
        assert_eq!(mislabelled.vector, "claimed-forged");
    }

    #[test]
    fn a_wrong_derived_key_is_named() {
        let failure = prove_hkdf_sha256_in(&[KdfVector {
            id: "deliberately-wrong",
            ikm: b"ikm",
            salt: b"salt",
            info: b"info",
            okm: &[0; 32],
        }])
        .expect_err("a wrong derived key");
        assert_eq!(failure.vector, "deliberately-wrong");
    }

    #[test]
    fn a_wrong_keystream_is_named() {
        let failure = prove_chacha20_in(&[StreamVector {
            id: "deliberately-wrong",
            key: [0; 32],
            nonce: [0; 12],
            counter: 0,
            keystream: &[0; 16],
        }])
        .expect_err("a wrong keystream");
        assert_eq!(failure.vector, "deliberately-wrong");
    }

    #[test]
    fn a_wrong_generated_stream_is_named() {
        let failure = prove_drbg_in(&[DrbgVector {
            id: "deliberately-wrong",
            key: [0; 32],
            nonce: [0; 12],
            first_output: &[0; 32],
        }])
        .expect_err("a wrong draw");
        assert_eq!(failure.vector, "deliberately-wrong");
    }

    /// One shape per way an authenticated-encryption row can be wrong, for
    /// both constructions: a ciphertext that does not seal to what it claims,
    /// a forgery that in fact authenticates, and a row wider than the scratch
    /// buffer — which is a table the build should have rejected and so must
    /// fail rather than be skipped.
    #[test]
    fn a_wrong_authenticated_encryption_row_is_named() {
        let genuine = &AES_256_GCM_VECTORS[0];
        let chacha_genuine = &CHACHA20_POLY1305_VECTORS[0];
        let cases: [(&str, AeadVector); 3] = [
            (
                "wrong-ciphertext",
                AeadVector {
                    id: "wrong-ciphertext",
                    key: genuine.key,
                    nonce: genuine.nonce,
                    associated_data: genuine.associated_data,
                    plaintext: &[0; 16],
                    ciphertext: &[0; 16],
                    tag: genuine.tag,
                    authentic: true,
                },
            ),
            (
                "forgery-that-authenticates",
                AeadVector {
                    id: "forgery-that-authenticates",
                    key: chacha_genuine.key,
                    nonce: chacha_genuine.nonce,
                    associated_data: chacha_genuine.associated_data,
                    plaintext: &[],
                    ciphertext: chacha_genuine.ciphertext,
                    tag: chacha_genuine.tag,
                    authentic: false,
                },
            ),
            (
                "wider-than-the-scratch-buffer",
                AeadVector {
                    id: "wider-than-the-scratch-buffer",
                    key: [0; 32],
                    nonce: [0; 12],
                    associated_data: &[],
                    plaintext: &[0; 1024],
                    ciphertext: &[0; 1024],
                    tag: [0; 16],
                    authentic: true,
                },
            ),
        ];
        for (name, vector) in cases {
            let table = [vector];
            let by_gcm = prove_aes_256_gcm_in(&table);
            let by_chacha = prove_chacha20_poly1305_in(&table);
            assert!(
                by_gcm.is_err() || by_chacha.is_err(),
                "{name} was accepted by both constructions"
            );
        }
    }

    /// Both directions a signature row can be wrong, and the three ways a
    /// signing row can be: a wrong signature, a wrong derived public key, and
    /// a scalar that is no key at all.
    #[test]
    fn a_wrong_signature_row_is_named() {
        let genuine = &ECDSA_P256_VERIFY_VECTORS[0];
        let claimed_authentic = prove_ecdsa_p256_verify_in(&[SignatureVector {
            id: "claimed-authentic",
            public_key: genuine.public_key,
            message: b"a message this signature is not over",
            signature: genuine.signature,
            authentic: true,
        }])
        .expect_err("a signature over another message claimed authentic");
        assert_eq!(claimed_authentic.vector, "claimed-authentic");

        let claimed_forged = prove_ecdsa_p256_verify_in(&[SignatureVector {
            id: "claimed-forged",
            public_key: genuine.public_key,
            message: genuine.message,
            signature: genuine.signature,
            authentic: false,
        }])
        .expect_err("a valid signature claimed forged");
        assert_eq!(claimed_forged.vector, "claimed-forged");
    }

    #[test]
    fn a_wrong_signing_row_is_named() {
        let genuine = &ECDSA_P256_SIGN_VECTORS[0];
        let wrong_signature = prove_ecdsa_p256_sign_in(&[SigningVector {
            id: "wrong-signature",
            secret: genuine.secret,
            public_key: genuine.public_key,
            message: genuine.message,
            signature: &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        }])
        .expect_err("a signature this key does not produce");
        assert_eq!(wrong_signature.vector, "wrong-signature");

        let wrong_public = prove_ecdsa_p256_sign_in(&[SigningVector {
            id: "wrong-public-key",
            secret: genuine.secret,
            public_key: &[0x04; 65],
            message: genuine.message,
            signature: genuine.signature,
        }])
        .expect_err("a public key this scalar does not derive");
        assert_eq!(wrong_public.vector, "wrong-public-key");

        let no_key = prove_ecdsa_p256_sign_in(&[SigningVector {
            id: "not-a-scalar",
            secret: [0; 32],
            public_key: genuine.public_key,
            message: genuine.message,
            signature: genuine.signature,
        }])
        .expect_err("zero is not a private key");
        assert_eq!(no_key.vector, "not-a-scalar");
    }

    #[test]
    fn a_wrong_agreement_row_is_named() {
        let genuine = &X25519_VECTORS[0];
        let wrong_secret = prove_x25519_in(&[AgreementVector {
            id: "wrong-shared-secret",
            secret: genuine.secret,
            peer: genuine.peer,
            shared: [0xaa; 32],
            contributory: true,
        }])
        .expect_err("a secret this exchange does not produce");
        assert_eq!(wrong_secret.vector, "wrong-shared-secret");

        let claimed_refusable = prove_x25519_in(&[AgreementVector {
            id: "claimed-refusable",
            secret: genuine.secret,
            peer: genuine.peer,
            shared: genuine.shared,
            contributory: false,
        }])
        .expect_err("an ordinary exchange claimed refusable");
        assert_eq!(claimed_refusable.vector, "claimed-refusable");
    }

    #[test]
    fn a_wrong_key_encapsulation_row_is_named() {
        let generated = &ML_KEM_768_KEYGEN_VECTORS[0];
        let wrong_key = prove_ml_kem_768_keygen_in(&[KemKeyGenVector {
            id: "wrong-generated-key",
            d: generated.d,
            z: generated.z,
            encapsulation_key: &[0; ML_KEM_768_ENCAPSULATION_KEY_LEN],
            decapsulation_key: generated.decapsulation_key,
        }])
        .expect_err("a key these seeds do not generate");
        assert_eq!(wrong_key.vector, "wrong-generated-key");

        let encapsulated = &ML_KEM_768_ENCAPSULATION_VECTORS[0];
        let wrong_ciphertext = prove_ml_kem_768_encapsulation_in(&[KemEncapsulationVector {
            id: "wrong-ciphertext",
            encapsulation_key: encapsulated.encapsulation_key,
            message: encapsulated.message,
            ciphertext: &[0; 8],
            shared_secret: encapsulated.shared_secret,
        }])
        .expect_err("a ciphertext this message does not produce");
        assert_eq!(wrong_ciphertext.vector, "wrong-ciphertext");

        let unusable_key = prove_ml_kem_768_encapsulation_in(&[KemEncapsulationVector {
            id: "unusable-encapsulation-key",
            encapsulation_key: &[0xff; ML_KEM_768_ENCAPSULATION_KEY_LEN],
            message: encapsulated.message,
            ciphertext: encapsulated.ciphertext,
            shared_secret: encapsulated.shared_secret,
        }])
        .expect_err("a key the decode refuses");
        assert_eq!(unusable_key.vector, "unusable-encapsulation-key");

        let wrong_secret = prove_ml_kem_768_decapsulation_in(&[KemDecapsulationVector {
            id: "wrong-decapsulated-secret",
            decapsulation_key: &[0; ML_KEM_768_DECAPSULATION_KEY_LEN],
            ciphertext: encapsulated.ciphertext,
            shared_secret: [0; 32],
        }])
        .expect_err("a secret this key does not derive");
        assert_eq!(wrong_secret.vector, "wrong-decapsulated-secret");

        let wrong_length = prove_ml_kem_768_decapsulation_in(&[KemDecapsulationVector {
            id: "wrong-key-length",
            decapsulation_key: &[0; 8],
            ciphertext: encapsulated.ciphertext,
            shared_secret: [0; 32],
        }])
        .expect_err("a decapsulation key of the wrong length");
        assert_eq!(wrong_length.vector, "wrong-key-length");

        let claimed_bad = prove_ml_kem_768_key_check_in(&[KemKeyCheckVector {
            id: "claimed-unacceptable",
            encapsulation_key: encapsulated.encapsulation_key,
            acceptable: false,
        }])
        .expect_err("a canonical key claimed unacceptable");
        assert_eq!(claimed_bad.vector, "claimed-unacceptable");

        let claimed_good = prove_ml_kem_768_key_check_in(&[KemKeyCheckVector {
            id: "claimed-acceptable",
            encapsulation_key: &[0xff; ML_KEM_768_ENCAPSULATION_KEY_LEN],
            acceptable: true,
        }])
        .expect_err("a non-canonical key claimed acceptable");
        assert_eq!(claimed_good.vector, "claimed-acceptable");
    }
}

/// The scratch buffer is derived from the tables, not chosen, so this holds
/// the derivation to a second walk written differently: a vector added past
/// it must fail the build rather than overflow a buffer on a booted node.
#[test]
fn the_scratch_buffer_is_wide_enough_for_every_committed_row() {
    let widest = crate::vectors::AES_256_GCM_VECTORS
        .iter()
        .chain(crate::vectors::CHACHA20_POLY1305_VECTORS)
        .map(|vector| vector.ciphertext.len())
        .chain(
            crate::vectors::CHACHA20_STREAM_VECTORS
                .iter()
                .map(|vector| vector.keystream.len()),
        )
        .chain(
            crate::vectors::HKDF_SHA256_VECTORS
                .iter()
                .map(|vector| vector.okm.len()),
        )
        .chain(
            crate::vectors::DRBG_VECTORS
                .iter()
                .map(|vector| vector.first_output.len()),
        )
        .max()
        .expect("the tables are not empty");
    assert_eq!(widest, crate::proof::widest_row(), "the two walks disagree");
    assert!(widest <= crate::proof::SCRATCH_LEN);
    assert!(
        widest * 2 > crate::proof::SCRATCH_LEN,
        "the scratch buffer is more than twice the widest row, so it is guessed rather than derived"
    );
}

#[test]
fn folding_raw_entropy_reaches_every_bit_of_the_seed() {
    let base = [0x11_u8; 256];
    let mut first = [0_u8; 64];
    Drbg::from_entropy(&base).fill(&mut first);
    // A single bit changed anywhere in the raw material must change the whole
    // draw: that is what makes the fold a fold rather than a slice, and it is
    // the property one degraded hardware draw among many depends on.
    for byte in [0_usize, 1, 127, 254, 255] {
        let mut altered = base;
        altered[byte] ^= 0x01;
        let mut other = [0_u8; 64];
        Drbg::from_entropy(&altered).fill(&mut other);
        assert_ne!(other, first, "a bit at {byte} did not reach the seed");
    }
    // Length is part of the input too, so raw material of a different size is
    // a different seeding even where it starts the same.
    let mut shorter = [0_u8; 64];
    Drbg::from_entropy(&base[..128]).fill(&mut shorter);
    assert_ne!(
        shorter,
        first[..64],
        "a shorter draw seeded the same generator"
    );
}

#[test]
fn an_entropy_fold_of_any_length_produces_a_generator_that_advances() {
    for length in [0_usize, 1, 32, 44, 255, 256, 1024] {
        let raw = vec![0x7C_u8; length];
        let mut generator = Drbg::from_entropy(&raw);
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        generator.fill(&mut first);
        generator.fill(&mut second);
        assert_ne!(first, second, "the generator did not advance at {length}");
        assert_ne!(
            first, [0_u8; 32],
            "the generator produced zeroes at {length}"
        );
    }
}

// ---------------------------------------------------------------------------
// ECDSA over P-256
// ---------------------------------------------------------------------------

/// The node's generator behind the shared-borrow interface every key
/// generation takes. On the appliance the protection domain supplies this; a
/// host test needs the same shape and reaches for the standard library's lock
/// to get it, which is a thing only a host test has.
struct TestEntropy(Mutex<Drbg>);

impl TestEntropy {
    fn new(fill: u8) -> Self {
        Self(Mutex::new(Drbg::from_seed(&seed(fill))))
    }
}

impl crate::Entropy for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        self.0
            .lock()
            .expect("no test panics holding this")
            .fill(out);
    }
}

#[test]
fn a_generated_key_signs_what_its_own_public_key_verifies() {
    let generator = TestEntropy::new(0x21);
    let key = P256SecretKey::generate(&generator).expect("a generator that generates");
    let public = key.public_key();
    assert_eq!(
        public[0], 0x04,
        "the point is not the uncompressed encoding"
    );
    let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
    let len = key
        .sign(b"the appliance authenticates itself", &mut signature)
        .expect("the buffer is the widest a signature can be");
    p256_verify(
        &public,
        b"the appliance authenticates itself",
        &signature[..len],
    )
    .expect("this build's verifier accepts this build's signature");
}

#[test]
fn two_generated_keys_differ_and_neither_verifies_the_other() {
    let generator = TestEntropy::new(0x22);
    let first = P256SecretKey::generate(&generator).expect("generates");
    let second = P256SecretKey::generate(&generator).expect("generates");
    assert_ne!(first.public_key(), second.public_key());
    let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
    let len = first.sign(b"one", &mut signature).expect("wide enough");
    assert_eq!(
        p256_verify(&second.public_key(), b"one", &signature[..len]),
        Err(CryptoError::NotAuthentic)
    );
}

#[test]
fn one_key_signs_one_message_the_same_way_every_time() {
    let key = P256SecretKey::from_scalar(&[0x33; 32]).expect("a scalar below the order");
    let mut first = [0_u8; P256_MAX_SIGNATURE_LEN];
    let mut second = [0_u8; P256_MAX_SIGNATURE_LEN];
    let a = key.sign(b"deterministic", &mut first).expect("wide enough");
    let b = key
        .sign(b"deterministic", &mut second)
        .expect("wide enough");
    assert_eq!(first[..a], second[..b]);
}

#[test]
fn a_scalar_outside_the_group_order_is_not_a_key() {
    // The order itself and zero: neither is a private key, and both are values
    // a corpus supplies deliberately.
    assert_eq!(
        P256SecretKey::from_scalar(&[0; 32]).err(),
        Some(CryptoError::InvalidSecretKey)
    );
    let order = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    assert_eq!(
        P256SecretKey::from_scalar(&order).err(),
        Some(CryptoError::InvalidSecretKey)
    );
    assert!(P256SecretKey::from_scalar(&[1; 32]).is_ok());
}

#[test]
fn a_signature_buffer_shorter_than_the_encoding_is_refused_and_names_the_length() {
    let key = P256SecretKey::from_scalar(&[0x44; 32]).expect("a scalar below the order");
    let mut wide = [0_u8; P256_MAX_SIGNATURE_LEN];
    let needed = key.sign(b"short", &mut wide).expect("wide enough");
    let mut narrow = [0_u8; 8];
    assert_eq!(
        key.sign(b"short", &mut narrow),
        Err(CryptoError::BufferTooSmall { needed })
    );
    assert!(
        narrow.iter().all(|byte| *byte == 0),
        "a refusal wrote bytes"
    );
}

#[test]
fn a_public_key_that_is_not_a_point_is_refused_before_the_signature_is_looked_at() {
    let key = P256SecretKey::from_scalar(&[0x55; 32]).expect("a scalar below the order");
    let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
    let len = key.sign(b"m", &mut signature).expect("wide enough");
    for wrong in [&[][..], &[0x04][..], &[0x04; P256_PUBLIC_LEN][..]] {
        assert_eq!(
            p256_verify(wrong, b"m", &signature[..len]),
            Err(CryptoError::InvalidPublicKey)
        );
    }
}

proptest! {
    /// Arbitrary bytes in either untrusted position answer no rather than
    /// panicking, whatever shape they have.
    #[test]
    fn arbitrary_public_keys_and_signatures_are_refused_and_never_panic(
        public in proptest::collection::vec(any::<u8>(), 0..80),
        signature in proptest::collection::vec(any::<u8>(), 0..80),
        message in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assert!(p256_verify(&public, &message, &signature).is_err());
    }

    /// A flipped bit anywhere in a signature stops it verifying.
    #[test]
    fn a_flipped_bit_anywhere_in_a_signature_is_refused(bit in 0_usize..8 * 64) {
        let key = P256SecretKey::from_scalar(&[0x66; 32]).expect("below the order");
        let public = key.public_key();
        let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
        let len = key.sign(b"flip", &mut signature).expect("wide enough");
        let at = bit / 8;
        prop_assume!(at < len);
        signature[at] ^= 1 << (bit % 8);
        prop_assert_eq!(
            p256_verify(&public, b"flip", &signature[..len]),
            Err(CryptoError::NotAuthentic)
        );
    }
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

#[test]
fn two_generated_scalars_agree_on_one_secret_from_either_side() {
    let generator = TestEntropy::new(0x71);
    let ours = X25519Secret::generate(&generator);
    let theirs = X25519Secret::generate(&generator);
    let here = ours
        .agree(&theirs.public_key())
        .expect("a generated public value is not small-order");
    let there = theirs
        .agree(&ours.public_key())
        .expect("a generated public value is not small-order");
    assert_eq!(here, there);
    assert_ne!(here, [0; 32], "a generated exchange produced no secret");
}

#[test]
fn a_small_order_public_value_is_refused_rather_than_keyed_from() {
    let ours = X25519Secret::from_scalar(&[0x77; 32]);
    // The identity and the order-two point: both force an all-zero result
    // whatever scalar they meet.
    for peer in [[0_u8; 32], {
        let mut point = [0_u8; 32];
        point[0] = 1;
        point
    }] {
        assert_eq!(ours.agree(&peer), Err(CryptoError::NonContributory));
    }
}

proptest! {
    /// Every 32-byte string is a scalar — the function clamps rather than
    /// rejects — so nothing here refuses on the scalar, and an exchange with a
    /// generated peer always produces a secret.
    #[test]
    fn arbitrary_scalars_produce_agreeing_secrets(
        ours in any::<[u8; 32]>(),
        theirs in any::<[u8; 32]>(),
    ) {
        let ours = X25519Secret::from_scalar(&ours);
        let theirs = X25519Secret::from_scalar(&theirs);
        prop_assert_eq!(
            ours.agree(&theirs.public_key()),
            theirs.agree(&ours.public_key())
        );
    }

    /// An arbitrary peer value never panics: it either agrees or is refused.
    #[test]
    fn an_arbitrary_peer_value_is_answered_and_never_panics(peer in any::<[u8; 32]>()) {
        let ours = X25519Secret::from_scalar(&[0x78; 32]);
        match ours.agree(&peer) {
            Ok(shared) => prop_assert_ne!(shared, [0; 32]),
            Err(error) => prop_assert_eq!(error, CryptoError::NonContributory),
        }
    }
}

// ---------------------------------------------------------------------------
// ML-KEM-768
// ---------------------------------------------------------------------------

#[test]
fn a_generated_key_pair_encapsulates_and_decapsulates_to_one_secret() {
    let generator = TestEntropy::new(0x91);
    let ours = MlKem768DecapsulationKey::generate(&generator);
    let published = ours.encapsulation_key();
    assert_eq!(published.len(), ML_KEM_768_ENCAPSULATION_KEY_LEN);
    let peer = MlKem768EncapsulationKey::from_bytes(&published)
        .expect("a generated key is canonically encoded");
    let (ciphertext, theirs) = peer
        .encapsulate(&generator)
        .expect("the adopted implementation encapsulates");
    assert_eq!(ciphertext.len(), ML_KEM_768_CIPHERTEXT_LEN);
    assert_eq!(
        ours.decapsulate(&ciphertext),
        Ok(theirs),
        "the two sides derived different secrets"
    );
}

#[test]
fn a_key_survives_its_own_encoding() {
    let generator = TestEntropy::new(0x92);
    let ours = MlKem768DecapsulationKey::generate(&generator);
    let encoded = ours.to_bytes();
    assert_eq!(encoded.len(), ML_KEM_768_DECAPSULATION_KEY_LEN);
    let rebuilt = MlKem768DecapsulationKey::from_bytes(&encoded);
    assert_eq!(rebuilt.encapsulation_key(), ours.encapsulation_key());
    let peer = MlKem768EncapsulationKey::from_bytes(&ours.encapsulation_key())
        .expect("canonically encoded");
    let (ciphertext, secret) = peer.encapsulate(&generator).expect("encapsulates");
    assert_eq!(rebuilt.decapsulate(&ciphertext), Ok(secret));
}

#[test]
fn the_same_seeds_generate_the_same_key_and_different_seeds_do_not() {
    let one = MlKem768DecapsulationKey::from_seeds(&[1; 32], &[2; 32]);
    let same = MlKem768DecapsulationKey::from_seeds(&[1; 32], &[2; 32]);
    let other = MlKem768DecapsulationKey::from_seeds(&[1; 32], &[3; 32]);
    assert_eq!(one.to_bytes(), same.to_bytes());
    assert_ne!(one.to_bytes(), other.to_bytes());
    // The rejection seed does not reach the public half, which is why the two
    // keys above share an encapsulation key and differ underneath it.
    assert_eq!(one.encapsulation_key(), other.encapsulation_key());
}

#[test]
fn a_modified_ciphertext_decapsulates_to_a_wrong_secret_rather_than_a_refusal() {
    let generator = TestEntropy::new(0x93);
    let ours = MlKem768DecapsulationKey::generate(&generator);
    let peer = MlKem768EncapsulationKey::from_bytes(&ours.encapsulation_key())
        .expect("canonically encoded");
    let (mut ciphertext, secret) = peer.encapsulate(&generator).expect("encapsulates");
    ciphertext[0] ^= 1;
    let answered = ours
        .decapsulate(&ciphertext)
        .expect("every well-sized ciphertext has an answer");
    // The implicit rejection is the algorithm's, and it is what stops an
    // attacker learning that a ciphertext was rejected at all.
    assert_ne!(answered, secret);
}

#[test]
fn a_ciphertext_of_the_wrong_length_is_refused_and_names_it() {
    let ours = MlKem768DecapsulationKey::from_seeds(&[4; 32], &[5; 32]);
    for bytes in [
        0_usize,
        1,
        ML_KEM_768_CIPHERTEXT_LEN - 1,
        ML_KEM_768_CIPHERTEXT_LEN + 1,
    ] {
        let ciphertext = vec![0_u8; bytes];
        assert_eq!(
            ours.decapsulate(&ciphertext),
            Err(CryptoError::InvalidCiphertext { bytes })
        );
    }
}

#[test]
fn an_encapsulation_key_of_the_wrong_length_or_shape_is_refused() {
    for bytes in [0_usize, 1, ML_KEM_768_ENCAPSULATION_KEY_LEN - 1] {
        assert_eq!(
            MlKem768EncapsulationKey::from_bytes(&vec![0_u8; bytes]).err(),
            Some(CryptoError::InvalidPublicKey)
        );
    }
    // Every packed coefficient set to 0xfff, which is above the modulus and so
    // re-encodes differently from what went in.
    let saturated = [0xff_u8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
    assert_eq!(
        MlKem768EncapsulationKey::from_bytes(&saturated).err(),
        Some(CryptoError::InvalidPublicKey)
    );
}
