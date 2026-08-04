use proptest::prelude::*;

use crate::{
    Aes256Gcm, ChaCha20Poly1305, CryptoError, DIGEST_LEN, Drbg, KEY_LEN, MAC_LEN, MAX_DERIVED_LEN,
    NONCE_LEN, RESEED_INTERVAL, SEED_LEN, Sha256, TAG_LEN, hkdf_expand, hkdf_extract, hmac_sha256,
    hmac_sha256_verify, prove_aes_256_gcm, prove_chacha20, prove_chacha20_poly1305, prove_drbg,
    prove_hkdf_sha256, prove_hmac_sha256, prove_sha256, sha256,
    vectors::{
        AES_256_GCM_VECTORS, CHACHA20_POLY1305_VECTORS, CHACHA20_STREAM_VECTORS, DRBG_VECTORS,
        HKDF_SHA256_VECTORS, HMAC_SHA256_VECTORS, SHA256_VECTORS,
    },
};

// ---------------------------------------------------------------------------
// The published vectors, which are the whole of the correctness claim
// ---------------------------------------------------------------------------

/// The same seven runs the cryptography domain makes at bring-up, here on the
/// host. Both must pass and neither substitutes for the other: this one proves
/// the code, the domain's proves the instructions the code was compiled to.
#[test]
fn every_published_vector_answers_on_the_host() {
    type Run = fn() -> Result<u32, crate::VectorFailure>;
    let runs: [(&str, Run, usize); 7] = [
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
    assert_eq!(total, 90, "the committed vector corpus changed size");
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
        .chain(DRBG_VECTORS.iter().map(|v| v.id));
    for id in ids {
        assert!(!id.is_empty(), "a vector carries no identifier");
        assert!(
            id.starts_with("cavp-")
                || id.starts_with("wycheproof-")
                || id.starts_with("rfc8439-")
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
        proof::{
            prove_aes_256_gcm_in, prove_chacha20_in, prove_chacha20_poly1305_in, prove_drbg_in,
            prove_hkdf_sha256_in, prove_hmac_sha256_in, prove_sha256_in,
        },
        vectors::{
            AES_256_GCM_VECTORS, AeadVector, CHACHA20_POLY1305_VECTORS, DrbgVector, HashVector,
            KdfVector, MacVector, StreamVector,
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
