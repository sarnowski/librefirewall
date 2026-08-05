//! The appliance's own state record, read back off the store medium.
//!
//! Every byte of the input is the region both copies of the record occupy, laid
//! over it verbatim: a fresh medium, a sector the device mis-addressed, a record
//! a previous deployment left, or a whole store an offline attacker composed with
//! physical possession of the disk. That last adversary is what makes this
//! surface different from every other one here — the bytes were not merely
//! *chosen* by an attacker, they were chosen at leisure, with the decoder's
//! source in hand.
//!
//! # What the harness asserts
//!
//! Three things, and the third is the one a decoder gets wrong.
//!
//! * **Totality.** Every input either refuses or decodes; nothing panics, no
//!   index leaves a buffer, and no length is believed.
//! * **Determinism.** Decoding one region twice gives one answer, so nothing
//!   here reads uninitialised storage or depends on an order.
//! * **Re-encoding is a fixed point.** A record that decoded, was checked
//!   against this build's layout, and was written back out must decode to the
//!   same state. That is what makes "the decoder accepts exactly what the writer
//!   produces" a checked claim rather than a hope: an accepted record whose
//!   re-encoding differs is a record the appliance would rewrite into something
//!   else on its next commit, and the copy an operator's disk carried would stop
//!   being the copy the appliance believes.
//!
//! It also drives [`lfw_store::verify`] on every accepted record, because that
//! is where an attacker's real leverage is: a digest holds over whatever the
//! attacker wrote, so what stands between a forged record and a node signing
//! under a key nobody can validate is the check that the scalar, the point and
//! the certificate agree. The claim asserted is that `verify` is total — every
//! accepted record either yields an identity whose fingerprint is the digest over
//! its own stored key, or a typed refusal.
//!
//! # No key material is committed
//!
//! The seeds below carry scalars, and every one of them is a fixed byte pattern
//! this file writes — `0x22` repeated, or the low bytes of a counter — chosen so
//! a reader can see at a glance that no key drawn from a real generator is in the
//! corpus. Two of them are deliberately *not* private keys at all (zero and
//! all-ones), which is the point of committing them.

use lfw_store::{Copies, IdentityError, STATE_COPY_BYTES, decode_state, encode_state, verify};

/// Bytes one corpus entry is: both copies of the record, which is the region the
/// store domain reads in one transfer.
///
/// Restated from the layout rather than taken from `size_of`, so a record that
/// changed size shows up as a seed that no longer means what it was committed for
/// rather than as a silently re-laid-out input.
pub const REGION_BYTES: usize = 2 * STATE_COPY_BYTES;

/// Drive the state-record decode, the layout check above it and the identity
/// verification above that.
pub fn store_state_harness(data: &[u8]) {
    let region = region_from_input(data);

    let first = decode_state(&region).map(|image| image.generation());
    let second = decode_state(&region).map(|image| image.generation());
    assert_eq!(
        first, second,
        "decoding one region twice gave two answers; the decode reads something the region does \
         not carry"
    );

    let Some(image) = decode_state(&region) else {
        return;
    };
    let claimed = image.generation();
    assert_ne!(
        claimed, 0,
        "a decoded record claims generation 0, which is what a zeroed medium reads as and what \
         `State::minted` starts above"
    );

    let Ok(checked) = image.check() else {
        // A record written under another build's layout. Refused rather than
        // adopted, which is the whole of what `check` is for.
        return;
    };
    let state = checked.get();
    assert_eq!(state.generation(), claimed);

    // The fixed point: what this build accepts, this build re-produces. A
    // difference here is a record the appliance would rewrite into something
    // else on its next commit.
    let mut written = [0_u8; REGION_BYTES];
    encode_state(&mut written, state, Copies::Both);
    let round_tripped = decode_state(&written)
        .expect("a region this writer just composed decodes")
        .check()
        .expect("written under this build's layout");
    assert_eq!(
        round_tripped.get().generation(),
        state.generation(),
        "a record survived the decode and its own re-encoding changed its generation"
    );
    assert_eq!(round_tripped.get().device_id(), state.device_id());
    assert_eq!(
        round_tripped.get().public_key().as_slice(),
        state.public_key().as_slice()
    );
    // By content rather than through `Debug`: a certificate has none, deliberately
    // — the type that carries a stored certificate sits beside the one that
    // carries a scalar, and neither may gain a way to print itself.
    assert!(
        round_tripped.get().device_certificate() == state.device_certificate(),
        "a record's device certificate did not survive its own re-encoding"
    );
    assert!(
        round_tripped.get().anchor_certificate() == state.anchor_certificate(),
        "a record's trust anchor did not survive its own re-encoding"
    );
    assert_eq!(round_tripped.get().endpoint(), state.endpoint());
    assert_eq!(round_tripped.get().slots(), state.slots());
    assert_eq!(round_tripped.get().onboarding(), state.onboarding());

    // And the identity, which is where the attacker's leverage is: the digest
    // holds over whatever was written, so this is what stands between a forged
    // record and a node signing under a key nobody can validate.
    match verify(state) {
        Ok(identity) => {
            let public = state.public_key();
            assert_eq!(
                identity.fingerprint,
                lfw_x509::spki_fingerprint(&public).expect("a fixed-length encoding"),
                "a verified identity's fingerprint is not the digest over its own stored key"
            );
            // A cause token is owed by every refusal and by no acceptance, so
            // there is nothing to check here beyond the fingerprint — which is
            // the value the console record carries.
        }
        Err(error) => {
            let cause = error.cause();
            assert!(!cause.is_empty(), "a refusal with no cause token");
            assert!(
                cause.len() <= 40,
                "cause token {cause} is wider than the record ABI carries"
            );
            assert!(
                cause
                    .bytes()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-')),
                "cause token {cause} is outside the console alphabet"
            );
            // Verification refuses for exactly the reasons a *stored* record can
            // be wrong. The minting-only variants are unreachable from here, and
            // asserting that is what keeps a future edit from routing a mint
            // failure through a reload path.
            assert!(
                matches!(
                    error,
                    IdentityError::ScalarUnusable
                        | IdentityError::PublicKeyMismatch
                        | IdentityError::CertificateKeyMismatch
                        | IdentityError::CertificateAbsent
                        | IdentityError::Fingerprint(_)
                ),
                "a stored record was refused for a reason only minting can reach: {error:?}"
            );
        }
    }
}

/// Lay the input over the region verbatim, zeroing whatever it does not reach —
/// which is what an unwritten part of a freshly mapped staging window holds.
///
/// Verbatim rather than through a field-by-field derivation, unlike the log
/// record's harness: this region is not a struct with a public layout but a byte
/// image whose every offset the decoder computes itself, so the fuzzer's bytes
/// *are* the medium and there is no field order for a seed to depend on.
#[must_use]
pub fn region_from_input(data: &[u8]) -> [u8; REGION_BYTES] {
    let mut region = [0_u8; REGION_BYTES];
    for (slot, byte) in region.iter_mut().zip(data) {
        *slot = *byte;
    }
    region
}

#[cfg(test)]
mod tests {
    use super::*;
    // The seed builders' own reach, kept here rather than at the module head: a
    // fuzz binary is built without `cfg(test)`, so an import only the fixtures
    // use is an unused one there.
    use lfw_store::{DEVICE_ID_BYTES, SECRET_LEN, State, StoredCertificate};
    use std::fs;
    use std::path::PathBuf;
    use std::{format, vec, vec::Vec};

    /// The corpus directory these seeds live in.
    const TARGET: &str = "store_state";

    fn seed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET)
            .join(name);
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// A recognisable, entirely synthetic identity: no scalar here came from a
    /// generator, and two of the seeds below use scalars that are not private
    /// keys at all.
    fn synthetic(scalar: [u8; SECRET_LEN]) -> State {
        let mut public = [0x33_u8; 65];
        public[0] = 0x04;
        State::minted(
            [0x11; DEVICE_ID_BYTES],
            scalar,
            public,
            StoredCertificate::new(&[0xAB; 300]).expect("inside the bound"),
        )
    }

    fn region_of(state: &State) -> Vec<u8> {
        let mut region = [0_u8; REGION_BYTES];
        encode_state(&mut region, state, Copies::Both);
        region.to_vec()
    }

    /// Every committed seed, as the bytes it stands for.
    fn demonstrations() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            // A fresh medium: neither copy is a record, which is not an error and
            // is what a first boot mints from.
            ("fresh_medium", vec![0_u8; REGION_BYTES]),
            // A well-formed record whose scalar is a fixed pattern rather than a
            // key: it decodes, it checks, and `verify` refuses it because the
            // stored point is not that scalar's. The interesting half of the
            // corpus, because a decoder that stopped at the digest would accept
            // this and let the node sign under it.
            (
                "record_with_a_mismatched_key",
                region_of(&synthetic([0x22; SECRET_LEN])),
            ),
            // The two scalars that are no private key at all, refused before any
            // point is derived from them.
            ("scalar_zero", region_of(&synthetic([0x00; SECRET_LEN]))),
            ("scalar_all_ones", region_of(&synthetic([0xff; SECRET_LEN]))),
            // Both copies present and the second newer, which is the tie-break
            // the decode has to get right; and the same record with its digest
            // broken in the newer copy, which must fall back to the older.
            ("newer_second_copy", newer_second_copy()),
            ("newer_copy_digest_broken", newer_copy_digest_broken()),
            // Every byte the medium could hold, set. A magic of all-ones is no
            // magic, so both copies refuse.
            ("every_byte_set", vec![0xFF; REGION_BYTES]),
            // The magic alone, with nothing behind it: the shape an attacker
            // reaches for first, and the one a decoder that trusted the magic
            // would walk into.
            ("magic_without_a_record", magic_without_a_record()),
        ]
    }

    /// Copy A at generation 1 and copy B at generation 2, so the newer is second.
    fn newer_second_copy() -> Vec<u8> {
        let mut region = [0_u8; REGION_BYTES];
        let first = synthetic([0x22; SECRET_LEN]);
        encode_state(&mut region, &first, Copies::Both);
        let mut second = synthetic([0x22; SECRET_LEN]);
        second.record_document(
            lfw_store::SlotIndex::new(0).expect("slot 0 exists"),
            lfw_store::SlotEntry {
                generation: 1,
                len: 512,
                digest: [0x44; 32],
            },
            true,
        );
        // The newer record's image placed in copy B by hand rather than through
        // `Copies::Parity`, which at generation 2 would select copy A: what this
        // seed is for is a *newer second* copy, and building it from the parity
        // rule would make the seed depend on which generation the fixture
        // happened to reach.
        let mut newer = [0_u8; REGION_BYTES];
        encode_state(&mut newer, &second, Copies::Both);
        region[STATE_COPY_BYTES..].copy_from_slice(&newer[..STATE_COPY_BYTES]);
        region.to_vec()
    }

    /// The same pair with one byte of the newer copy's body flipped, so its
    /// digest no longer covers it and the older copy is what decodes.
    fn newer_copy_digest_broken() -> Vec<u8> {
        let mut region = newer_second_copy();
        // The device identifier's first byte, inside the digest's range and
        // outside every length field, so nothing but the digest refuses it.
        let at = STATE_COPY_BYTES + 24;
        region[at] ^= 0xff;
        region
    }

    /// The record magic and the version, and zeroes behind them.
    fn magic_without_a_record() -> Vec<u8> {
        let mut region = vec![0_u8; REGION_BYTES];
        region[..8].copy_from_slice(&lfw_store::STATE_MAGIC.to_le_bytes());
        region[8..12].copy_from_slice(&lfw_store::STATE_VERSION.to_le_bytes());
        region
    }

    /// Rewrite every committed seed from the demonstration of the same name.
    ///
    /// Ignored by default and run by hand — `cargo test --manifest-path
    /// fuzz/Cargo.toml -- --ignored rewrite_the_committed_store_seeds` — after a
    /// deliberate change to the record layout, which moves every offset a seed's
    /// byte image places. The test below is what holds the corpus to the
    /// demonstrations afterwards, so this is a regeneration step and never a
    /// substitute for it.
    #[test]
    #[ignore = "regenerates the committed corpus; run by hand after a layout change"]
    fn rewrite_the_committed_store_seeds() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET);
        fs::create_dir_all(&dir).expect("create the corpus directory");
        for (name, built) in demonstrations() {
            fs::write(dir.join(name), &built).expect("write the seed");
        }
    }

    #[test]
    fn every_demonstration_is_the_committed_seed_of_its_name() {
        for (name, built) in demonstrations() {
            assert_eq!(
                built.len(),
                REGION_BYTES,
                "seed {name} is not one region's worth of medium"
            );
            assert_eq!(
                seed(name),
                built,
                "seed {name} is not the region it stands for"
            );
        }
    }

    /// The whole point of the corpus: a record whose digest holds and whose
    /// identity does not is accepted by the format and refused by the
    /// verification. A decoder that stopped at the digest would let this node
    /// sign under a key nobody can validate.
    #[test]
    fn a_record_whose_digest_holds_and_whose_identity_does_not_is_refused() {
        for name in [
            "record_with_a_mismatched_key",
            "scalar_zero",
            "scalar_all_ones",
        ] {
            let region = region_from_input(&seed(name));
            let state = decode_state(&region)
                .unwrap_or_else(|| panic!("{name} is a well-formed record"))
                .check()
                .unwrap_or_else(|error| panic!("{name} is this build's layout: {error:?}"));
            assert!(
                verify(state.get()).is_err(),
                "{name} passed verification with a synthetic key"
            );
        }
    }

    /// The tie-break, and the fallback behind it.
    #[test]
    fn the_newer_copy_wins_and_a_broken_newer_copy_falls_back() {
        let newer = region_from_input(&seed("newer_second_copy"));
        assert_eq!(
            decode_state(&newer)
                .expect("a valid pair decodes")
                .generation(),
            2
        );
        let broken = region_from_input(&seed("newer_copy_digest_broken"));
        assert_eq!(
            decode_state(&broken)
                .expect("the older copy still decodes")
                .generation(),
            1,
            "a newer copy whose digest does not cover it was adopted"
        );
    }

    #[test]
    fn a_fresh_medium_and_a_forged_magic_both_yield_no_record() {
        for name in ["fresh_medium", "every_byte_set", "magic_without_a_record"] {
            let region = region_from_input(&seed(name));
            assert!(
                decode_state(&region).is_none(),
                "{name} decoded to a record"
            );
        }
    }

    /// The harness survives every seed and a deterministic sweep of synthetic
    /// regions, which is what a cold fuzz run starts from.
    #[test]
    fn the_harness_survives_its_seeds_and_a_sweep_of_synthetic_regions() {
        for (_, bytes) in demonstrations() {
            store_state_harness(&bytes);
        }
        for stamp in 0..256_u32 {
            let region: Vec<u8> = (0..REGION_BYTES)
                .map(|offset| {
                    (stamp
                        .wrapping_mul(0x9E37_79B9)
                        .wrapping_add(offset as u32)
                        .rotate_left(offset as u32 % 32)
                        & 0xFF) as u8
                })
                .collect();
            store_state_harness(&region);
        }
        // And the shared edges every harness here is driven with.
        store_state_harness(&[]);
        store_state_harness(&[0]);
    }

    /// The reader is total over a short input: whatever the fuzzer hands over,
    /// the region is exactly one region and the tail is the zeroes an unwritten
    /// staging window holds.
    #[test]
    fn a_short_input_becomes_one_whole_region_with_a_zeroed_tail() {
        let region = region_from_input(&[0xAB, 0xCD]);
        assert_eq!(region.len(), REGION_BYTES);
        assert_eq!(&region[..2], &[0xAB, 0xCD]);
        assert!(region[2..].iter().all(|byte| *byte == 0));
        // And over a long one: the extra is dropped rather than wrapping.
        let long = vec![0x5A_u8; REGION_BYTES * 2];
        assert!(region_from_input(&long).iter().all(|byte| *byte == 0x5A));
    }

    /// Every seed's name reads differently, so a crash report names one shape.
    #[test]
    fn every_seed_has_its_own_name() {
        let mut names: Vec<&str> = demonstrations().into_iter().map(|(name, _)| name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
        assert_eq!(
            format!("{REGION_BYTES}"),
            "8192",
            "the region is two 4 KiB copies"
        );
    }
}
