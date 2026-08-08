//! Taking ownership, against a package the management server actually produced
//! and against every way one can fail to be that.
//!
//! The fixture is the package reader's own, referenced rather than copied: two
//! copies of one artifact are two things that drift, and what these tests need is
//! exactly the archive that reader is proved against — a certificate the
//! management server's certification authority really issued, so the one
//! signature this appliance verifies is a signature that was really made.

use std::{vec, vec::Vec};

use proptest::prelude::*;

use super::*;
use crate::state::SECRET_LEN;

/// A package the management server composed, byte for byte as it produced it.
const FIXTURE: &[u8] = include_bytes!("../../../package/fixtures/management-server-package.tar");

/// The public point of the key that package's device certificate was issued
/// over. Public material: the private half was generated for the fixture and
/// never left the machine that minted it.
const APPLIANCE_POINT: &[u8; P256_PUBLIC_LEN] =
    include_bytes!("../../../package/fixtures/appliance-public-key.bin");

/// A verifier that accepts, for the two tests that need the fixture's
/// certificates out of it rather than a verdict on them.
struct Accept;

impl ChainVerifier for Accept {
    fn verify(&self, _end_entity: &[u8], _anchor: &[u8]) -> Result<(), ChainRejected> {
        Ok(())
    }
}

/// An unowned appliance holding the key the fixture was issued over.
///
/// The scalar is a fixed non-zero pattern and is never used: nothing on this
/// path signs, and what the rules here compare against is the public point.
fn unowned() -> State {
    State::minted(
        [7; crate::state::DEVICE_ID_BYTES],
        [1; SECRET_LEN],
        *APPLIANCE_POINT,
        StoredCertificate::ABSENT,
    )
}

/// The two certificates the fixture carries, as DER.
fn fixture_certificates() -> (Vec<u8>, Vec<u8>) {
    let key = spki(APPLIANCE_POINT).expect("the fixture's point encodes");
    let package = lfw_package::read(FIXTURE, &key, &Accept).expect("the fixture is a package");
    (
        package.device_certificate().to_vec(),
        package.trust_anchor().to_vec(),
    )
}

// ------------------------------------------------------------------ the path

#[test]
fn the_management_servers_package_becomes_this_appliances_ownership() {
    let state = unowned();
    let adoption =
        read(FIXTURE.len() as u32, FIXTURE, &state).expect("the fixture installs on this key");

    // The endpoint the package named, and the anchor's fingerprint taken the one
    // way this appliance takes a fingerprint.
    assert!(!adoption.endpoint().is_absent());
    let (_, anchor) = fixture_certificates();
    let anchor_spki = subject_public_key_info(&anchor).expect("the anchor walks");
    assert_eq!(adoption.anchor_fingerprint(), sha256(anchor_spki));

    let mut state = state;
    let before = state.generation();
    adoption.take_ownership(&mut state);
    assert_eq!(state.onboarding(), Onboarding::Onboarded);
    assert_eq!(state.generation(), before + 1);
    assert_eq!(state.anchor_certificate().as_bytes(), anchor.as_slice());
    assert!(!state.device_certificate().is_empty());
    assert!(!state.endpoint().is_absent());
}

/// The whole point of the second check: the key it compares against is the one
/// in this appliance's own record, so a package issued for another appliance has
/// nothing here to match — however well formed and however genuinely signed.
#[test]
fn a_package_issued_for_another_appliance_matches_nothing_here() {
    let mut point = *APPLIANCE_POINT;
    // The last coordinate byte, so the encoding is still an uncompressed point
    // and only the key it names has moved.
    point[P256_PUBLIC_LEN - 1] ^= 1;
    let state = State::minted(
        [7; crate::state::DEVICE_ID_BYTES],
        [1; SECRET_LEN],
        point,
        StoredCertificate::ABSENT,
    );
    assert_eq!(
        read(FIXTURE.len() as u32, FIXTURE, &state).err(),
        Some(InstallError::Package(
            PackageError::DeviceKeyIsNotThisAppliance
        ))
    );
}

/// A factory reset is the only way back, so an owned appliance is not re-owned
/// by delivering it another package.
#[test]
fn an_appliance_that_already_has_an_owner_refuses_before_reading_a_byte() {
    let mut state = unowned();
    read(FIXTURE.len() as u32, FIXTURE, &state)
        .expect("the fixture installs")
        .take_ownership(&mut state);
    assert_eq!(
        read(FIXTURE.len() as u32, FIXTURE, &state).err(),
        Some(InstallError::AlreadyOwned)
    );
}

/// The stated length is the asking side's claim and is ranged against what was
/// really staged, never believed.
#[test]
fn a_stated_length_past_what_was_staged_reads_nothing() {
    let state = unowned();
    let len = FIXTURE.len() as u32 + 1;
    assert_eq!(
        read(len, FIXTURE, &state).err(),
        Some(InstallError::ArchivePastRegion {
            len,
            staged: FIXTURE.len()
        })
    );
    // And one byte short is not an error of this kind at all: it is an archive
    // that ends without its terminator, which the package reader names.
    assert!(matches!(
        read(FIXTURE.len() as u32 - 512, FIXTURE, &state).err(),
        Some(InstallError::Package(PackageError::Archive(_)))
    ));
}

#[test]
fn a_stated_length_of_zero_is_an_archive_and_not_a_special_case() {
    let state = unowned();
    assert!(matches!(
        read(0, FIXTURE, &state).err(),
        Some(InstallError::Package(PackageError::Archive(_)))
    ));
}

// -------------------------------------------------------- the one signature

#[test]
fn the_anchor_really_signed_the_fixtures_device_certificate() {
    let (device, anchor) = fixture_certificates();
    assert_eq!(verify_one_signature(&device, &anchor), Ok(()));
}

/// The signature is the last thing checked and it is really checked: one byte of
/// it moved and the answer is no.
#[test]
fn a_signature_one_byte_different_does_not_verify() {
    let (device, anchor) = fixture_certificates();
    let mut forged = device.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xff;
    assert_eq!(
        verify_one_signature(&forged, &anchor),
        Err(ChainFault::NotAuthentic)
    );
    // And the same certificate against an anchor that is not its issuer.
    assert_eq!(
        verify_one_signature(&device, &device),
        Err(ChainFault::NotAuthentic)
    );
}

/// Exactly the two places a certificate names what signed it, so the test that
/// moves one of them is moving what it means to.
fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(at, _)| at)
        .collect()
}

#[test]
fn a_certificate_signed_with_another_algorithm_is_refused_for_that() {
    let (device, anchor) = fixture_certificates();
    let at = occurrences(&device, oid::ECDSA_WITH_SHA256);
    assert_eq!(at.len(), 2, "a certificate names its algorithm twice");

    // The outer one, beside the signature: the algorithm this appliance would
    // have to verify under.
    let mut other = device.clone();
    let outer = at[1] + oid::ECDSA_WITH_SHA256.len() - 1;
    other[outer] ^= 1;
    assert_eq!(
        verify_one_signature(&other, &anchor),
        Err(ChainFault::SignatureAlgorithmNotEcdsaSha256)
    );

    // The inner one, inside the signed body: the certificate now states two
    // answers to what signed it.
    let mut disagreeing = device.clone();
    let inner = at[0] + oid::ECDSA_WITH_SHA256.len() - 1;
    disagreeing[inner] ^= 1;
    assert_eq!(
        verify_one_signature(&disagreeing, &anchor),
        Err(ChainFault::SignatureAlgorithmsDisagree)
    );
}

#[test]
fn an_anchor_on_another_curve_is_refused_before_any_arithmetic() {
    let (device, anchor) = fixture_certificates();
    let at = occurrences(&anchor, oid::PRIME256V1);
    assert_eq!(at.len(), 1, "an anchor names its curve once");
    let mut other = anchor.clone();
    let last = at[0] + oid::PRIME256V1.len() - 1;
    other[last] ^= 1;
    assert_eq!(
        verify_one_signature(&device, &other),
        Err(ChainFault::AnchorKeyNotP256)
    );

    let at = occurrences(&anchor, oid::EC_PUBLIC_KEY);
    let mut not_ec = anchor.clone();
    // The first occurrence is the key's own algorithm; a signature algorithm
    // never carries this identifier, so there is exactly one.
    assert_eq!(at.len(), 1, "an anchor names its key kind once");
    let last = at[0] + oid::EC_PUBLIC_KEY.len() - 1;
    not_ec[last] ^= 1;
    assert_eq!(
        verify_one_signature(&device, &not_ec),
        Err(ChainFault::AnchorKeyNotP256)
    );
}

// ------------------------------------------------------- malformed encodings

/// One DER tag-length-value with a minimally encoded definite length, for the
/// shapes the fixture cannot supply: a real management server composes only
/// correct certificates, so every broken one is composed here.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// A certificate shaped enough for the walk to reach the element under test.
fn certificate_with(inner_algorithm: &[u8], outer_algorithm: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&tlv(lfw_package::CONTEXT_ZERO, &tlv(INTEGER, &[2])));
    tbs.extend_from_slice(&tlv(INTEGER, &[1]));
    tbs.extend_from_slice(&tlv(SEQUENCE, &tlv(OBJECT_IDENTIFIER, inner_algorithm)));
    let mut body = tlv(SEQUENCE, &tbs);
    body.extend_from_slice(&tlv(SEQUENCE, &tlv(OBJECT_IDENTIFIER, outer_algorithm)));
    body.extend_from_slice(signature);
    tlv(SEQUENCE, &body)
}

#[test]
fn every_malformed_shape_is_named_by_the_element_it_broke() {
    let (_, anchor) = fixture_certificates();

    // Nothing at all, and a SEQUENCE holding nothing: neither is a certificate.
    for shape in [Vec::new(), tlv(SEQUENCE, &[])] {
        assert_eq!(
            verify_one_signature(&shape, &anchor),
            Err(ChainFault::MalformedCertificate)
        );
    }

    // Bytes after the certificate, inside what should hold exactly one.
    let mut trailing = certificate_with(
        oid::ECDSA_WITH_SHA256,
        oid::ECDSA_WITH_SHA256,
        &tlv(BIT_STRING, &[0, 1, 2]),
    );
    trailing.push(0);
    assert_eq!(
        verify_one_signature(&trailing, &anchor),
        Err(ChainFault::MalformedCertificate)
    );

    // The algorithm beside the signature is not an `AlgorithmIdentifier`.
    let mut body = tlv(SEQUENCE, &tlv(INTEGER, &[1]));
    body.extend_from_slice(&tlv(INTEGER, &[1]));
    assert_eq!(
        verify_one_signature(&tlv(SEQUENCE, &body), &anchor),
        Err(ChainFault::MalformedSignatureAlgorithm)
    );

    // A signature that is not a BIT STRING, and one whose last byte is part
    // padding — which for a signature is an encoding nothing writes.
    for signature in [tlv(INTEGER, &[1]), tlv(BIT_STRING, &[1, 0xff])] {
        assert_eq!(
            verify_one_signature(
                &certificate_with(oid::ECDSA_WITH_SHA256, oid::ECDSA_WITH_SHA256, &signature),
                &anchor
            ),
            Err(ChainFault::MalformedSignature)
        );
    }

    // An anchor that is not a certificate at all.
    let device = certificate_with(
        oid::ECDSA_WITH_SHA256,
        oid::ECDSA_WITH_SHA256,
        &tlv(BIT_STRING, &[0, 1]),
    );
    for shape in [Vec::new(), tlv(SEQUENCE, &[])] {
        assert_eq!(
            verify_one_signature(&device, &shape),
            Err(ChainFault::MalformedAnchorKey)
        );
    }
}

/// A BIT STRING's leading octet is how many bits of the last byte are padding,
/// and a key or a signature is whole bytes.
#[test]
fn a_bit_string_that_is_not_whole_octets_yields_nothing() {
    assert_eq!(whole_octets(&[0, 1, 2]), Some(&[1, 2][..]));
    assert_eq!(whole_octets(&[0]), Some(&[][..]));
    assert_eq!(whole_octets(&[1, 2]), None);
    assert_eq!(whole_octets(&[]), None);
}

/// What an install occupies on the store domain's stack, and the stack that
/// domain is declared with.
///
/// `sel4_microkit`'s `run_main` holds the handler as a temporary of its own
/// frame, so the domain's resident state and its `stack_size` are one number to
/// keep in step — and an install's own call frame sits on top of it. This is the
/// side that can measure both: the composition below is `pds/store`'s, which is
/// not host-testable.
///
/// **The configuration model is what makes this worth a test.** Reading a
/// package runs the configuration reader, whose model is twenty-four kilobytes
/// built and discarded inside a frame that already holds the state record twice
/// over — so the domain that used to need eight kilobytes for a boot now needs
/// two orders of magnitude more for one wakeup. A stack sized for the old shape
/// produces a write fault one page past it, on the boot after the change, and
/// this is what fails on a developer's machine instead.
#[test]
fn an_install_fits_the_stack_the_store_domain_is_declared_with() {
    /// `<protection_domain name="store" stack_size="0x40000">`.
    const STORE_STACK: usize = 0x40000;
    /// Six `&'static` region references, a `RingSink`, a `SignResponder`, a
    /// `StagedArchive`, the counters and the frames' own alignment slack,
    /// rounded up.
    const REFERENCES: usize = 512;

    // Resident for the domain's life: the device it now keeps past start-up, and
    // the identity it signs with.
    let resident = size_of::<lfw_blk::request::Requests<'static>>()
        + size_of::<lfw_blk::io::IoRegion<'static>>()
        + size_of::<lfw_blk::bringup::Live<lfw_blk::bringup::MappedBlkDevice>>()
        + size_of::<StoredCertificate>()
        + REFERENCES;

    // One install's own frame: the record read back off the medium, the decoded
    // state moved through its three shapes, the package's fixed certificate
    // storage, the configuration model the reader builds and discards — counted
    // twice, because it is built and then returned — the ownership that comes
    // out, and the byte image a commit composes.
    let install = 2 * crate::STATE_COPY_BYTES
        + 3 * size_of::<State>()
        + size_of::<lfw_package::Package<'static>>()
        + 2 * size_of::<config::Model>()
        + size_of::<Adoption>()
        + crate::STATE_COPY_BYTES;

    let state = resident + install;
    assert!(
        state <= STORE_STACK / 2,
        "an install occupies {state} bytes ({resident} resident, {install} in its own frame) \
         against a {STORE_STACK}-byte stack, which leaves under the twofold headroom its call \
         frames are sized by"
    );
}

proptest! {
    /// Reading is total over an arbitrary staged region and an arbitrary claim
    /// about its length: every input is a typed refusal or an ownership, and
    /// nothing panics, indexes out of bounds or loops unbounded.
    #[test]
    fn reading_an_arbitrary_region_is_total(
        stated in any::<u32>(),
        staged in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let state = unowned();
        // An arbitrary region is not a package the fixture's authority signed,
        // so what this asserts is that every path answers rather than faults.
        let _ = read(stated, &staged, &state);
    }

    /// The same, for the one signature: arbitrary DER on either side answers a
    /// fault or a verification, and never both and never neither.
    #[test]
    fn verifying_arbitrary_der_is_total(
        end_entity in proptest::collection::vec(any::<u8>(), 0..512),
        anchor in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        // Arbitrary bytes are not a signed certificate, so the answer is always
        // a named fault — which is the assertion: no input reaches `Ok` by
        // accident and none of them panics.
        prop_assert!(verify_one_signature(&end_entity, &anchor).is_err());
    }
}
