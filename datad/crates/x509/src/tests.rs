use std::sync::Mutex;

use lfw_crypto::{Drbg, Entropy, P256_PUBLIC_LEN, P256SecretKey, SEED_LEN, p256_verify, sha256};
use proptest::prelude::*;

use crate::{
    Certificate, CertificateKind, DEVICE_ID_LEN, DerError, DeviceId, FINGERPRINT_LEN,
    MAX_CERTIFICATE_LEN, MAX_CSR_LEN, Profile, ProfileError, SPKI_LEN, Serial, Validity,
    fingerprint_hex, spki, spki_fingerprint, write_certificate, write_csr,
};

struct TestEntropy(Mutex<Drbg>);

impl Entropy for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        self.0.lock().expect("no test panics here").fill(out);
    }
}

fn entropy(fill: u8) -> TestEntropy {
    TestEntropy(Mutex::new(Drbg::from_seed(&[fill; SEED_LEN])))
}

fn key(fill: u8) -> P256SecretKey {
    P256SecretKey::generate(&entropy(fill)).expect("a generator that generates")
}

const NOW: i64 = 1_784_000_000;

fn certificate(kind: CertificateKind, key: &P256SecretKey) -> Certificate {
    write_certificate(
        &Profile {
            kind,
            subject: b"00000000000000000000000000000001",
            issuer: b"librefirewall management",
            serial: Serial::from_bytes([0x42; 16]),
            validity: Validity::ten_years_from(NOW),
            subject_public_key: key.public_key(),
        },
        key,
    )
    .expect("the profile fits its own buffer")
}

// ---------------------------------------------------------------------------
// The structures, checked against the encoding rather than against themselves
// ---------------------------------------------------------------------------

#[test]
fn a_public_key_info_is_the_fixed_ninety_one_bytes_the_curve_makes_it() {
    let signing = key(0x31);
    let info = spki(&signing.public_key()).expect("a fixed-length encoding");
    assert_eq!(info.len(), SPKI_LEN);
    // SEQUENCE(89) { SEQUENCE(19) { OID ecPublicKey, OID prime256v1 },
    //                BIT STRING(66) { 00, 04, X, Y } }
    assert_eq!(
        info.get(..27),
        Some(
            &[
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
            ][..]
        )
    );
    assert_eq!(info.get(27..), signing.public_key().get(1..));
}

#[test]
fn a_fingerprint_is_the_digest_of_that_encoding_and_renders_one_way() {
    let signing = key(0x32);
    let public = signing.public_key();
    let digest = spki_fingerprint(&public).expect("a fixed-length encoding");
    assert_eq!(digest, sha256(&spki(&public).expect("encodes")));
    let rendered = fingerprint_hex(&digest);
    assert_eq!(rendered.len(), FINGERPRINT_LEN);
    assert!(
        rendered
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    );
}

#[test]
fn a_device_identifier_renders_as_thirty_two_lowercase_hexadecimal_characters() {
    let id = DeviceId::from_bytes([
        0x0f, 0xa0, 0x00, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ]);
    assert_eq!(&id.render(), b"0fa000ff0102030405060708090a0b0c");
    assert_eq!(id.render().len(), DEVICE_ID_LEN);
}

#[test]
fn a_serial_is_positive_and_never_empty() {
    assert_eq!(Serial::from_bytes([0; 16]), Serial::from_bytes([0; 16]));
    // The top bit is cleared so the magnitude never needs a leading zero, and
    // a leading zero byte is replaced so the magnitude is never empty.
    let high = Serial::from_bytes([0xff; 16]);
    let zero = Serial::from_bytes([0; 16]);
    assert_ne!(high, zero);
    let signing = key(0x33);
    for serial in [high, zero] {
        let certificate = write_certificate(
            &Profile {
                kind: CertificateKind::Device,
                subject: b"device",
                issuer: b"issuer",
                serial,
                validity: Validity::ten_years_from(NOW),
                subject_public_key: signing.public_key(),
            },
            &signing,
        )
        .expect("encodes");
        assert!(!certificate.is_empty());
    }
}

#[test]
fn every_certificate_kind_encodes_and_is_signed_by_the_key_that_issued_it() {
    let signing = key(0x34);
    for kind in [
        CertificateKind::Onboarding,
        CertificateKind::Device,
        CertificateKind::ChannelEndpoint {
            address: [10, 0, 0, 1],
        },
        CertificateKind::ManagementCa,
    ] {
        let certificate = certificate(kind, &signing);
        let bytes = certificate.as_bytes();
        assert_eq!(bytes.len(), certificate.len());
        assert!(bytes.len() < MAX_CERTIFICATE_LEN, "{kind:?}");
        assert_eq!(bytes.first(), Some(&0x30), "{kind:?}");
        // The outer sequence's length must account for exactly the rest.
        let (header, body) = split_header(bytes);
        assert_eq!(body, bytes.len() - header, "{kind:?}");
        // The signature at the end verifies over the first element, which is
        // the to-be-signed certificate: that is what makes this a certificate
        // and not a byte string shaped like one.
        let (tbs, signature) = tbs_and_signature(bytes);
        p256_verify(&signing.public_key(), tbs, signature)
            .unwrap_or_else(|error| panic!("{kind:?} did not verify: {error}"));
    }
}

#[test]
fn an_authority_marks_itself_one_and_an_end_entity_does_not() {
    let signing = key(0x35);
    let authority = certificate(CertificateKind::ManagementCa, &signing);
    let device = certificate(CertificateKind::Device, &signing);
    // `basicConstraints` critical with `cA` TRUE and a path length of zero.
    let marker = [
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff,
        0x02, 0x01, 0x00,
    ];
    assert!(contains(authority.as_bytes(), &marker));
    assert!(!contains(device.as_bytes(), &marker));
    // The end-entity form is the same extension with an empty sequence.
    let end_entity = [
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
    ];
    assert!(contains(device.as_bytes(), &end_entity));
    assert!(!contains(authority.as_bytes(), &end_entity));
}

#[test]
fn each_kind_carries_the_key_usage_and_purpose_the_profile_gives_it() {
    let signing = key(0x36);
    let signature_usage = [
        0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80,
    ];
    let cert_sign_usage = [
        0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04,
    ];
    let server_auth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    let client_auth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

    let authority = certificate(CertificateKind::ManagementCa, &signing);
    assert!(contains(authority.as_bytes(), &cert_sign_usage));
    assert!(!contains(authority.as_bytes(), &server_auth));
    assert!(!contains(authority.as_bytes(), &client_auth));

    let device = certificate(CertificateKind::Device, &signing);
    assert!(contains(device.as_bytes(), &signature_usage));
    assert!(contains(device.as_bytes(), &client_auth));
    assert!(!contains(device.as_bytes(), &server_auth));

    let onboarding = certificate(CertificateKind::Onboarding, &signing);
    assert!(contains(onboarding.as_bytes(), &signature_usage));
    assert!(contains(onboarding.as_bytes(), &server_auth));

    let endpoint = certificate(
        CertificateKind::ChannelEndpoint {
            address: [192, 0, 2, 7],
        },
        &signing,
    );
    assert!(contains(endpoint.as_bytes(), &server_auth));
    // `subjectAltName` carrying one `iPAddress`.
    assert!(contains(
        endpoint.as_bytes(),
        &[
            0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x08, 0x30, 0x06, 0x87, 0x04, 192, 0, 2, 7
        ]
    ));
    assert!(!contains(
        device.as_bytes(),
        &[0x06, 0x03, 0x55, 0x1d, 0x11]
    ));
}

#[test]
fn a_request_carries_the_name_and_the_key_and_asks_for_nothing_else() {
    let signing = key(0x37);
    let mut out = [0_u8; MAX_CSR_LEN];
    let len = write_csr(b"00000000000000000000000000000001", &signing, &mut out)
        .expect("a request fits its own buffer");
    let bytes = out.get(..len).expect("the length is the writer's own");
    assert_eq!(bytes.first(), Some(&0x30));
    // The empty `[0]` attribute set: a request that reaches for no extension.
    assert!(contains(bytes, &[0xa0, 0x00]));
    assert!(contains(
        bytes,
        &spki(&signing.public_key()).expect("encodes")
    ));
    let (info, signature) = tbs_and_signature(bytes);
    p256_verify(&signing.public_key(), info, signature).expect("the request is self-signed");
}

#[test]
fn a_certificate_a_buffer_cannot_hold_is_refused_and_not_truncated() {
    let signing = key(0x38);
    // A name that pushes the encoding past the buffer the profile reserves.
    let long = [b'a'; MAX_CERTIFICATE_LEN];
    let outcome = write_certificate(
        &Profile {
            kind: CertificateKind::Device,
            subject: &long,
            issuer: &long,
            serial: Serial::from_bytes([1; 16]),
            validity: Validity::ten_years_from(NOW),
            subject_public_key: signing.public_key(),
        },
        &signing,
    );
    assert!(matches!(
        outcome,
        Err(ProfileError::Encoding(DerError::OutOfSpace { .. }))
    ));
    let mut out = [0_u8; MAX_CSR_LEN];
    assert!(matches!(
        write_csr(&long, &signing, &mut out),
        Err(ProfileError::Encoding(DerError::OutOfSpace { .. }))
    ));
}

#[test]
fn a_clock_outside_the_datable_window_refuses_and_names_the_year() {
    let signing = key(0x39);
    let outcome = write_certificate(
        &Profile {
            kind: CertificateKind::Device,
            subject: b"device",
            issuer: b"issuer",
            serial: Serial::from_bytes([1; 16]),
            validity: Validity {
                not_before: 0,
                not_after: 2_600_000_000,
            },
            subject_public_key: signing.public_key(),
        },
        &signing,
    );
    assert_eq!(outcome.err(), Some(ProfileError::Undatable { year: 2052 }));
}

#[test]
fn a_validity_window_is_ten_years_and_starts_before_now() {
    let validity = Validity::ten_years_from(NOW);
    assert!(validity.not_before < NOW);
    assert_eq!(
        validity.not_after - validity.not_before,
        Validity::TEN_YEARS + 3600
    );
    // Saturating rather than wrapping at the extremes.
    let far = Validity::ten_years_from(i64::MAX);
    assert_eq!(far.not_after, i64::MAX);
}

#[test]
fn every_refusal_says_what_was_refused() {
    let rendered = |error: ProfileError| std::format!("{error:?}");
    assert!(rendered(ProfileError::Undatable { year: 2051 }).contains("2051"));
    assert!(rendered(ProfileError::Signature).contains("Signature"));
    assert!(rendered(ProfileError::Encoding(DerError::TooLong { bytes: 9 })).contains("TooLong"));
}

proptest! {
    /// Whatever name and key it is given, a certificate either encodes into
    /// its buffer or is refused — never a panic, never a partial structure.
    #[test]
    fn arbitrary_names_encode_or_refuse(
        name in proptest::collection::vec(any::<u8>(), 0..900),
        fill: u8,
    ) {
        let signing = key(fill);
        let outcome = write_certificate(
            &Profile {
                kind: CertificateKind::Device,
                subject: &name,
                issuer: &name,
                serial: Serial::from_bytes([fill; 16]),
                validity: Validity::ten_years_from(NOW),
                subject_public_key: signing.public_key(),
            },
            &signing,
        );
        match outcome {
            Ok(certificate) => {
                let (tbs, signature) = tbs_and_signature(certificate.as_bytes());
                prop_assert!(p256_verify(&signing.public_key(), tbs, signature).is_ok());
            }
            Err(ProfileError::Encoding(_)) => {}
            Err(other) => prop_assert!(false, "{other:?}"),
        }
    }

    /// Every point encodes to the same fixed length, whatever its coordinates.
    #[test]
    fn every_public_key_info_is_the_same_length(fill: u8) {
        let public: [u8; P256_PUBLIC_LEN] = key(fill).public_key();
        prop_assert_eq!(spki(&public).map(|info| info.len()), Ok(SPKI_LEN));
    }
}

/// The header length and the content length of a DER element.
fn split_header(bytes: &[u8]) -> (usize, usize) {
    match bytes.get(1) {
        Some(&length) if length < 0x80 => (2, usize::from(length)),
        Some(&marker) => {
            let width = usize::from(marker & 0x7f);
            let mut length = 0_usize;
            for at in 0..width {
                length = (length << 8) | usize::from(bytes[2 + at]);
            }
            (2 + width, length)
        }
        None => (0, 0),
    }
}

/// The first element of an outer sequence, and the content of the bit string
/// that ends it: for a certificate that is the to-be-signed body and the
/// signature over it, and for a request the information and its signature.
fn tbs_and_signature(bytes: &[u8]) -> (&[u8], &[u8]) {
    let (outer, _) = split_header(bytes);
    let body = &bytes[outer..];
    let (inner, inner_len) = split_header(body);
    let tbs = &body[..inner + inner_len];
    let rest = &body[inner + inner_len..];
    // The algorithm identifier, then the bit string.
    let (algorithm, algorithm_len) = split_header(rest);
    let signature_element = &rest[algorithm + algorithm_len..];
    let (signature_header, signature_len) = split_header(signature_element);
    // One byte of unused-bit count in front of the signature itself.
    (
        tbs,
        &signature_element[signature_header + 1..signature_header + signature_len],
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
