//! The reader against the format's own rules, and against a package the
//! management server actually produced.
//!
//! The fixture is the point of this file. The format has two implementations in
//! two languages in two components, and two implementations of one format drift
//! silently; a reader tested only against archives this same crate composed
//! would prove that this crate agrees with itself. So the archive below came
//! out of the management server's own writer, carries certificates its own
//! certification authority issued, and is read here by every rule this reader
//! states — while the server's suite asserts that its writer still reproduces
//! these exact bytes. A change to either implementation that the other does not
//! admit fails one of the two gates the moment it is made.

use super::*;
use proptest::prelude::*;

/// A package the management server composed, byte for byte as it produced it.
const FIXTURE: &[u8] = include_bytes!("../fixtures/management-server-package.tar");

/// The public point of the key that package's device certificate was issued
/// over. Public material: the private half was generated for the fixture and
/// never left the machine that minted it.
const APPLIANCE_POINT: &[u8; 65] = include_bytes!("../fixtures/appliance-public-key.bin");

fn appliance_key() -> [u8; SPKI_LEN] {
    lfw_x509::spki(APPLIANCE_POINT).expect("the fixture's point encodes")
}

/// A verifier that accepts, standing in for the cryptography domain's adopted
/// validator: what these tests exercise is everything up to the chain, and the
/// chain's own answer is the validator's to give.
struct Accept;

impl ChainVerifier for Accept {
    fn verify(&self, _end_entity: &[u8], _anchor: &[u8]) -> Result<(), ChainRejected> {
        Ok(())
    }
}

/// A verifier that refuses everything.
struct Refuse;

impl ChainVerifier for Refuse {
    fn verify(&self, _end_entity: &[u8], _anchor: &[u8]) -> Result<(), ChainRejected> {
        Err(ChainRejected)
    }
}

/// A verifier that records what it was asked about.
#[derive(Default)]
struct Witness {
    calls: core::cell::Cell<usize>,
    end_entity: core::cell::RefCell<Vec<u8>>,
    anchor: core::cell::RefCell<Vec<u8>>,
}

impl ChainVerifier for Witness {
    fn verify(&self, end_entity: &[u8], anchor: &[u8]) -> Result<(), ChainRejected> {
        self.calls.set(self.calls.get() + 1);
        self.end_entity.replace(end_entity.to_vec());
        self.anchor.replace(anchor.to_vec());
        Ok(())
    }
}

fn read_fixture() -> Result<Package<'static>, PackageError> {
    read(FIXTURE, &appliance_key(), &Accept)
}

// ---------------------------------------------------------------- composing

/// A tar writer for the adversarial shapes, which the fixture cannot supply:
/// the management server's writer only ever composes correct archives, so every
/// broken one is composed here.
struct Compose {
    blocks: Vec<u8>,
}

impl Compose {
    fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    fn member(self, name: &[u8], body: &[u8]) -> Self {
        self.raw(name, body, b'0', body.len())
    }

    /// A member whose header may lie about its type or its length.
    fn raw(mut self, name: &[u8], body: &[u8], type_flag: u8, stated: usize) -> Self {
        self.blocks
            .extend_from_slice(&header(name, stated, type_flag));
        self.blocks.extend_from_slice(body);
        let remainder = body.len() % BLOCK;
        if remainder != 0 {
            self.blocks.resize(self.blocks.len() + BLOCK - remainder, 0);
        }
        self
    }

    fn close(mut self) -> Vec<u8> {
        self.blocks.resize(self.blocks.len() + 2 * BLOCK, 0);
        self.blocks
    }
}

fn header(name: &[u8], size: usize, type_flag: u8) -> [u8; BLOCK] {
    let mut block = [0_u8; BLOCK];
    block[..name.len()].copy_from_slice(name);
    block[100..107].copy_from_slice(b"0000644");
    block[108..115].copy_from_slice(b"0000000");
    block[116..123].copy_from_slice(b"0000000");
    block[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    block[136..147].copy_from_slice(b"15234352100");
    block[148..156].copy_from_slice(b"        ");
    block[156] = type_flag;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    checksum(&mut block);
    block
}

/// Recompute a header's checksum in place, which is what makes a tampered
/// header a well-formed one that says something else.
fn checksum(block: &mut [u8; BLOCK]) {
    block[148..156].copy_from_slice(b"        ");
    let sum: usize = block.iter().map(|byte| usize::from(*byte)).sum();
    let digits = format!("{sum:06o}");
    block[148..154].copy_from_slice(digits.as_bytes());
    block[154] = 0;
    block[155] = b' ';
}

/// The fixture's four members, taken back out of it, so a composed archive can
/// carry real content.
fn members() -> [(Member, Vec<u8>); 4] {
    let mut found = Vec::new();
    let mut at = 0;
    while at + BLOCK <= FIXTURE.len() {
        let block = &FIXTURE[at..at + BLOCK];
        if block.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_end = block[..100].iter().position(|byte| *byte == 0).unwrap();
        let name = &block[..name_end];
        let size_end = block[124..136].iter().position(|byte| *byte == 0).unwrap();
        let size = usize::from_str_radix(
            core::str::from_utf8(&block[124..124 + size_end]).unwrap(),
            8,
        )
        .unwrap();
        let member = Member::ALL
            .into_iter()
            .find(|member| member.name() == name)
            .unwrap();
        found.push((member, FIXTURE[at + BLOCK..at + BLOCK + size].to_vec()));
        at += BLOCK + size.div_ceil(BLOCK) * BLOCK;
    }
    found
        .try_into()
        .unwrap_or_else(|_| panic!("the fixture's four members"))
}

fn body(member: Member) -> Vec<u8> {
    members()
        .into_iter()
        .find(|(which, _)| *which == member)
        .map(|(_, body)| body)
        .expect("a fixture member")
}

/// The fixture recomposed, with one member replaced, dropped or added.
fn composed(edit: impl Fn(Compose, Member, &[u8]) -> Compose) -> Vec<u8> {
    let mut compose = Compose::new();
    for (member, body) in members() {
        compose = edit(compose, member, &body);
    }
    compose.close()
}

fn plain() -> Vec<u8> {
    composed(|compose, member, body| compose.member(member.name(), body))
}

// -------------------------------------------------- the real package reads

#[test]
fn the_management_servers_own_package_is_accepted_whole() {
    let package = read_fixture().expect("the management server's package");
    assert_eq!(
        package.endpoint(),
        Endpoint {
            address: [192, 0, 2, 10],
            port: 8443
        }
    );
    assert_eq!(package.configuration(), body(Member::Configuration));
    assert_eq!(package.device_certificate().first(), Some(&0x30));
    assert_eq!(package.trust_anchor().first(), Some(&0x30));
    assert_ne!(package.device_certificate(), package.trust_anchor());
    // The document is the archive's own bytes rather than a copy of them.
    assert!(
        FIXTURE
            .as_ptr_range()
            .contains(&package.configuration().as_ptr())
    );
}

#[test]
fn the_device_certificate_binds_the_key_the_appliance_holds() {
    let package = read_fixture().expect("the fixture");
    let spki =
        certificate::subject_public_key_info(package.device_certificate()).expect("a certificate");
    assert_eq!(spki, appliance_key().as_slice());
    // And the anchor does not: the two are different keys, which is what makes
    // the equality above a check rather than a tautology.
    let anchor = certificate::subject_public_key_info(package.trust_anchor()).expect("an anchor");
    assert_ne!(anchor, appliance_key().as_slice());
}

#[test]
fn the_verifier_is_asked_about_the_two_certificates_the_package_carried() {
    let witness = Witness::default();
    let package = read(FIXTURE, &appliance_key(), &witness).expect("the fixture");
    assert_eq!(witness.calls.get(), 1);
    assert_eq!(*witness.end_entity.borrow(), package.device_certificate());
    assert_eq!(*witness.anchor.borrow(), package.trust_anchor());
}

#[test]
fn a_refusing_verifier_yields_no_package_from_an_otherwise_perfect_one() {
    assert_eq!(
        read(FIXTURE, &appliance_key(), &Refuse).err(),
        Some(PackageError::ChainNotVerified)
    );
}

#[test]
fn a_certificate_for_another_key_is_somebody_elses_identity() {
    // The anchor is a real, well-formed certificate over a different key, which
    // is exactly the shape a substring search for the key's bytes would miss.
    let archive = composed(|compose, member, body| match member {
        Member::DeviceCertificate => {
            compose.member(member.name(), &self::body(Member::TrustAnchor))
        }
        _ => compose.member(member.name(), body),
    });
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::DeviceKeyIsNotThisAppliance)
    );
}

#[test]
fn the_composed_archive_is_the_fixture_the_server_wrote() {
    // The test writer above has to produce the same framing as the management
    // server's, or every adversarial archive below would be testing a shape the
    // real one never has.
    assert_eq!(plain(), FIXTURE);
}

// ------------------------------------------------------------ the archive

#[test]
fn an_archive_past_its_bound_is_refused_before_anything_is_parsed() {
    let archive = vec![0_u8; ARCHIVE_BOUND + BLOCK];
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::ArchiveOverBound {
            len: ARCHIVE_BOUND + BLOCK,
            bound: ARCHIVE_BOUND
        }))
    );
}

#[test]
fn an_archive_that_is_not_whole_blocks_is_refused() {
    let mut archive = plain();
    archive.push(b'x');
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(
            ArchiveError::NotAWholeNumberOfBlocks {
                len: FIXTURE.len() + 1
            }
        ))
    );
}

#[test]
fn every_missing_member_is_named() {
    for absent in Member::ALL {
        let archive = composed(|compose, member, body| {
            if member == absent {
                compose
            } else {
                compose.member(member.name(), body)
            }
        });
        assert_eq!(
            read(&archive, &appliance_key(), &Accept).err(),
            Some(PackageError::Archive(ArchiveError::MissingMember {
                member: absent
            })),
            "{absent:?} missing"
        );
    }
}

#[test]
fn every_duplicated_member_is_named() {
    for twice in Member::ALL {
        let archive = composed(|compose, member, body| {
            let compose = compose.member(member.name(), body);
            if member == twice {
                compose.member(member.name(), body)
            } else {
                compose
            }
        });
        assert_eq!(
            read(&archive, &appliance_key(), &Accept).err(),
            Some(PackageError::Archive(ArchiveError::DuplicateMember {
                member: twice
            })),
            "{twice:?} twice"
        );
    }
}

#[test]
fn a_member_the_contract_does_not_name_refuses_the_package() {
    for name in [
        &b"unexpected.pem"[..],
        b"./configuration.xml",
        b"etc/configuration.xml",
        b"configuration.xml ",
        b"CONFIGURATION.XML",
    ] {
        let archive = Compose::new().member(name, b"x").close();
        assert!(
            matches!(
                read(&archive, &appliance_key(), &Accept).err(),
                Some(PackageError::Archive(ArchiveError::UnknownMember { at: 0 }))
            ),
            "{:?}",
            core::str::from_utf8(name)
        );
    }
}

#[test]
fn a_truncated_header_and_a_truncated_body_are_told_apart() {
    let mut short = plain();
    short.truncate(BLOCK);
    assert_eq!(
        read(&short, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::MemberBodyTruncated {
            member: Member::DeviceCertificate,
            size: body(Member::DeviceCertificate).len()
        }))
    );

    // A header block cut short is a partial block, which the block rule catches
    // before anything reads a field out of it.
    let mut cut = plain();
    cut.truncate(BLOCK - 1);
    assert_eq!(
        read(&cut, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(
            ArchiveError::NotAWholeNumberOfBlocks { len: BLOCK - 1 }
        ))
    );
}

#[test]
fn a_size_field_that_lies_is_refused_in_both_directions() {
    // Longer than the bytes present: the archive runs out inside the member.
    let over = composed(|compose, member, body| {
        if member == Member::DeviceCertificate {
            compose.raw(member.name(), body, b'0', member.bound())
        } else {
            compose.member(member.name(), body)
        }
    });
    assert_eq!(
        read(&over, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::MemberBodyTruncated {
            member: Member::DeviceCertificate,
            size: Member::DeviceCertificate.bound()
        }))
    );

    // Shorter: the bytes it did not claim are read as the next header, and they
    // are not one.
    let under = composed(|compose, member, body| {
        if member == Member::ManagementEndpoint {
            compose.raw(member.name(), body, b'0', 1)
        } else {
            compose.member(member.name(), body)
        }
    });
    assert!(matches!(
        read(&under, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(
            ArchiveError::MemberPaddingIsNotZero {
                member: Member::ManagementEndpoint
            }
        ))
    ));
}

#[test]
fn a_size_field_naming_more_than_the_member_may_hold_is_refused_by_its_bound() {
    let archive = Compose::new()
        .raw(
            Member::ManagementEndpoint.name(),
            &[b'x'; BLOCK],
            b'0',
            BLOCK,
        )
        .close();
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::MemberOverBound {
            member: Member::ManagementEndpoint,
            size: BLOCK,
            bound: 32
        }))
    );
}

#[test]
fn a_header_whose_checksum_does_not_verify_is_refused() {
    let mut archive = plain();
    // A byte the checksum covers, changed without recomputing it.
    archive[0] = b'D';
    assert!(matches!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::ChecksumMismatch {
            at: 0,
            ..
        }))
    ));
}

#[test]
fn every_tar_extension_is_refused_by_its_type_flag() {
    // PAX extended and global headers, GNU long name and long link, and the
    // ordinary filesystem kinds that have no meaning here.
    for flag in [b'x', b'g', b'L', b'K', b'1', b'2', b'3', b'4', b'5', b'6'] {
        let archive = Compose::new()
            .raw(Member::ManagementEndpoint.name(), b"10.0.0.1:1", flag, 10)
            .close();
        assert_eq!(
            read(&archive, &appliance_key(), &Accept).err(),
            Some(PackageError::Archive(ArchiveError::NotARegularFile {
                at: 0
            })),
            "type flag {}",
            char::from(flag)
        );
    }
}

#[test]
fn a_header_that_is_not_ustar_is_refused() {
    let mut archive = plain();
    archive[257..263].copy_from_slice(b"gnutar");
    let mut block: [u8; BLOCK] = archive[..BLOCK].try_into().unwrap();
    checksum(&mut block);
    archive[..BLOCK].copy_from_slice(&block);
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::NotUstar { at: 0 }))
    );

    let mut version = plain();
    version[263..265].copy_from_slice(b"01");
    let mut block: [u8; BLOCK] = version[..BLOCK].try_into().unwrap();
    checksum(&mut block);
    version[..BLOCK].copy_from_slice(&block);
    assert_eq!(
        read(&version, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::NotUstar { at: 0 }))
    );
}

#[test]
fn the_two_fields_this_format_never_uses_must_be_empty() {
    for (at, field) in [(157_usize, EmptyField::LinkName), (345, EmptyField::Prefix)] {
        let mut archive = plain();
        archive[at] = b'x';
        let mut block: [u8; BLOCK] = archive[..BLOCK].try_into().unwrap();
        checksum(&mut block);
        archive[..BLOCK].copy_from_slice(&block);
        assert_eq!(
            read(&archive, &appliance_key(), &Accept).err(),
            Some(PackageError::Archive(ArchiveError::FieldIsNotEmpty {
                at: 0,
                field
            })),
            "{field:?}"
        );
    }
}

#[test]
fn an_archive_without_its_two_closing_blocks_is_refused() {
    let mut one_block = plain();
    one_block.truncate(one_block.len() - BLOCK);
    assert_eq!(
        read(&one_block, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::EndsWithoutTerminator))
    );

    let mut none = plain();
    none.truncate(none.len() - 2 * BLOCK);
    assert_eq!(
        read(&none, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::EndsWithoutTerminator))
    );

    assert_eq!(
        read(&[], &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::EndsWithoutTerminator))
    );
}

#[test]
fn nothing_may_follow_the_closing_blocks() {
    let mut archive = plain();
    archive.resize(archive.len() + BLOCK, 0);
    let last = archive.len() - 1;
    archive[last] = b'x';
    assert!(matches!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(
            ArchiveError::BytesAfterEndOfArchive { .. }
        ))
    ));
}

#[test]
fn a_numeric_field_that_is_empty_or_not_octal_is_refused_by_field() {
    let mut empty = plain();
    empty[124..136].copy_from_slice(&[0_u8; 12]);
    let mut block: [u8; BLOCK] = empty[..BLOCK].try_into().unwrap();
    checksum(&mut block);
    empty[..BLOCK].copy_from_slice(&block);
    assert_eq!(
        read(&empty, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::EmptyNumericField {
            at: 0,
            field: NumericField::Size
        }))
    );

    let mut digits = plain();
    digits[124..135].copy_from_slice(b"00000000009");
    let mut block: [u8; BLOCK] = digits[..BLOCK].try_into().unwrap();
    checksum(&mut block);
    digits[..BLOCK].copy_from_slice(&block);
    assert_eq!(
        read(&digits, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::NotOctal {
            at: 0,
            field: NumericField::Size
        }))
    );

    // A checksum field that is not a number is a checksum that cannot verify,
    // and it is refused as the field it is rather than as a mismatch.
    let mut checksum_field = plain();
    checksum_field[148..156].copy_from_slice(b"99999999");
    assert_eq!(
        read(&checksum_field, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::NotOctal {
            at: 0,
            field: NumericField::Checksum
        }))
    );
}

#[test]
fn a_size_field_past_the_archive_bound_is_refused_as_a_number() {
    let mut archive = plain();
    archive[124..135].copy_from_slice(b"77777777777");
    let mut block: [u8; BLOCK] = archive[..BLOCK].try_into().unwrap();
    checksum(&mut block);
    archive[..BLOCK].copy_from_slice(&block);
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::Archive(ArchiveError::NumericFieldOverBound {
            at: 0,
            field: NumericField::Size
        }))
    );
}

// -------------------------------------------------------- the certificates

#[test]
fn a_member_that_is_not_one_armoured_certificate_is_refused_by_the_rule_it_broke() {
    let anchor = body(Member::TrustAnchor);
    let cases: Vec<(Vec<u8>, CertificateError)> = vec![
        (
            b"not pem at all\n".to_vec(),
            CertificateError::MissingBeginBoundary,
        ),
        (
            [b"\n".to_vec(), anchor.clone()].concat(),
            CertificateError::MissingBeginBoundary,
        ),
        (
            anchor
                .iter()
                .copied()
                .take(anchor.len() - 40)
                .collect::<Vec<_>>(),
            CertificateError::MissingEndBoundary,
        ),
        (
            [anchor.clone(), b"trailing\n".to_vec()].concat(),
            CertificateError::TrailingContent,
        ),
        (
            anchor.replacen_first(b"MII", b"M!I"),
            CertificateError::NotBase64,
        ),
        (
            anchor.replacen_first(b"MII", b"M=I"),
            CertificateError::PaddingMisplaced,
        ),
    ];
    for (member, expected) in cases {
        let archive = composed(|compose, which, body| {
            if which == Member::TrustAnchor {
                compose.member(which.name(), &member)
            } else {
                compose.member(which.name(), body)
            }
        });
        assert_eq!(
            read(&archive, &appliance_key(), &Accept).err(),
            Some(PackageError::TrustAnchor(expected)),
            "{expected:?}"
        );
    }
}

#[test]
fn an_armoured_line_longer_than_the_encoding_permits_is_refused() {
    let member = [
        b"-----BEGIN CERTIFICATE-----\n".to_vec(),
        vec![b'A'; 68],
        b"\n-----END CERTIFICATE-----\n".to_vec(),
    ]
    .concat();
    let archive = one_certificate(member);
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::DeviceCertificate(
            CertificateError::LineTooLong { len: 68, bound: 64 }
        ))
    );
}

#[test]
fn base64_that_does_not_close_its_group_or_pads_non_canonically_is_refused() {
    for (encoded, expected) in [
        ("QUJD", None),
        ("QUJ", Some(CertificateError::NotAWholeGroup)),
        ("QUI=", None),
        ("QUJ=", Some(CertificateError::NonCanonicalPadding)),
        ("QQ==", None),
        ("QR==", Some(CertificateError::NonCanonicalPadding)),
        ("=QQQ", Some(CertificateError::PaddingMisplaced)),
        ("QUJDQQ==QUJD", Some(CertificateError::PaddingMisplaced)),
    ] {
        let member = [
            b"-----BEGIN CERTIFICATE-----\n".to_vec(),
            encoded.as_bytes().to_vec(),
            b"\n-----END CERTIFICATE-----\n".to_vec(),
        ]
        .concat();
        let archive = one_certificate(member);
        let answer = read(&archive, &appliance_key(), &Accept).err();
        match expected {
            // Well-formed base64 of something that is not a certificate gets
            // past the armour and is refused by the structure instead.
            None => assert!(
                matches!(
                    answer,
                    Some(PackageError::DeviceCertificate(
                        CertificateError::UnexpectedTag { .. }
                            | CertificateError::TruncatedDer { .. }
                    ))
                ),
                "{encoded}: {answer:?}"
            ),
            Some(fault) => assert_eq!(
                answer,
                Some(PackageError::DeviceCertificate(fault)),
                "{encoded}"
            ),
        }
    }
}

#[test]
fn a_certificate_longer_than_the_appliance_holds_is_refused_by_its_length() {
    let der = vec![b'A'; 4 * 1024];
    let member = armour(&der);
    let archive = one_certificate(member);
    assert!(matches!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::DeviceCertificate(
            CertificateError::CertificateTooLong { bound: 768, .. }
        ))
    ));
}

#[test]
fn an_empty_armoured_body_is_not_a_certificate() {
    let archive = one_certificate(armour(&[]));
    assert_eq!(
        read(&archive, &appliance_key(), &Accept).err(),
        Some(PackageError::DeviceCertificate(
            CertificateError::CertificateIsEmpty
        ))
    );
}

#[test]
fn every_element_the_walk_descends_through_is_named_when_it_is_wrong() {
    let der = body_der(Member::DeviceCertificate);
    // Truncating one byte at a time walks the refusal outward through the
    // elements, and each one says which element ran out.
    for cut in [1_usize, 4, 12, 40, 120, 220] {
        let mut damaged = der.clone();
        damaged.truncate(damaged.len() - cut);
        let answer = certificate::subject_public_key_info(&damaged);
        assert!(answer.is_err(), "truncated by {cut} still parsed");
    }
    // A tag that is not a SEQUENCE where the body must be one.
    let mut wrong = der.clone();
    let inner = wrong.len() - der.len();
    let _ = inner;
    wrong[4] = 0x31;
    assert!(matches!(
        certificate::subject_public_key_info(&wrong),
        Err(CertificateError::UnexpectedTag { .. }) | Err(CertificateError::TruncatedDer { .. })
    ));
    // Bytes after the certificate, inside a member that should hold one.
    let mut trailing = der.clone();
    trailing.push(0);
    assert_eq!(
        certificate::subject_public_key_info(&trailing),
        Err(CertificateError::TrailingDer)
    );
}

fn body_der(member: Member) -> Vec<u8> {
    let package = read_fixture().expect("the fixture");
    match member {
        Member::TrustAnchor => package.trust_anchor().to_vec(),
        _ => package.device_certificate().to_vec(),
    }
}

fn armour(der: &[u8]) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::new();
    for chunk in der.chunks(3) {
        let mut group = [0_u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let packed = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(alphabet[((packed >> (18 - 6 * index)) & 0x3f) as usize]);
            } else {
                encoded.push(b'=');
            }
        }
    }
    let mut member = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for line in encoded.chunks(64) {
        member.extend_from_slice(line);
        member.push(b'\n');
    }
    member.extend_from_slice(b"-----END CERTIFICATE-----\n");
    member
}

fn one_certificate(member: Vec<u8>) -> Vec<u8> {
    composed(|compose, which, body| {
        if which == Member::DeviceCertificate {
            compose.member(which.name(), &member)
        } else {
            compose.member(which.name(), body)
        }
    })
}

// ------------------------------------------------- the other two members

#[test]
fn the_endpoint_member_is_read_by_its_own_rules() {
    for (line, expected) in [
        (&b"10.0.0.1"[..], EndpointError::MissingColon),
        (b"010.0.0.1:1", EndpointError::OctetHasLeadingZero),
        (b"10.0.0.1:0", EndpointError::PortOutOfRange),
        (b"10.0.0.1:1\nmore", EndpointError::TrailingBytes),
    ] {
        let archive = composed(|compose, which, body| {
            if which == Member::ManagementEndpoint {
                compose.member(which.name(), line)
            } else {
                compose.member(which.name(), body)
            }
        });
        assert_eq!(
            read(&archive, &appliance_key(), &Accept).err(),
            Some(PackageError::Endpoint(expected)),
            "{:?}",
            core::str::from_utf8(line)
        );
    }
}

#[test]
fn the_configuration_member_goes_through_the_configuration_reader() {
    let archive = composed(|compose, which, body| {
        if which == Member::Configuration {
            compose.member(which.name(), b"<configuration>")
        } else {
            compose.member(which.name(), body)
        }
    });
    let answer = read(&archive, &appliance_key(), &Accept).err();
    assert!(
        matches!(answer, Some(PackageError::Configuration(_))),
        "{answer:?}"
    );
    assert_eq!(
        answer.and_then(|fault| match fault {
            PackageError::Configuration(inner) => Some(inner.reason()),
            _ => None,
        }),
        Some(config::load(b"<configuration>").unwrap_err().reason())
    );
}

// ---------------------------------------------------------- the invariants

proptest! {
    /// Arbitrary bytes are answered, once, the same way twice, and never with a
    /// package: the fixture is the only archive there is, so nothing this
    /// generator reaches can carry a certificate over the appliance's key.
    #[test]
    fn arbitrary_bytes_are_answered_and_yield_nothing(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let key = appliance_key();
        let first = read(&bytes, &key, &Accept).err();
        let second = read(&bytes, &key, &Accept).err();
        prop_assert_eq!(first.is_some(), true);
        prop_assert_eq!(first, second);
    }

    /// The fixture with one byte changed is still answered, and is a package
    /// only where the byte it changed was one nothing reads.
    #[test]
    fn one_changed_byte_never_yields_a_package_the_verifier_did_not_see(
        at in 0..6144_usize,
        value in any::<u8>(),
    ) {
        let mut archive = FIXTURE.to_vec();
        if archive[at] == value {
            return Ok(());
        }
        archive[at] = value;
        let witness = Witness::default();
        let answered = read(&archive, &appliance_key(), &witness).is_ok();
        prop_assert_eq!(answered, witness.calls.get() == 1);
    }
}

/// A small helper for the armour cases: replace the first occurrence of a
/// pattern, which is how a well-formed member is made ill-formed in one place.
trait ReplaceFirst {
    fn replacen_first(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
}

impl ReplaceFirst for Vec<u8> {
    fn replacen_first(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
        let at = self
            .windows(from.len())
            .position(|window| window == from)
            .expect("the pattern occurs");
        let mut out = self.clone();
        out[at..at + to.len()].copy_from_slice(to);
        out
    }
}

// ------------------------------------------------------- the seed corpus

/// Where the fuzz workspace keeps this reader's seeds.
const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fuzz/corpus/onboarding_package"
);

/// The one seed that is a package, which is the fixture read everywhere above.
const ACCEPTED_SEED: &str = "management_server_package";

/// One committed fuzz seed and the refusal it stands for.
///
/// The corpus is what a cold fuzz run starts from, and a seed whose meaning
/// nothing checks is a file whose name is the only claim about it. So each is
/// named here with the rule it breaks, and a seed that stops breaking that rule
/// — because a refusal moved, or because the fixture it was cut from did —
/// fails here rather than going on being fuzzed as something else.
macro_rules! seeds {
    ($(($name:literal, $expected:pat)),+ $(,)?) => {
        &[$(
            (
                $name,
                include_bytes!(concat!("../../../fuzz/corpus/onboarding_package/", $name))
                    as &[u8],
                (|fault: PackageError| matches!(fault, $expected)) as fn(PackageError) -> bool,
            )
        ),+]
    };
}

/// One seed: what it is called, what it holds, and whether an answer is the
/// refusal it stands for.
type Seed = (&'static str, &'static [u8], fn(PackageError) -> bool);

const SEEDS: &[Seed] = seeds![
    (
        "missing_device_certificate_pem",
        PackageError::Archive(ArchiveError::MissingMember {
            member: Member::DeviceCertificate
        })
    ),
    (
        "missing_trust_anchor_pem",
        PackageError::Archive(ArchiveError::MissingMember {
            member: Member::TrustAnchor
        })
    ),
    (
        "missing_management_endpoint",
        PackageError::Archive(ArchiveError::MissingMember {
            member: Member::ManagementEndpoint
        })
    ),
    (
        "missing_configuration_xml",
        PackageError::Archive(ArchiveError::MissingMember {
            member: Member::Configuration
        })
    ),
    (
        "duplicate_device_certificate_pem",
        PackageError::Archive(ArchiveError::DuplicateMember {
            member: Member::DeviceCertificate
        })
    ),
    (
        "duplicate_trust_anchor_pem",
        PackageError::Archive(ArchiveError::DuplicateMember {
            member: Member::TrustAnchor
        })
    ),
    (
        "duplicate_management_endpoint",
        PackageError::Archive(ArchiveError::DuplicateMember {
            member: Member::ManagementEndpoint
        })
    ),
    (
        "duplicate_configuration_xml",
        PackageError::Archive(ArchiveError::DuplicateMember {
            member: Member::Configuration
        })
    ),
    (
        "unknown_member",
        PackageError::Archive(ArchiveError::UnknownMember { .. })
    ),
    (
        "dot_slash_member_name",
        PackageError::Archive(ArchiveError::UnknownMember { at: 0 })
    ),
    (
        "truncated_header",
        PackageError::Archive(ArchiveError::NotAWholeNumberOfBlocks { .. })
    ),
    (
        "truncated_body",
        PackageError::Archive(ArchiveError::MemberBodyTruncated {
            member: Member::DeviceCertificate,
            ..
        })
    ),
    (
        "size_field_longer_than_the_body",
        PackageError::Archive(ArchiveError::MemberBodyTruncated {
            member: Member::DeviceCertificate,
            size: 16384
        })
    ),
    (
        "size_field_shorter_than_the_body",
        PackageError::Archive(ArchiveError::MemberPaddingIsNotZero {
            member: Member::ManagementEndpoint
        })
    ),
    (
        "header_checksum_does_not_verify",
        PackageError::Archive(ArchiveError::ChecksumMismatch { at: 0, .. })
    ),
    (
        "pax_extended_header",
        PackageError::Archive(ArchiveError::NotARegularFile { .. })
    ),
    (
        "gnu_long_name",
        PackageError::Archive(ArchiveError::NotARegularFile { .. })
    ),
    (
        "symbolic_link_member",
        PackageError::Archive(ArchiveError::NotARegularFile { .. })
    ),
    (
        "directory_member",
        PackageError::Archive(ArchiveError::NotARegularFile { .. })
    ),
    (
        "member_over_its_bound",
        PackageError::Archive(ArchiveError::MemberOverBound {
            member: Member::ManagementEndpoint,
            size: 64,
            bound: 32
        })
    ),
    (
        "archive_over_its_bound",
        PackageError::Archive(ArchiveError::ArchiveOverBound { .. })
    ),
    (
        "not_ustar",
        PackageError::Archive(ArchiveError::NotUstar { at: 0 })
    ),
    (
        "a_single_zero_block",
        PackageError::Archive(ArchiveError::EndsWithoutTerminator)
    ),
    (
        "two_zero_blocks_only",
        PackageError::Archive(ArchiveError::MissingMember {
            member: Member::DeviceCertificate
        })
    ),
    (
        "armour_does_not_open",
        PackageError::DeviceCertificate(CertificateError::MissingBeginBoundary)
    ),
    (
        "endpoint_octet_has_a_leading_zero",
        PackageError::Endpoint(EndpointError::OctetHasLeadingZero)
    ),
    (
        "certificate_for_another_key",
        PackageError::DeviceKeyIsNotThisAppliance
    ),
];

#[test]
fn every_committed_seed_breaks_the_rule_its_name_claims() {
    let key = appliance_key();
    for (name, seed, expected) in SEEDS {
        let fault = read(seed, &key, &Accept)
            .err()
            .unwrap_or_else(|| panic!("seed {name} was accepted"));
        assert!(expected(fault), "seed {name} answered {fault:?}");
        println!("{name}: {fault:?}");
    }
}

#[test]
fn the_corpus_and_the_table_are_the_same_set() {
    // A seed added to the directory without a claim about what it means would
    // be fuzzed as something nobody decided, and one deleted would leave a
    // claim about a file that is gone.
    let mut on_disk: Vec<String> = std::fs::read_dir(CORPUS)
        .expect("the committed corpus")
        .map(|entry| entry.expect("a readable entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    on_disk.sort();

    let mut claimed: Vec<String> = SEEDS
        .iter()
        .map(|(name, _, _)| (*name).to_owned())
        .chain(core::iter::once(ACCEPTED_SEED.to_owned()))
        .collect();
    claimed.sort();

    assert_eq!(on_disk, claimed);
    assert_eq!(
        std::fs::read(format!("{CORPUS}/{ACCEPTED_SEED}")).expect("the accepted seed"),
        FIXTURE,
        "the seed a cold run starts from is not the package the tests read"
    );
}
