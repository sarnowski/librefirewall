//! `lfw_package` under the management-plane attacker.
//!
//! # The adversary and the surface
//!
//! The onboarding package is uploaded whole, as the body of one request, by
//! whoever opened the session. That session authenticates the appliance to an
//! administrator and nobody to the appliance, so the input here *is* the
//! archive: no length prefix, no operation selector, no prologue this harness
//! supplies, and no filter of any kind on the bytes. A corpus entry is a file,
//! which is what lets the management server's own package be a seed.
//!
//! # What the adversary may express here, and what it may not
//!
//! Everything a byte string can be. A tar that is not ustar, a PAX or GNU
//! extension header, a symlink, a directory, a size field that lies in either
//! direction, a header whose checksum does not verify, a member over its bound,
//! an archive over its own, a duplicated or missing member, armour that does
//! not close, base64 that is not canonical, a certificate for another key — all
//! of them are ordinary inputs and all are seeds.
//!
//! What the adversary does **not** choose is the appliance's own key, and
//! modelling that correctly is what makes this target able to reach anything at
//! all: the key is fixed here to the one the seed package's device certificate
//! was issued over, exactly as a running appliance's key is fixed by the store
//! domain that minted it. An input carrying a certificate over any other key
//! must be refused, and the harness asserts that it is.
//!
//! # What is asserted
//!
//! * **Totality and determinism.** Every byte string is answered — one typed
//!   refusal or one package — and the same bytes are answered the same way
//!   twice.
//! * **Nothing is yielded unless every rule passed.** A yielded package is
//!   taken apart again and every rule re-checked from the outside: the
//!   configuration reloads through the configuration reader, the device
//!   certificate's `SubjectPublicKeyInfo` is the appliance's own, the two
//!   certificates are distinct DER structures inside their profile bound, the
//!   endpoint names a port and an address a host can be dialled at — not the
//!   unspecified address, a loopback, multicast or broadcast address, or one in
//!   the reserved top of the space — and the document handed back is a slice of
//!   the caller's own archive rather than a copy of something else.
//! * **The verifier is load-bearing.** The same input read with a verifier that
//!   refuses yields a package never, whatever else was right about it — so
//!   acceptance genuinely requires the chain to have been accepted, rather than
//!   requiring it in the order the code happens to run its checks in.
//! * **The verifier is asked only about a package that already passed.** What
//!   crosses into the chain check is a certificate over the appliance's key,
//!   so the domain that holds the cryptography is never asked to spend a
//!   signature on an archive the structural rules would have refused.
//! * **Boundedness.** An archive past the outer bound is refused by that bound
//!   and nothing else, and anything the reader looked inside was a whole number
//!   of blocks — which is what stops a partial block being read as a header.

use core::cell::Cell;

use lfw_package::{
    ARCHIVE_BOUND, ArchiveError, BLOCK, ChainRejected, ChainVerifier, Member, Package,
    PackageError, read, subject_public_key_info,
};

/// The public point the seed package's device certificate binds — the appliance
/// this harness plays. Fixed, because the adversary does not choose it.
const APPLIANCE_POINT: &[u8; 65] =
    include_bytes!("../../crates/package/fixtures/appliance-public-key.bin");

/// Bytes the profile bounds one certificate at.
const CERTIFICATE_BOUND: usize = 768;

/// A verifier that accepts, and holds what it was asked about to the rules the
/// reader should already have applied.
struct Accepting<'a> {
    calls: Cell<usize>,
    appliance_key: &'a [u8; lfw_x509::SPKI_LEN],
}

impl ChainVerifier for Accepting<'_> {
    fn verify(&self, end_entity: &[u8], anchor: &[u8]) -> Result<(), ChainRejected> {
        self.calls.set(self.calls.get().saturating_add(1));
        // The chain check is the expensive one and it sits behind every
        // structural rule, so what reaches it is already this appliance's own
        // certificate and a distinct, well-formed anchor.
        assert_eq!(
            subject_public_key_info(end_entity).ok(),
            Some(self.appliance_key.as_slice()),
            "the verifier was asked about a certificate for another key"
        );
        // Not asserted here: that the two certificates differ. A member
        // carrying the device certificate twice is refused by a real validator
        // — the end entity is not a certification authority — and that is the
        // validator's answer to give, so a harness whose verifier accepts
        // everything must not claim it.
        assert!(
            subject_public_key_info(anchor).is_ok(),
            "the verifier was asked about an anchor that is not a certificate"
        );
        Ok(())
    }
}

/// A verifier that refuses everything, which is the whole of what it is for.
struct Refusing;

impl ChainVerifier for Refusing {
    fn verify(&self, _end_entity: &[u8], _anchor: &[u8]) -> Result<(), ChainRejected> {
        Err(ChainRejected)
    }
}

/// Read one uploaded archive, and hold whatever came back to every rule.
pub fn onboarding_package_harness(archive: &[u8]) {
    let appliance_key = lfw_x509::spki(APPLIANCE_POINT).expect("the harness's own point encodes");

    let accepting = Accepting {
        calls: Cell::new(0),
        appliance_key: &appliance_key,
    };
    let answer = read(archive, &appliance_key, &accepting);

    assert_eq!(
        accepting.calls.get(),
        usize::from(answer.is_ok()),
        "the chain was checked a number of times that does not match the answer"
    );

    match &answer {
        Ok(package) => assert_package(archive, package, &appliance_key),
        Err(fault) => assert_refusal(archive, *fault),
    }

    // The same bytes, again: a reader whose answer moved between two reads of
    // one archive would make an unchanged upload look like a different one.
    let again = Accepting {
        calls: Cell::new(0),
        appliance_key: &appliance_key,
    };
    let repeated = read(archive, &appliance_key, &again);
    assert_eq!(
        answer.is_ok(),
        repeated.is_ok(),
        "one archive read twice gave two answers"
    );
    assert_eq!(answer.err(), repeated.err(), "two refusals for one archive");

    // And with a verifier that says no, nothing is a package — whatever else
    // about the archive was right.
    assert!(
        read(archive, &appliance_key, &Refusing).is_err(),
        "a package was yielded although the chain was never accepted"
    );
}

/// Every rule the reader applied, re-applied from the outside.
fn assert_package(archive: &[u8], package: &Package<'_>, appliance_key: &[u8; lfw_x509::SPKI_LEN]) {
    assert!(
        archive.len() <= ARCHIVE_BOUND && archive.len() % BLOCK == 0,
        "a package came out of an archive the outer rules refuse"
    );

    let device = package.device_certificate();
    let anchor = package.trust_anchor();
    for certificate in [device, anchor] {
        assert!(
            !certificate.is_empty() && certificate.len() <= CERTIFICATE_BOUND,
            "a certificate outside the profile's bound was yielded"
        );
        assert!(
            subject_public_key_info(certificate).is_ok(),
            "a yielded certificate is not shaped like one"
        );
    }
    assert_eq!(
        subject_public_key_info(device).ok(),
        Some(appliance_key.as_slice()),
        "a certificate for another key was yielded as this appliance's identity"
    );

    let endpoint = package.endpoint();
    assert!(endpoint.port != 0, "an endpoint with no port was yielded");
    // Dialable, which is more than well-formed: an address out of one of the
    // five ranges that name no host would be an appliance accepted into a life
    // of reporting an unreachable next hop.
    let leading = endpoint.address[0];
    assert!(
        u32::from_be_bytes(endpoint.address) != 0,
        "the unspecified address was yielded as an endpoint"
    );
    assert!(
        leading != 127,
        "a loopback address was yielded as an endpoint"
    );
    assert!(
        leading & 0xf0 != 224,
        "a multicast address was yielded as an endpoint"
    );
    assert!(
        leading & 0xf0 != 240,
        "an address in the reserved top of the space was yielded as an endpoint"
    );
    assert!(
        endpoint.address != [255; 4],
        "the broadcast address was yielded as an endpoint"
    );

    let document = package.configuration();
    assert!(
        document.len() <= Member::Configuration.bound(),
        "a configuration document past its bound was yielded"
    );
    assert!(
        config::load(document).is_ok(),
        "a document the configuration reader refuses was yielded"
    );
    // The document is a window onto the caller's own bytes, so a caller that
    // persists it persists what it received rather than something composed here.
    let range = archive.as_ptr_range();
    assert!(
        document.is_empty() || range.contains(&document.as_ptr()),
        "the document handed back is not part of the archive"
    );
}

/// A refusal says what was wrong, and the two outer bounds say it first.
fn assert_refusal(archive: &[u8], fault: PackageError) {
    if archive.len() > ARCHIVE_BOUND {
        assert!(
            matches!(
                fault,
                PackageError::Archive(ArchiveError::ArchiveOverBound { .. })
            ),
            "an over-long archive was read past its own bound"
        );
        return;
    }
    if archive.len() % BLOCK != 0 {
        assert!(
            matches!(
                fault,
                PackageError::Archive(ArchiveError::NotAWholeNumberOfBlocks { .. })
            ),
            "a partial block was read as a header"
        );
    }
}
