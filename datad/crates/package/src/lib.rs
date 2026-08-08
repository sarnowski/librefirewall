#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! The onboarding package an administrator uploads: an uncompressed ustar
//! archive of exactly four members, and the rules each of them must satisfy
//! before any of it is installed.
//!
//! Nothing partial leaves here. [`Package`] has no public constructor and no
//! public field, and the value the members are staged in is crate-private, so
//! the only way to hold one is to have called [`read`] and had every rule pass
//! — which is what "the package is validated whole before anything is
//! installed" means when it is a type rather than a sentence.
//!
//! # Adversary
//!
//! A **management-plane attacker**. The upload arrives inside the TLS session
//! an administrator opened to this appliance after checking its fingerprint out
//! of band, and that session is the whole of the package's authentication: it
//! says the bytes came from whoever the administrator was talking to and
//! nothing about what the bytes are. So the archive is attacker-shaped
//! throughout, and an authenticated session is not a reason to relax one rule
//! of it.
//!
//! # The chain check is not written here
//!
//! Whether the device certificate chains to the anchor is a cryptographic
//! question and is answered by the adopted validator, which lives with the
//! cryptography this appliance adopted rather than in a parser. It arrives as
//! [`ChainVerifier`], supplied by the caller; a [`Package`] cannot be built
//! without one having accepted, because the private token that says so is what
//! the constructor takes. Whether the anchor is a certification authority at
//! all is part of that same answer — an anchor lacking the constraint fails the
//! validator — so no extension is walked here.
//!
//! What *is* decided here about the certificates is structural, and that is the
//! reason the key check is here: the device certificate must bind this
//! appliance's own key, which is an equality between two byte strings and not a
//! judgement about a signature. The appliance's key is an argument rather than
//! something read out of the archive, so a package carrying somebody else's
//! identity has nothing to be compared against and is refused by construction.
//!
//! # Constraints, and what was given up to meet them
//!
//! * **No allocator.** The two certificates are undone from their armour into
//!   fixed storage sized by the profile; everything else is borrowed out of the
//!   archive the caller still owns.
//! * **The configuration member is read by the configuration reader**, not by
//!   anything here, and the model it produces is deliberately not carried: what
//!   a caller is given is the document's own bytes, which is what it persists,
//!   together with the fact that they were accepted.

mod archive;
mod certificate;
mod endpoint;

#[cfg(test)]
mod tests;

pub use archive::{ARCHIVE_BOUND, ArchiveError, BLOCK, EmptyField, Member, NumericField};
pub use certificate::{CertificateError, Element, subject_public_key_info};
pub use endpoint::{Endpoint, EndpointError};

use certificate::Certificate;
use config::ConfigError;
use lfw_x509::SPKI_LEN;

/// The verifier said no. One shape, because *why* a chain failed is the
/// validator's own vocabulary and belongs where the validator is; what this
/// crate needs from it is whether the answer was yes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainRejected;

/// Deciding whether a device certificate chains to an anchor.
///
/// Injected rather than implemented: the appliance has exactly one certificate
/// parser and it is the adopted one, in the domain that holds the adopted
/// cryptography. A second parser here — written to answer the same question
/// less well — would be the parser an attacker reached first.
pub trait ChainVerifier {
    /// Whether `end_entity` chains to `anchor`, both DER.
    ///
    /// # Errors
    /// [`ChainRejected`] for every way the answer is no.
    fn verify(&self, end_entity: &[u8], anchor: &[u8]) -> Result<(), ChainRejected>;
}

/// A chain a [`ChainVerifier`] accepted.
///
/// Private, and constructed in exactly one place: the call that asked. A
/// [`Package`] takes one, so a future edit that dropped the verification would
/// have nothing to build a package out of and would not compile.
struct ChainAccepted(());

/// Why a byte string is not an onboarding package.
///
/// The two certificates carry their faults separately: an administrator told
/// only that "a certificate is malformed" has two files to go and look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackageError {
    Archive(ArchiveError),
    DeviceCertificate(CertificateError),
    TrustAnchor(CertificateError),
    /// The device certificate binds a key that is not this appliance's, which
    /// is somebody else's identity however well formed it is.
    DeviceKeyIsNotThisAppliance,
    Endpoint(EndpointError),
    Configuration(ConfigError),
    /// The device certificate does not chain to the delivered anchor, which is
    /// the anchor this appliance would afterwards validate its channel against.
    ChainNotVerified,
}

/// A package every rule has passed, and the only shape one is ever seen in.
///
/// Borrows the configuration document out of the archive the caller owns; the
/// certificates cannot be borrowed, their armour having had to come off.
pub struct Package<'a> {
    device_certificate: Certificate,
    trust_anchor: Certificate,
    endpoint: Endpoint,
    configuration: &'a [u8],
}

impl<'a> Package<'a> {
    /// The device certificate, as DER, binding this appliance's own key.
    #[must_use]
    pub fn device_certificate(&self) -> &[u8] {
        self.device_certificate.as_bytes()
    }

    /// The management authority's certificate, as DER.
    #[must_use]
    pub fn trust_anchor(&self) -> &[u8] {
        self.trust_anchor.as_bytes()
    }

    /// Where this appliance answers to.
    #[must_use]
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// The configuration document, exactly as the archive carried it.
    #[must_use]
    pub const fn configuration(&self) -> &'a [u8] {
        self.configuration
    }
}

/// Read a package whole, or say which rule refused it.
///
/// `appliance_key` is this appliance's own `SubjectPublicKeyInfo`, in the
/// encoding it renders its key in; the device certificate must bind exactly it.
///
/// # Errors
/// [`PackageError`], one variant per rule, and nothing is installed on any of
/// them: a package with one bad member yields no package at all.
pub fn read<'a, V: ChainVerifier + ?Sized>(
    archive: &'a [u8],
    appliance_key: &[u8; SPKI_LEN],
    verifier: &V,
) -> Result<Package<'a>, PackageError> {
    let staged = archive::stage(archive).map_err(PackageError::Archive)?;

    let device_certificate =
        certificate::decode(staged.device_certificate).map_err(PackageError::DeviceCertificate)?;
    let trust_anchor =
        certificate::decode(staged.trust_anchor).map_err(PackageError::TrustAnchor)?;

    if !certificate::binds_key(&device_certificate, appliance_key)
        .map_err(PackageError::DeviceCertificate)?
    {
        return Err(PackageError::DeviceKeyIsNotThisAppliance);
    }

    let endpoint = endpoint::parse(staged.management_endpoint).map_err(PackageError::Endpoint)?;
    config::load(staged.configuration).map_err(PackageError::Configuration)?;

    // Last, because it is the one rule that costs signature arithmetic: a
    // malformed archive never reaches the domain's cryptography at all.
    let accepted = verifier
        .verify(device_certificate.as_bytes(), trust_anchor.as_bytes())
        .map(|()| ChainAccepted(()))
        .map_err(|ChainRejected| PackageError::ChainNotVerified)?;

    Ok(sealed(
        device_certificate,
        trust_anchor,
        endpoint,
        staged.configuration,
        accepted,
    ))
}

/// The one place a [`Package`] is built, and it takes the proof.
fn sealed<'a>(
    device_certificate: Certificate,
    trust_anchor: Certificate,
    endpoint: Endpoint,
    configuration: &'a [u8],
    _chain: ChainAccepted,
) -> Package<'a> {
    Package {
        device_certificate,
        trust_anchor,
        endpoint,
        configuration,
    }
}
