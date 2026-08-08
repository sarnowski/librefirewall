//! Taking ownership of the appliance out of an onboarding package: every rule
//! the package contract states, checked again here, and the one signature this
//! appliance verifies for itself.
//!
//! # The adversary
//!
//! A **management-plane attacker**, and a **byzantine neighbour protection
//! domain** behind them. The archive is the body of an upload authenticated by
//! nothing but the session it arrived in, and by the time it reaches here it has
//! been across a shared region a second domain writes — so both parties chose
//! these bytes and neither is trusted. Every rule below is applied to a snapshot
//! the caller already took, which is what makes "the bytes that were checked are
//! the bytes that are installed" a property rather than a hope.
//!
//! # Why this check exists when another one already ran
//!
//! The domain that terminates the upload validates the package too, against the
//! adopted certificate validator — a general chain policy over a general X.509
//! reader. This is deliberately **not** that check repeated, and the difference
//! is the whole reason it is worth running twice:
//!
//! * **What it repeats** is everything structural: the archive's framing, the
//!   armour around each certificate, the shape of the DER inside it, the endpoint
//!   line, and the configuration document against the reader every document goes
//!   through. Those are the rules that decide whether a package is well formed,
//!   and repeating them here means the domain that *writes the medium* has read
//!   the bytes it is about to write rather than been told about them.
//!
//! * **What it adds** is the one question this domain can answer better than
//!   anybody: whether the device certificate binds **this appliance's own key**.
//!   The key it compares against is the point in its own state record, not the
//!   point the package offers and not one a peer named over a channel, so a
//!   package carrying somebody else's identity has nothing here to match.
//!
//! * **What it does not add** is a chain validation. It verifies **one
//!   signature** — the anchor's over the device certificate — under **one
//!   profile**: one algorithm, one curve, a path of length one, and no policy at
//!   all. Name constraints, key usage, basic constraints, validity windows,
//!   revocation and every other thing a validator weighs are the other domain's,
//!   and none of them is decided here. So a package this check accepts is one
//!   whose anchor really did sign its device certificate and whose bytes are well
//!   formed — and that is a *narrower* claim than the one the validator makes,
//!   deliberately, because a second general X.509 policy engine in the domain
//!   that holds the private key is exactly what this appliance declines to have.
//!
//! Two checks that agree say the package survived two independent readings of
//! it. Two checks that disagree say something between them changed the bytes,
//! which is worth far more than a third opinion would have been.
//!
//! # What an accepted package changes, and what it does not yet
//!
//! The device certificate, the trust anchor and the endpoint, together and under
//! one new generation. The **configuration document** it carried is read and
//! held to every rule and then goes nowhere: persisting it means placing it in
//! the slot array and telling the domain that owns configuration about it, which
//! is a handover this crate does not reach. That is a deliberate gap rather than
//! an oversight, and it is why [`Adoption`] has no field for one — a value
//! carrying a document nothing writes would read as though something did.
//!
//! # No allocator, and one signature's worth of arithmetic
//!
//! Everything here is fixed storage or a borrow of the caller's snapshot. The
//! signature verification is the only cryptography, it runs last, and it runs
//! only once — a malformed archive never reaches it.

use core::cell::Cell;

use lfw_crypto::{DIGEST_LEN, P256_PUBLIC_LEN, p256_verify, sha256};
use lfw_package::{
    BIT_STRING, ChainRejected, ChainVerifier, Element, INTEGER, OBJECT_IDENTIFIER, Package,
    PackageError, SEQUENCE, read_tlv, subject_public_key_info,
};
use lfw_x509::{DerError, oid, spki};

use crate::state::{Onboarding, State, StateError, StoredCertificate, StoredEndpoint};

/// Why the one signature this appliance verifies for itself did not hold.
///
/// One variant per distinct rule, because each sends somebody somewhere else: a
/// curve this profile does not have is a management server issuing under the
/// wrong algorithm, a malformed encoding is a writer that is broken, and a
/// signature that simply does not verify is an anchor that did not issue this
/// certificate at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainFault {
    /// The device certificate is not one SEQUENCE with nothing after it.
    /// Unreachable by the time this runs, the package reader having decoded it,
    /// and answered rather than asserted because nothing about a package may
    /// fault the domain that reads one.
    MalformedCertificate,
    /// The `AlgorithmIdentifier` beside the signature is not one this walk can
    /// read.
    MalformedSignatureAlgorithm,
    /// The signature is not a BIT STRING of whole octets.
    MalformedSignature,
    /// The anchor's `SubjectPublicKeyInfo` does not hold an algorithm and a key.
    MalformedAnchorKey,
    /// The certificate is signed with something other than the one algorithm
    /// this profile fixes.
    SignatureAlgorithmNotEcdsaSha256,
    /// The algorithm named inside the signed body and the one named beside the
    /// signature disagree, so the certificate states two answers to what signed
    /// it.
    SignatureAlgorithmsDisagree,
    /// The anchor holds a key of a kind or a curve this profile has no
    /// verification for, so nothing here could check its signature.
    AnchorKeyNotP256,
    /// The anchor's key is a point nothing accepts, or the signature is not the
    /// canonical encoding of two in-range integers, or it simply does not
    /// verify. One variant, because those are the three ways an answer is *no*
    /// and a forger learns nothing from being told which.
    NotAuthentic,
}

/// Why an onboarding package did not become this appliance's ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallError {
    /// The appliance already has an owner. Refused rather than replaced: a
    /// package delivered over a channel could otherwise move an appliance from
    /// one management plane to another, and the ownership model makes a factory
    /// reset the only way back.
    AlreadyOwned,
    /// The stated archive length names more bytes than the caller staged, so
    /// there is no archive of that length to read.
    ArchivePastRegion { len: u32, staged: usize },
    /// This appliance's own `SubjectPublicKeyInfo` could not be encoded, which
    /// its fixed length makes unreachable and which is answered rather than
    /// asserted for that reason.
    ApplianceKey(DerError),
    /// The package broke one of the contract's own rules.
    Package(PackageError),
    /// The one signature this appliance verifies did not hold.
    Chain(ChainFault),
    /// What the package carried does not fit the state record. Unreachable while
    /// the profile's bound and the record's agree, and held to that by the
    /// assertion at the foot of this file.
    Storage(StateError),
}

impl From<StateError> for InstallError {
    fn from(error: StateError) -> Self {
        Self::Storage(error)
    }
}

/// Everything an accepted package changes about this appliance, and nothing
/// else.
///
/// The configuration document the package carried is deliberately absent: it was
/// read and held to every rule, and what becomes of it is a decision for the
/// domain that owns configuration rather than a field of the ownership record.
pub struct Adoption {
    device_certificate: StoredCertificate,
    anchor_certificate: StoredCertificate,
    endpoint: StoredEndpoint,
    anchor_fingerprint: [u8; DIGEST_LEN],
}

impl Adoption {
    /// SHA-256 over the delivered anchor's DER `SubjectPublicKeyInfo` — the
    /// appliance's own fingerprint definition applied to the authority it has
    /// just accepted, so an administrator compares one kind of string against
    /// one kind of string.
    #[must_use]
    pub const fn anchor_fingerprint(&self) -> [u8; DIGEST_LEN] {
        self.anchor_fingerprint
    }

    /// Where this appliance will answer to.
    #[must_use]
    pub const fn endpoint(&self) -> StoredEndpoint {
        self.endpoint
    }

    /// Write this ownership into `state`, which advances its generation and so
    /// selects the copy the next commit lands in.
    ///
    /// It consumes the adoption, so the one value that says a package passed
    /// every rule is spent exactly where the record changes.
    pub fn take_ownership(self, state: &mut State) {
        state.adopt(
            self.device_certificate,
            self.anchor_certificate,
            self.endpoint,
        );
    }
}

/// Read a package out of `staged` and answer the ownership it establishes.
///
/// `stated_len` is the length the asking side claimed and is **not trusted**: it
/// is ranged against what was really staged before a byte is read. `staged` is
/// the caller's own snapshot of whatever region the archive crossed in — a
/// borrow of that region instead would let its writer change the bytes between
/// a rule passing and the record being written.
///
/// # Errors
/// [`InstallError`], one variant per rule, and the appliance is unchanged on
/// every one of them: a package with one bad member takes no ownership at all.
pub fn read(stated_len: u32, staged: &[u8], state: &State) -> Result<Adoption, InstallError> {
    if matches!(state.onboarding(), Onboarding::Onboarded) {
        return Err(InstallError::AlreadyOwned);
    }
    let Some(archive) = staged.get(..stated_len as usize) else {
        return Err(InstallError::ArchivePastRegion {
            len: stated_len,
            staged: staged.len(),
        });
    };
    // The appliance's own key, out of its own record. The package's device
    // certificate is compared against this and never against anything the
    // package or a peer offers, which is what makes somebody else's identity
    // unmatchable rather than merely refused.
    let appliance_key = spki(&state.public_key()).map_err(InstallError::ApplianceKey)?;

    let chain = ProfileChain::new();
    let package = lfw_package::read(archive, &appliance_key, &chain).map_err(|error| {
        // The injected verifier answers yes or no by design, so the reason it
        // said no is recorded beside it and picked up here. The fallback names
        // the package reader's own token and is unreachable: every path that
        // refuses a chain records why first.
        match error {
            PackageError::ChainNotVerified => chain
                .fault()
                .map_or(InstallError::Package(error), InstallError::Chain),
            other => InstallError::Package(other),
        }
    })?;

    adoption_of(&package)
}

/// What an accepted package becomes on the medium.
fn adoption_of(package: &Package<'_>) -> Result<Adoption, InstallError> {
    let anchor = package.trust_anchor();
    // The anchor's own `SubjectPublicKeyInfo`, taken by the same walk the key
    // check uses rather than by searching the certificate: a digest over bytes
    // found by a search would be a digest of whatever matched.
    let anchor_spki = subject_public_key_info(anchor)
        .map_err(|error| InstallError::Package(PackageError::TrustAnchor(error)))?;
    Ok(Adoption {
        device_certificate: StoredCertificate::new(package.device_certificate())?,
        anchor_certificate: StoredCertificate::new(anchor)?,
        endpoint: StoredEndpoint {
            address: package.endpoint().address,
            port: package.endpoint().port,
        },
        anchor_fingerprint: sha256(anchor_spki),
    })
}

/// The one-signature verifier this appliance runs for itself.
///
/// It carries a cell rather than answering a reason, because the injected
/// interface is a yes or a no on purpose — *why* a chain failed is the
/// validator's own vocabulary — and this validator's vocabulary happens to be
/// this appliance's. The cell is written on exactly the paths that return an
/// error and is read once, by the call that asked.
struct ProfileChain {
    fault: Cell<Option<ChainFault>>,
}

impl ProfileChain {
    const fn new() -> Self {
        Self {
            fault: Cell::new(None),
        }
    }

    fn fault(&self) -> Option<ChainFault> {
        self.fault.get()
    }
}

impl ChainVerifier for ProfileChain {
    fn verify(&self, end_entity: &[u8], anchor: &[u8]) -> Result<(), ChainRejected> {
        match verify_one_signature(end_entity, anchor) {
            Ok(()) => Ok(()),
            Err(fault) => {
                self.fault.set(Some(fault));
                Err(ChainRejected)
            }
        }
    }
}

/// Whether `anchor` signed `end_entity`, under the one profile this appliance
/// has.
///
/// Four descents and one verification, none of them a loop: the anchor's point,
/// the signed body, the algorithm named in two places, and the signature.
fn verify_one_signature(end_entity: &[u8], anchor: &[u8]) -> Result<(), ChainFault> {
    let point = anchor_point(anchor)?;
    let signed = signed_body(end_entity)?;
    p256_verify(&point, signed.tbs, signed.signature).map_err(|_| ChainFault::NotAuthentic)
}

/// A certificate taken apart into the three things a verification needs.
struct SignedBody<'a> {
    /// The whole `tbsCertificate`, tag and length included — which is what was
    /// signed, and not merely its content.
    tbs: &'a [u8],
    signature: &'a [u8],
}

fn signed_body(certificate: &[u8]) -> Result<SignedBody<'_>, ChainFault> {
    let (body, after) = read_tlv(certificate, Element::Certificate, SEQUENCE)
        .map_err(|_| ChainFault::MalformedCertificate)?;
    if !after.is_empty() {
        return Err(ChainFault::MalformedCertificate);
    }
    let (_, after_tbs) = read_tlv(body, Element::TbsCertificate, SEQUENCE)
        .map_err(|_| ChainFault::MalformedCertificate)?;
    // The signed body as bytes: everything the tbs read consumed, tag and length
    // included, because that is what a signature is over.
    let tbs = body
        .get(..body.len().saturating_sub(after_tbs.len()))
        .ok_or(ChainFault::MalformedCertificate)?;

    let (algorithm, after_algorithm) = read_tlv(after_tbs, Element::SignatureAlgorithm, SEQUENCE)
        .map_err(|_| ChainFault::MalformedSignatureAlgorithm)?;
    if !names_algorithm(algorithm, oid::ECDSA_WITH_SHA256)? {
        return Err(ChainFault::SignatureAlgorithmNotEcdsaSha256);
    }
    // RFC 5280's own consistency rule: a certificate names the algorithm twice
    // and a certificate whose two answers differ is one nothing should read.
    if inner_algorithm(tbs)? != algorithm {
        return Err(ChainFault::SignatureAlgorithmsDisagree);
    }

    let (bits, after_signature) = read_tlv(after_algorithm, Element::SignatureValue, BIT_STRING)
        .map_err(|_| ChainFault::MalformedSignature)?;
    if !after_signature.is_empty() {
        return Err(ChainFault::MalformedCertificate);
    }
    let signature = whole_octets(bits).ok_or(ChainFault::MalformedSignature)?;
    Ok(SignedBody { tbs, signature })
}

/// The `AlgorithmIdentifier` the signed body itself names, which a certificate
/// carries as the third element of its `tbsCertificate`.
fn inner_algorithm(tbs: &[u8]) -> Result<&[u8], ChainFault> {
    let malformed = |_| ChainFault::MalformedSignatureAlgorithm;
    let (inside, _) = read_tlv(tbs, Element::TbsCertificate, SEQUENCE).map_err(malformed)?;
    let (_, rest) =
        read_tlv(inside, Element::Version, lfw_package::CONTEXT_ZERO).map_err(malformed)?;
    let (_, rest) = read_tlv(rest, Element::SerialNumber, INTEGER).map_err(malformed)?;
    let (algorithm, _) =
        read_tlv(rest, Element::SignatureAlgorithm, SEQUENCE).map_err(malformed)?;
    Ok(algorithm)
}

/// The uncompressed SEC1 point the anchor's `SubjectPublicKeyInfo` binds.
fn anchor_point(anchor: &[u8]) -> Result<[u8; P256_PUBLIC_LEN], ChainFault> {
    let malformed = |_| ChainFault::MalformedAnchorKey;
    let spki = subject_public_key_info(anchor).map_err(malformed)?;
    let (inside, _) = read_tlv(spki, Element::SubjectPublicKeyInfo, SEQUENCE).map_err(malformed)?;
    let (algorithm, after_algorithm) =
        read_tlv(inside, Element::AlgorithmIdentifier, SEQUENCE).map_err(malformed)?;
    // One kind of key and one curve, which is the whole of what this appliance
    // can verify under: an anchor holding anything else is refused for that
    // rather than failing a verification nothing could have run.
    if !names_curve(algorithm)? {
        return Err(ChainFault::AnchorKeyNotP256);
    }
    let (bits, after_key) =
        read_tlv(after_algorithm, Element::SubjectPublicKey, BIT_STRING).map_err(malformed)?;
    if !after_key.is_empty() {
        return Err(ChainFault::MalformedAnchorKey);
    }
    let point = whole_octets(bits).ok_or(ChainFault::MalformedAnchorKey)?;
    let mut encoded = [0_u8; P256_PUBLIC_LEN];
    if point.len() != P256_PUBLIC_LEN {
        return Err(ChainFault::AnchorKeyNotP256);
    }
    for (slot, byte) in encoded.iter_mut().zip(point) {
        *slot = *byte;
    }
    Ok(encoded)
}

/// Whether an `AlgorithmIdentifier` names `wanted` and nothing after it.
///
/// ECDSA-with-SHA-256 takes no parameters, so an identifier carrying any is one
/// this profile does not write and does not read.
fn names_algorithm(algorithm: &[u8], wanted: &[u8]) -> Result<bool, ChainFault> {
    let (identifier, rest) = read_tlv(algorithm, Element::AlgorithmIdentifier, OBJECT_IDENTIFIER)
        .map_err(|_| ChainFault::MalformedSignatureAlgorithm)?;
    Ok(identifier == wanted && rest.is_empty())
}

/// Whether a key's `AlgorithmIdentifier` names an elliptic-curve key on P-256,
/// and nothing after the curve.
fn names_curve(algorithm: &[u8]) -> Result<bool, ChainFault> {
    let malformed = |_| ChainFault::MalformedAnchorKey;
    let (kind, after_kind) =
        read_tlv(algorithm, Element::AlgorithmIdentifier, OBJECT_IDENTIFIER).map_err(malformed)?;
    if kind != oid::EC_PUBLIC_KEY {
        return Ok(false);
    }
    let (curve, rest) =
        read_tlv(after_kind, Element::AlgorithmIdentifier, OBJECT_IDENTIFIER).map_err(malformed)?;
    Ok(curve == oid::PRIME256V1 && rest.is_empty())
}

/// A BIT STRING's octets, or `None` where it does not hold a whole number of
/// them.
///
/// The leading octet of a BIT STRING says how many bits of the last byte are
/// padding, and a key or a signature is bytes: anything but zero there is an
/// encoding this profile neither writes nor accepts.
fn whole_octets(bits: &[u8]) -> Option<&[u8]> {
    let (unused, octets) = bits.split_first()?;
    (*unused == 0).then_some(octets)
}

// The record and the profile each bound a certificate, and the package reader
// bounds one too. A package member the record could not hold would refuse every
// well-formed package on the last step, which is the one place a length must not
// be discovered.
const _: () = {
    assert!(lfw_x509::MAX_CERTIFICATE_LEN <= crate::MAX_STORED_CERTIFICATE);
    assert!(P256_PUBLIC_LEN == lfw_crypto::P256_PUBLIC_LEN);
};

#[cfg(test)]
mod tests;
