//! What makes this appliance *this* appliance: the 128-bit name, the signing key
//! behind it, the self-signed certificate that binds the two, and the
//! fingerprint an administrator authenticates the node by.
//!
//! Minting and verifying both live here rather than in the protection domain
//! that owns the medium, because both are arithmetic over bytes: given the same
//! randomness and the same instant, [`mint`] produces the same identity on a host
//! as it does on the appliance, and [`verify`] answers the same question about a
//! decoded record either way. What the domain keeps is the device, the entropy
//! and the `unsafe` — none of which a test can hold.
//!
//! # Why the certificate is written here and not left to the domain
//!
//! An identity is not a keypair; it is a keypair *with a certificate that binds
//! it to a name*, and the two are minted in one step so no boot can reach a state
//! holding one without the other. A domain that wrote the certificate separately
//! would have a window in which the medium carried a key and no proof of whose it
//! is, and the recovery from a power cut inside that window is a question nobody
//! should have to answer.
//!
//! # The adversary
//!
//! On the minting path, none: every input is a hardware draw or a compile-time
//! constant, and the one number that comes from elsewhere — the wall clock — only
//! bounds a validity window and is treated as the unauthenticated reading it is.
//!
//! On the reload path, **a physical attacker who wrote the medium at leisure**.
//! By the time [`verify`] runs, `state`'s digest has held and its lengths are
//! inside their bounds — that is what a [`crate::CheckedState`] means — and what
//! is left is the question a digest cannot answer: whether the three things the
//! record claims about one identity agree with each other. A record whose public
//! point is not its scalar's, or whose certificate binds a different key, is one
//! this appliance never wrote, and it is refused rather than repaired: signing
//! under a key whose certificate names another is a node that cannot be
//! authenticated and does not know it.
//!
//! Nothing here renders, formats or returns a private scalar. What leaves is a
//! name, a public point, a certificate and a digest.

use lfw_crypto::{DIGEST_LEN, Entropy, P256_PUBLIC_LEN, P256SecretKey, zeroize};
use lfw_x509::{
    CertificateKind, DerError, DeviceId, Profile, ProfileError, Serial, Validity, spki_fingerprint,
    write_certificate,
};

use crate::state::{DEVICE_ID_BYTES, SECRET_LEN, State, StateError, StoredCertificate};

/// Why an identity could not be minted, or why a decoded one is not one.
///
/// Each variant names what disagreed and never a byte of key material: a refusal
/// that echoed a scalar would put one on whatever surface reported the refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// Key generation drew no scalar inside the group order, which a working
    /// generator does not reach. Its own variant because it is the one failure on
    /// this path that is the *hardware's* rather than the medium's.
    KeyUnusable,
    /// The onboarding certificate could not be written.
    Certificate(ProfileError),
    /// The `SubjectPublicKeyInfo` could not be encoded, which its fixed length
    /// makes unreachable and which is answered rather than asserted for that
    /// reason.
    Fingerprint(DerError),
    /// The certificate did not fit the record. Unreachable while the profile's
    /// own bound and the record's agree, and held to that by an assertion below.
    Storage(StateError),
    /// The stored scalar is not a private key: zero, or not below the group
    /// order. A record nothing this appliance runs wrote.
    ScalarUnusable,
    /// The stored public point is not the point the stored scalar derives, so the
    /// record's two halves describe two different keys.
    PublicKeyMismatch,
    /// The stored certificate does not bind the stored public key, so a peer
    /// validating the certificate would be trusting a key this node cannot sign
    /// with.
    CertificateKeyMismatch,
    /// The record carries no certificate at all, which every state this appliance
    /// mints does.
    CertificateAbsent,
}

impl From<ProfileError> for IdentityError {
    fn from(error: ProfileError) -> Self {
        Self::Certificate(error)
    }
}

impl From<DerError> for IdentityError {
    fn from(error: DerError) -> Self {
        Self::Fingerprint(error)
    }
}

impl IdentityError {
    /// The console cause token for this refusal.
    ///
    /// Here rather than at the domain, so the one place that knows what each
    /// variant means is the one place that names it — and so a variant added
    /// cannot reach a console line as another's token.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::KeyUnusable => "device-key-ungenerable",
            Self::Certificate(_) => "onboarding-certificate-unwritable",
            Self::Fingerprint(_) => "public-key-unencodable",
            Self::Storage(_) => "certificate-too-long-for-record",
            Self::ScalarUnusable => "stored-scalar-unusable",
            Self::PublicKeyMismatch => "stored-public-key-mismatch",
            Self::CertificateKeyMismatch => "stored-certificate-key-mismatch",
            Self::CertificateAbsent => "stored-certificate-absent",
        }
    }
}

/// An identity as everything outside this module may see it: the public name,
/// the key's fingerprint, and nothing else.
///
/// The scalar is deliberately absent. It reaches its one consumer through
/// [`State::secret_scalar`], which is the accessor that documents who may have
/// it; a copy in this type would be a second path to the same bytes and a second
/// thing to keep off every surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The 128-bit name, as the type that renders it.
    pub device: DeviceId,
    /// SHA-256 over the DER `SubjectPublicKeyInfo` of the appliance's public
    /// key — the one definition of a fingerprint, taken from the one place that
    /// holds it.
    pub fingerprint: [u8; DIGEST_LEN],
}

/// What a fresh medium's first boot produces: the state to write, and the
/// identity to report.
pub struct Minted {
    /// Generation one, unowned, carrying the keypair and the onboarding
    /// certificate. The caller writes it; nothing here touches a device.
    pub state: State,
    pub identity: Identity,
}

/// Mint an identity: 128 bits of name, a P-256 keypair, a self-signed onboarding
/// certificate over the two, and the fingerprint of the key.
///
/// `now` is seconds since the Unix epoch, and it bounds the certificate's
/// validity and nothing else. It is an unauthenticated real-time-clock reading
/// and is treated as one: a certificate needs a window, and this is enough to
/// give it one and not enough to judge anybody by.
///
/// The device identifier, the serial and the key all come from `entropy`, which
/// is one generator rather than three: a second source would be a second thing
/// to have proved healthy.
///
/// # Errors
/// [`IdentityError`], naming which step refused. Every one of them leaves the
/// medium untouched, this function reaching no device.
pub fn mint(entropy: &dyn Entropy, now: i64) -> Result<Minted, IdentityError> {
    let mut raw = [0_u8; DEVICE_ID_BYTES];
    entropy.fill(&mut raw);
    let device = DeviceId::from_bytes(raw);

    let key = P256SecretKey::generate(entropy).map_err(|_| IdentityError::KeyUnusable)?;
    let public = key.public_key();

    let mut serial_bytes = [0_u8; DEVICE_ID_BYTES];
    entropy.fill(&mut serial_bytes);
    let name = device.render();
    let certificate = write_certificate(
        &Profile {
            // Self-signed: the issuer name is the subject's and the signing key
            // is the subject's own, which is what makes it so. There is no flag
            // to disagree with.
            kind: CertificateKind::Onboarding,
            subject: &name,
            issuer: &name,
            serial: Serial::from_bytes(serial_bytes),
            validity: Validity::ten_years_from(now),
            subject_public_key: public,
        },
        &key,
    )?;
    let fingerprint = spki_fingerprint(&public)?;

    let stored = StoredCertificate::new(certificate.as_bytes()).map_err(IdentityError::Storage)?;
    // The scalar reaches the state and nothing else. It is read out of the key
    // rather than held from the draw above, so there is one copy of it in this
    // frame and it is the one that goes to the record.
    let mut scalar = key.into_scalar();
    let state = State::minted(raw, scalar, public, stored);
    // The frame's own copy, cleared through a volatile write so the compiler
    // cannot remove a store to a value nothing reads again. The record's copy is
    // the one that survives, deliberately.
    zeroize(&mut scalar);

    Ok(Minted {
        state,
        identity: Identity {
            device,
            fingerprint,
        },
    })
}

/// Hold a decoded state's identity to itself, and answer the name and the
/// fingerprint it establishes.
///
/// Three claims, in the order a reader would want them: the scalar is a private
/// key at all, the public point is the one that scalar derives, and the
/// certificate binds that point. A record failing any of them is refused; a
/// record passing all three is one this appliance could have written and whose
/// certificate a peer will accept for the key this node signs with.
///
/// # Errors
/// [`IdentityError`], naming which of the three disagreed.
pub fn verify(state: &State) -> Result<Identity, IdentityError> {
    let mut scalar = state.secret_scalar();
    let key = P256SecretKey::from_scalar(&scalar);
    zeroize(&mut scalar);
    let key = key.map_err(|_| IdentityError::ScalarUnusable)?;

    let derived = key.public_key();
    if derived != state.public_key() {
        return Err(IdentityError::PublicKeyMismatch);
    }

    let certificate = state.device_certificate();
    if certificate.is_empty() {
        return Err(IdentityError::CertificateAbsent);
    }
    // The certificate is held to the key by *containment* of the encoded
    // `SubjectPublicKeyInfo` rather than by parsing the certificate: this crate
    // writes DER and does not read it, and a reader added here would be a second
    // X.509 parser on a path whose input is a physical attacker's. The
    // structure's own shape is what makes containment sufficient — the point
    // appears in a certificate exactly once, inside the SPKI — and what it
    // establishes is the whole claim: the bytes a validator will take the key
    // from are the bytes of this key.
    let spki = lfw_x509::spki(&derived)?;
    if !contains(certificate.as_bytes(), &spki) {
        return Err(IdentityError::CertificateKeyMismatch);
    }

    Ok(Identity {
        device: DeviceId::from_bytes(state.device_id()),
        fingerprint: spki_fingerprint(&derived)?,
    })
}

/// Whether `needle` appears in `haystack`.
///
/// Written out rather than reached for, because `core` has no such method and the
/// candidate windows are the whole of what is bounded: `windows` yields only
/// slices inside the haystack, and an empty or over-long needle yields none —
/// which for a fixed-length SPKI is unreachable and is answered rather than
/// asserted.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len().checked_sub(needle.len()).is_some_and(|_| {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    })
}

// The record and the profile each bound a certificate, and neither derives its
// number from the other. A profile that outgrew the record would put every
// minted identity one byte past what the medium can hold, discovered on a first
// boot rather than at build time.
const _: () = {
    assert!(lfw_x509::MAX_CERTIFICATE_LEN <= crate::MAX_STORED_CERTIFICATE);
    assert!(SECRET_LEN == lfw_crypto::P256_SECRET_LEN);
    assert!(P256_PUBLIC_LEN == 65);
};
