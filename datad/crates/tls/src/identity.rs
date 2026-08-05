use lfw_crypto::{CryptoError, Entropy, P256_PUBLIC_LEN, P256SecretKey};
use lfw_x509::{
    Certificate, CertificateKind, DerError, Profile, ProfileError, Serial, Validity,
    write_certificate,
};

/// Why an identity could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// The node's generator did not produce a usable key, which a working
    /// generator does not reach.
    KeyGeneration(CryptoError),
    /// The certificate could not be written.
    Certificate(ProfileError),
}

impl From<ProfileError> for IdentityError {
    fn from(error: ProfileError) -> Self {
        Self::Certificate(error)
    }
}

impl From<DerError> for IdentityError {
    fn from(error: DerError) -> Self {
        Self::Certificate(ProfileError::Encoding(error))
    }
}

/// A key and the certificate that binds it, which is the whole of what a party
/// to a mutually-authenticated session needs.
///
/// The key is owned here today. When the store domain owns it instead, this
/// type holds the certificate alone and the signing capability comes from
/// there — which is why nothing outside this module reads the key, only signs
/// with it.
pub struct Identity {
    key: P256SecretKey,
    certificate: Certificate,
}

impl Identity {
    /// A self-signed identity: a fresh key, and a certificate over it issued
    /// by itself. This is what a certification authority is, and it is also
    /// what an appliance serves before it has been issued anything.
    ///
    /// # Errors
    /// [`IdentityError`] where the key or the certificate could not be made.
    pub fn self_signed(
        entropy: &dyn Entropy,
        now: i64,
        kind: CertificateKind,
        common_name: &[u8],
    ) -> Result<Self, IdentityError> {
        let key = P256SecretKey::generate(entropy).map_err(IdentityError::KeyGeneration)?;
        let public = key.public_key();
        let certificate = write_certificate(
            &Profile {
                kind,
                subject: common_name,
                issuer: common_name,
                serial: serial(entropy),
                validity: Validity::ten_years_from(now),
                subject_public_key: public,
            },
            &key,
        )?;
        Ok(Self { key, certificate })
    }

    /// A fresh key, and a certificate over it issued by `authority`.
    ///
    /// # Errors
    /// [`IdentityError`], on the same terms.
    pub fn issued_by(
        authority: &Self,
        entropy: &dyn Entropy,
        now: i64,
        kind: CertificateKind,
        subject: &[u8],
        issuer: &[u8],
    ) -> Result<Self, IdentityError> {
        let key = P256SecretKey::generate(entropy).map_err(IdentityError::KeyGeneration)?;
        let public = key.public_key();
        let certificate = write_certificate(
            &Profile {
                kind,
                subject,
                issuer,
                serial: serial(entropy),
                validity: Validity::ten_years_from(now),
                subject_public_key: public,
            },
            &authority.key,
        )?;
        Ok(Self { key, certificate })
    }

    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        self.certificate.as_bytes()
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; P256_PUBLIC_LEN] {
        self.key.public_key()
    }

    /// The key itself, for the one caller that needs to sign with it. Consumed
    /// rather than borrowed: an identity that has handed over its key has
    /// nothing left to sign with, and the type says so.
    #[must_use]
    pub fn into_key(self) -> P256SecretKey {
        self.key
    }

    /// A certificate this authority issues over a public key **whose private
    /// half it does not hold**, and which nothing here can hold.
    ///
    /// A certificate and not an [`Self`], and that absence is the whole point:
    /// the type above pairs a certificate with a key, and there is no key on this
    /// path to pair one with. The private half lives in another protection
    /// domain, reached through a [`crate::SignOperation`] the caller supplies, so
    /// what comes back is the binding alone.
    ///
    /// Everything else is [`Self::issued_by`]'s: the same profile, the same
    /// validity, the same authority signing it. Only the subject's key comes
    /// from outside — which is exactly the substitution the signing seam exists
    /// for.
    ///
    /// # Errors
    /// [`IdentityError`] where the certificate could not be written. Never
    /// [`IdentityError::KeyGeneration`]: no key is generated here.
    pub fn certify(
        &self,
        entropy: &dyn Entropy,
        now: i64,
        kind: CertificateKind,
        subject: &[u8],
        issuer: &[u8],
        subject_public_key: [u8; P256_PUBLIC_LEN],
    ) -> Result<Certificate, IdentityError> {
        Ok(write_certificate(
            &Profile {
                kind,
                subject,
                issuer,
                serial: serial(entropy),
                validity: Validity::ten_years_from(now),
                subject_public_key,
            },
            &self.key,
        )?)
    }
}

/// A serial number drawn from the node's generator, which is what the profile
/// asks for: 128 random bits, unique within one issuer by size rather than by
/// a counter nothing here could persist.
fn serial(entropy: &dyn Entropy) -> Serial {
    let mut bytes = [0_u8; 16];
    entropy.fill(&mut bytes);
    Serial::from_bytes(bytes)
}
