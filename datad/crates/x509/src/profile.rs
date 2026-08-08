use lfw_crypto::{DIGEST_LEN, P256_MAX_SIGNATURE_LEN, P256_PUBLIC_LEN, P256SecretKey, sha256};

use crate::{
    Utc,
    der::{
        BIT_STRING, BOOLEAN, DerError, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, SET,
        UTC_TIME, UTF8_STRING, Writer, context, context_primitive,
    },
};

/// Characters a rendered device identifier occupies: 128 bits as lowercase
/// hexadecimal.
pub const DEVICE_ID_LEN: usize = 32;

/// Bytes of a DER-encoded `SubjectPublicKeyInfo` for an uncompressed P-256
/// point. Fixed, because every field in it is: two algorithm identifiers of
/// known length and a 65-byte point.
pub const SPKI_LEN: usize = 91;

/// Slack a writer needs above what it produces.
///
/// A constructed element's length is not known until its content is written,
/// so the content goes past a reserved header and moves back over it. The
/// reservation is the widest header, and it is live for every element still
/// open — three deep at most here, in a `SubjectPublicKeyInfo`.
const WRITER_SLACK: usize = 16;

/// Characters a rendered fingerprint occupies: a SHA-256 digest as lowercase
/// hexadecimal, with no separators.
pub const FINGERPRINT_LEN: usize = 2 * DIGEST_LEN;

/// **The profile's bound on a certificate's DER**, and the authoritative one:
/// every consumer of a certificate in this appliance — the writer here, the
/// reader that unwraps a delivered one, the state record that persists it, the
/// region it crosses a protection-domain boundary in — holds this number, and
/// so does the management server that issues under the same profile and refuses
/// to sign past it. It is a limit the profile states rather than a buffer size
/// read off what this writer happens to produce.
///
/// Seven hundred and sixty-eight is far from tight, which is deliberate: the
/// widest certificate the profile admits is a CA-issued endpoint certificate —
/// two names, a validity, a public key, four extensions and a signature, under
/// five hundred bytes — so the slack above it is room for a subject name, and a
/// name that outgrows even that is one the issuer shortens rather than one an
/// appliance discovers it cannot persist.
pub const MAX_CERTIFICATE_LEN: usize = 768;

/// A buffer wide enough for any certificate signing request this profile
/// produces: one name, one public key, no attributes, one signature.
pub const MAX_CSR_LEN: usize = 384;

/// Why a certificate could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// The encoding outgrew the caller's buffer or could not be lengthed.
    Encoding(DerError),
    /// The clock's answer is outside the window a `UTCTime` names without
    /// ambiguity. Surfaced rather than guessed at: a certificate dated by a
    /// clock nobody believes is worse than no certificate.
    Undatable { year: i64 },
    /// The signature did not fit the fixed buffer this profile signs into,
    /// which its own bound makes unreachable and which is answered rather than
    /// asserted for that reason.
    Signature,
}

impl From<DerError> for ProfileError {
    fn from(error: DerError) -> Self {
        Self::Encoding(error)
    }
}

/// A 128-bit device identifier, and the only subject attribute anything the
/// appliance identifies itself with carries.
///
/// A stable, meaningless name: no serial number, no owner, no site. It is
/// rendered once, here, so the string on the console and the string in the
/// certificate cannot be two renderings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 32 lowercase hexadecimal characters this identifier is written as.
    #[must_use]
    pub fn render(&self) -> [u8; DEVICE_ID_LEN] {
        let mut out = [0_u8; DEVICE_ID_LEN];
        write_hex(&self.0, &mut out);
        out
    }
}

/// A certificate serial number: 128 random bits from the issuer's generator,
/// encoded as a positive integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Serial([u8; 16]);

impl Serial {
    /// The top bit is cleared so the magnitude is positive without a leading
    /// zero byte, which keeps the encoded length fixed. It costs one bit of a
    /// value whose only requirement is uniqueness within one issuer.
    #[must_use]
    pub const fn from_bytes(mut bytes: [u8; 16]) -> Self {
        bytes[0] &= 0x7f;
        // A serial of zero is legal and useless; one keeps every serial a
        // non-empty magnitude without touching the other 127 bits.
        if bytes[0] == 0 {
            bytes[0] = 1;
        }
        Self(bytes)
    }
}

/// The window a certificate is valid in, as the two instants it is written
/// from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
}

impl Validity {
    /// Seconds in the profile's ten-year validity, counted as 3652 days —
    /// four hundred years' average leap rate over a decade, which lands within
    /// a day of the calendar answer for any start date and is a window, not an
    /// appointment.
    pub const TEN_YEARS: i64 = 3652 * 86_400;

    /// Ten years from `now`, starting an hour before it. The hour is for a
    /// verifier whose clock is behind ours: the appliance's time comes from an
    /// unauthenticated real-time clock, and a certificate that is not yet
    /// valid by a few seconds is a failure with no diagnosis.
    #[must_use]
    pub const fn ten_years_from(now: i64) -> Self {
        Self {
            not_before: now.saturating_sub(3600),
            not_after: now.saturating_add(Self::TEN_YEARS),
        }
    }
}

/// Which of the profile's certificates is being written. The variant decides
/// the extensions and nothing else — every other field is the same shape in
/// all four, which is what makes one writer correct for the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateKind {
    /// Self-signed, `serverAuth`, no alternative name: what an appliance
    /// serves before it has been issued anything.
    Onboarding,
    /// CA-issued, `clientAuth`: the appliance's identity on the channel.
    Device,
    /// CA-issued, `serverAuth`, with the endpoint's address as its one
    /// alternative name, because an appliance dials a literal and validates
    /// against what it dialed.
    ChannelEndpoint { address: [u8; 4] },
    /// Self-signed, `keyCertSign`, `CA:true` with path length zero.
    ManagementCa,
}

/// One certificate to write: what it is, whose name it carries, whose key it
/// binds, and when it is valid.
pub struct Profile<'a> {
    pub kind: CertificateKind,
    /// The subject's common name, as the bytes it is written from.
    pub subject: &'a [u8],
    /// The issuer's common name. Equal to `subject` on a self-signed
    /// certificate, which is what makes it self-signed here — there is no
    /// separate flag to disagree with.
    pub issuer: &'a [u8],
    pub serial: Serial,
    pub validity: Validity,
    /// The uncompressed SEC1 point this certificate binds.
    pub subject_public_key: [u8; P256_PUBLIC_LEN],
}

/// A certificate that was written, as the bytes and their length.
pub struct Certificate {
    bytes: [u8; MAX_CERTIFICATE_LEN],
    len: usize,
}

impl Certificate {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Write one certificate, signed by `issuer_key`.
///
/// A self-signed certificate is one whose `issuer_key` is the key its
/// `subject_public_key` belongs to and whose issuer name equals its subject
/// name; nothing here checks that pairing, because the caller is the only
/// party that knows it and a check here would be a second place to get it
/// wrong.
///
/// # Errors
/// [`ProfileError`] where the encoding does not fit, the clock is undatable,
/// or the signature does not fit its fixed buffer.
pub fn write_certificate(
    profile: &Profile<'_>,
    issuer_key: &P256SecretKey,
) -> Result<Certificate, ProfileError> {
    let mut tbs = [0_u8; MAX_CERTIFICATE_LEN];
    let tbs_len = write_tbs(profile, &mut tbs)?;
    let body = tbs.get(..tbs_len).unwrap_or_default();
    let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
    let signature_len = issuer_key
        .sign(body, &mut signature)
        .map_err(|_| ProfileError::Signature)?;
    let signature = signature.get(..signature_len).unwrap_or_default();

    let mut bytes = [0_u8; MAX_CERTIFICATE_LEN];
    let mut writer = Writer::new(&mut bytes);
    writer.constructed(SEQUENCE, |certificate| {
        certificate.bytes(body)?;
        write_signature_algorithm(certificate)?;
        certificate.bit_string(signature)
    })?;
    let len = writer.len();
    Ok(Certificate { bytes, len })
}

/// Write a PKCS#10 certificate signing request for `key`.
///
/// It requests no extensions, deliberately: the issuing authority honours
/// none, so a request is a proof of key possession and a name and never a
/// channel into the certificate's contents.
///
/// # Errors
/// [`ProfileError`] where the encoding does not fit or the signature does not
/// fit its fixed buffer.
pub fn write_csr(
    subject: &[u8],
    key: &P256SecretKey,
    out: &mut [u8; MAX_CSR_LEN],
) -> Result<usize, ProfileError> {
    write_csr_signed(subject, &key.public_key(), out, |body, signature| {
        key.sign(body, signature).map_err(|_| ())
    })
}

/// The same request, signed by something that is not a key this crate holds.
///
/// [`write_csr`] above is this with the key beside the caller; this is the
/// shape the appliance really uses, because the scalar the request must be
/// signed under lives in the protection domain that owns the medium it is
/// written on and reaches this one only as a call. The public point is
/// therefore a parameter rather than derived: the only party that can say
/// which point the signer will sign under is the signer.
///
/// `sign` is handed the `CertificationRequestInfo` and a fixed buffer, and
/// answers the DER signature's length. Its error carries nothing — a signer
/// that will not sign gives a caller here nothing to act on, and a richer one
/// would be a description of another domain's internals travelling on a path
/// whose product faces the network.
///
/// # Errors
/// [`ProfileError`] where the encoding does not fit or the signature was
/// refused or did not fit its fixed buffer.
pub fn write_csr_signed(
    subject: &[u8],
    public_key: &[u8; P256_PUBLIC_LEN],
    out: &mut [u8; MAX_CSR_LEN],
    sign: impl FnOnce(&[u8], &mut [u8]) -> Result<usize, ()>,
) -> Result<usize, ProfileError> {
    let mut info = [0_u8; MAX_CSR_LEN];
    let mut writer = Writer::new(&mut info);
    writer.constructed(SEQUENCE, |request| {
        request.unsigned_integer(&[0])?;
        write_name(request, subject)?;
        write_spki(request, public_key)?;
        // An empty `[0] IMPLICIT SET OF Attribute`, which is where a request's
        // extensions would go and where this profile puts none.
        request.constructed(context(0), |_| Ok(()))
    })?;
    let info_len = writer.len();
    let body = info.get(..info_len).unwrap_or_default();

    let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
    let signature_len = sign(body, &mut signature).map_err(|()| ProfileError::Signature)?;
    let signature = signature
        .get(..signature_len)
        .ok_or(ProfileError::Signature)?;

    let mut writer = Writer::new(out);
    writer.constructed(SEQUENCE, |request| {
        request.bytes(body)?;
        write_signature_algorithm(request)?;
        request.bit_string(signature)
    })?;
    Ok(writer.len())
}

/// The DER `SubjectPublicKeyInfo` for an uncompressed P-256 point.
///
/// # Errors
/// [`DerError`] where the encoding does not fit, which its fixed length makes
/// unreachable.
pub fn spki(public_key: &[u8; P256_PUBLIC_LEN]) -> Result<[u8; SPKI_LEN], DerError> {
    let mut scratch = [0_u8; SPKI_LEN + WRITER_SLACK];
    let len = {
        let mut writer = Writer::new(&mut scratch);
        write_spki(&mut writer, public_key)?;
        writer.len()
    };
    let mut bytes = [0_u8; SPKI_LEN];
    let written = scratch
        .get(..len)
        .filter(|written| written.len() == SPKI_LEN)
        .ok_or(DerError::OutOfSpace { needed: len })?;
    bytes.copy_from_slice(written);
    Ok(bytes)
}

/// SHA-256 over the DER `SubjectPublicKeyInfo`, which is the one definition of
/// an appliance's fingerprint.
///
/// # Errors
/// [`DerError`], on the same terms as [`spki`].
pub fn spki_fingerprint(public_key: &[u8; P256_PUBLIC_LEN]) -> Result<[u8; DIGEST_LEN], DerError> {
    Ok(sha256(&spki(public_key)?))
}

/// A fingerprint rendered the one way it is ever rendered: 64 lowercase
/// hexadecimal characters, no separators.
#[must_use]
pub fn fingerprint_hex(digest: &[u8; DIGEST_LEN]) -> [u8; FINGERPRINT_LEN] {
    let mut out = [0_u8; FINGERPRINT_LEN];
    write_hex(digest, &mut out);
    out
}

/// The object identifiers this profile names, each as its DER content bytes.
mod oid {
    /// `1.2.840.10045.2.1` — an elliptic-curve public key.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// `1.2.840.10045.3.1.7` — the P-256 curve.
    pub const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// `1.2.840.10045.4.3.2` — ECDSA with SHA-256.
    pub const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// `2.5.4.3` — the common-name attribute.
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// `2.5.29.15` — key usage.
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// `2.5.29.17` — subject alternative name.
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// `2.5.29.19` — basic constraints.
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// `2.5.29.37` — extended key usage.
    pub const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// `1.3.6.1.5.5.7.3.1` — TLS server authentication.
    pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// `1.3.6.1.5.5.7.3.2` — TLS client authentication.
    pub const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
}

fn write_tbs(
    profile: &Profile<'_>,
    out: &mut [u8; MAX_CERTIFICATE_LEN],
) -> Result<usize, ProfileError> {
    let not_before = Utc::from_unix_seconds(profile.validity.not_before)
        .to_utc_time()
        .map_err(|year| ProfileError::Undatable { year })?;
    let not_after = Utc::from_unix_seconds(profile.validity.not_after)
        .to_utc_time()
        .map_err(|year| ProfileError::Undatable { year })?;
    let mut writer = Writer::new(out);
    writer.constructed(SEQUENCE, |tbs| {
        // `[0] EXPLICIT Version`, and the only version this profile writes.
        tbs.constructed(context(0), |version| version.unsigned_integer(&[2]))?;
        tbs.unsigned_integer(&profile.serial.0)?;
        write_signature_algorithm(tbs)?;
        write_name(tbs, profile.issuer)?;
        tbs.constructed(SEQUENCE, |validity| {
            validity.primitive(UTC_TIME, &not_before)?;
            validity.primitive(UTC_TIME, &not_after)
        })?;
        write_name(tbs, profile.subject)?;
        write_spki(tbs, &profile.subject_public_key)?;
        tbs.constructed(context(3), |wrapper| {
            wrapper.constructed(SEQUENCE, |extensions| {
                write_extensions(extensions, profile.kind)
            })
        })
    })?;
    Ok(writer.len())
}

fn write_extensions(out: &mut Writer<'_>, kind: CertificateKind) -> Result<(), DerError> {
    let authority = matches!(kind, CertificateKind::ManagementCa);
    write_extension(out, oid::BASIC_CONSTRAINTS, true, |value| {
        value.constructed(SEQUENCE, |constraints| {
            if !authority {
                // `cA` defaults to FALSE, so an end-entity certificate's
                // constraints are an empty sequence and writing the default
                // would not be DER.
                return Ok(());
            }
            constraints.primitive(BOOLEAN, &[0xff])?;
            constraints.unsigned_integer(&[0])
        })
    })?;
    write_extension(out, oid::KEY_USAGE, true, |value| {
        // Named bits, most-significant first, with the unused trailing bits
        // dropped: `digitalSignature` is bit zero and `keyCertSign` is bit
        // five, so each is one content byte and a count of unused bits.
        let (unused, bits) = if authority { (2, 0x04) } else { (7, 0x80) };
        value.primitive(BIT_STRING, &[unused, bits])
    })?;
    match kind {
        CertificateKind::ManagementCa => Ok(()),
        CertificateKind::Device => write_extended_key_usage(out, oid::CLIENT_AUTH),
        CertificateKind::Onboarding => write_extended_key_usage(out, oid::SERVER_AUTH),
        CertificateKind::ChannelEndpoint { address } => {
            write_extended_key_usage(out, oid::SERVER_AUTH)?;
            write_extension(out, oid::SUBJECT_ALT_NAME, false, |value| {
                value.constructed(SEQUENCE, |names| {
                    // `[7] IPAddress`, primitive: four octets and nothing else.
                    names.primitive(context_primitive(7), &address)
                })
            })
        }
    }
}

fn write_extended_key_usage(out: &mut Writer<'_>, purpose: &[u8]) -> Result<(), DerError> {
    write_extension(out, oid::EXTENDED_KEY_USAGE, false, |value| {
        value.constructed(SEQUENCE, |purposes| {
            purposes.primitive(OBJECT_IDENTIFIER, purpose)
        })
    })
}

/// One `Extension`: its identifier, whether a reader must understand it, and
/// its value wrapped in the octet string the structure puts it in.
fn write_extension(
    out: &mut Writer<'_>,
    id: &[u8],
    critical: bool,
    value: impl FnOnce(&mut Writer<'_>) -> Result<(), DerError>,
) -> Result<(), DerError> {
    out.constructed(SEQUENCE, |extension| {
        extension.primitive(OBJECT_IDENTIFIER, id)?;
        if critical {
            // `critical` defaults to FALSE, so only TRUE is written.
            extension.primitive(BOOLEAN, &[0xff])?;
        }
        extension.constructed(OCTET_STRING, value)
    })
}

/// A `Name` carrying exactly one common name, which is the whole of every
/// subject and issuer in this profile.
fn write_name(out: &mut Writer<'_>, common_name: &[u8]) -> Result<(), DerError> {
    out.constructed(SEQUENCE, |name| {
        name.constructed(SET, |set| {
            set.constructed(SEQUENCE, |attribute| {
                attribute.primitive(OBJECT_IDENTIFIER, oid::COMMON_NAME)?;
                attribute.primitive(UTF8_STRING, common_name)
            })
        })
    })
}

fn write_signature_algorithm(out: &mut Writer<'_>) -> Result<(), DerError> {
    out.constructed(SEQUENCE, |algorithm| {
        algorithm.primitive(OBJECT_IDENTIFIER, oid::ECDSA_WITH_SHA256)
    })
}

fn write_spki(out: &mut Writer<'_>, public_key: &[u8; P256_PUBLIC_LEN]) -> Result<(), DerError> {
    out.constructed(SEQUENCE, |info| {
        info.constructed(SEQUENCE, |algorithm| {
            algorithm.primitive(OBJECT_IDENTIFIER, oid::EC_PUBLIC_KEY)?;
            algorithm.primitive(OBJECT_IDENTIFIER, oid::PRIME256V1)
        })?;
        info.bit_string(public_key)
    })
}

/// Lowercase hexadecimal, written into a buffer of exactly twice the input's
/// length. A shorter buffer leaves the tail as it was, which no caller here
/// can produce: every call site sizes the output from the input's own type.
fn write_hex(bytes: &[u8], out: &mut [u8]) {
    for (byte, slot) in bytes.iter().zip(out.chunks_exact_mut(2)) {
        if let [high, low] = slot {
            *high = digit(byte >> 4);
            *low = digit(byte & 0x0f);
        }
    }
}

/// One nibble as its lowercase character. Arithmetic rather than a table
/// lookup, so there is no index here to be in or out of bounds; the `if` is
/// the whole of the range check and the caller's shift already makes it true.
const fn digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

/// The unused-tag guard: `INTEGER` is written through
/// [`Writer::unsigned_integer`] everywhere here, so the raw tag would be a
/// second encoding of the same thing.
const _: () = assert!(INTEGER == 0x02);
