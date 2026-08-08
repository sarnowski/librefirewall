//! The console token each refusal is named by.
//!
//! One catalogue, here rather than in a caller, for two reasons that point the
//! same way.
//!
//! The first is that more than one protection domain refuses a package. A
//! domain that validates an upload before passing it on and a domain that
//! installs what it is passed both hold a [`PackageError`], and an operator
//! reading two domains' records is reading one appliance: a second catalogue
//! would be a second vocabulary, and the two would drift the first time a
//! variant was added to one of them.
//!
//! The second is that a match written in a caller cannot be held to this crate's
//! variants. Every error type here is `#[non_exhaustive]`, so a match outside
//! this crate must carry a wildcard arm — and that arm silently swallows the
//! next variant, which is exactly the detail a token exists to preserve. Inside
//! the crate that declares them the attribute has no effect, no arm here is a
//! wildcard, and a variant added without a token fails to compile.
//!
//! # What is not decided here
//!
//! The numbers a refusal carries alongside its token. They are shaped by the
//! record a domain writes rather than by this contract, so a caller reads them
//! off the variant it already holds; what this crate owns is the name.

use crate::{
    ArchiveError, CertificateError, EmptyField, EndpointError, Member, NumericField, PackageError,
};

impl PackageError {
    /// Which rule of the package contract refused, at the contract's own grain.
    ///
    /// One token per distinct rule, all the way down: an administrator holding a
    /// refused package has four files to go and look at, and a token covering
    /// three rules names none of them.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::Archive(error) => error.cause(),
            Self::DeviceCertificate(error) => error.device_cause(),
            Self::TrustAnchor(error) => error.anchor_cause(),
            Self::DeviceKeyIsNotThisAppliance => "install-device-key-is-not-this-appliance",
            Self::Endpoint(error) => error.cause(),
            Self::Configuration(_) => "install-configuration-refused",
            // Unreachable where the caller injects a verifier that records why a
            // chain failed before this is reached. Named rather than left to a
            // neighbouring token, so a reader who ever sees it knows exactly
            // which claim broke.
            Self::ChainNotVerified => "install-chain-not-verified",
        }
    }
}

impl ArchiveError {
    /// The archive's own rules. Every one that names a position leaves the
    /// position to the caller, because a tar an administrator did not compose by
    /// hand is one whose fault is found by offset.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::ArchiveOverBound { .. } => "install-archive-over-bound",
            Self::NotAWholeNumberOfBlocks { .. } => "install-archive-partial-block",
            Self::TruncatedHeader { .. } => "install-archive-truncated-header",
            Self::EndsWithoutTerminator => "install-archive-no-terminator",
            Self::BytesAfterEndOfArchive { .. } => "install-archive-trailing-bytes",
            Self::NotUstar { .. } => "install-archive-not-ustar",
            Self::ChecksumMismatch { .. } => "install-archive-checksum-mismatch",
            Self::NotARegularFile { .. } => "install-archive-not-a-regular-file",
            Self::FieldIsNotEmpty { field, .. } => match field {
                EmptyField::LinkName => "install-archive-link-name-not-empty",
                EmptyField::Prefix => "install-archive-prefix-not-empty",
            },
            Self::UnknownMember { .. } => "install-archive-unknown-member",
            Self::DuplicateMember { member } => match member {
                Member::DeviceCertificate => "install-duplicate-device-certificate",
                Member::TrustAnchor => "install-duplicate-trust-anchor",
                Member::ManagementEndpoint => "install-duplicate-management-endpoint",
                Member::Configuration => "install-duplicate-configuration",
            },
            Self::MissingMember { member } => match member {
                Member::DeviceCertificate => "install-missing-device-certificate",
                Member::TrustAnchor => "install-missing-trust-anchor",
                Member::ManagementEndpoint => "install-missing-management-endpoint",
                Member::Configuration => "install-missing-configuration",
            },
            Self::EmptyNumericField { field, .. } => match field {
                NumericField::Size => "install-archive-size-empty",
                NumericField::Checksum => "install-archive-checksum-empty",
            },
            Self::NotOctal { field, .. } => match field {
                NumericField::Size => "install-archive-size-not-octal",
                NumericField::Checksum => "install-archive-checksum-not-octal",
            },
            Self::NumericFieldOverBound { field, .. } => match field {
                NumericField::Size => "install-archive-size-over-bound",
                NumericField::Checksum => "install-archive-checksum-over-bound",
            },
            // The member is named where it is what an administrator would act on
            // — a file that is too large is a file to shrink — and not where the
            // fault is the archive writer's whatever member it landed on.
            Self::MemberOverBound { member, .. } => match member {
                Member::DeviceCertificate => "install-device-certificate-over-bound",
                Member::TrustAnchor => "install-trust-anchor-over-bound",
                Member::ManagementEndpoint => "install-management-endpoint-over-bound",
                Member::Configuration => "install-configuration-over-bound",
            },
            Self::MemberBodyTruncated { .. } => "install-archive-member-truncated",
            Self::MemberPaddingIsNotZero { .. } => "install-archive-member-padding",
        }
    }
}

impl CertificateError {
    /// The device certificate's own rules.
    ///
    /// Two methods rather than one taking which, because the token is what tells
    /// an administrator which of two files to open: a certificate is malformed
    /// in exactly the same ways whichever of them it is, and being told only
    /// that is being told to check both.
    #[must_use]
    pub const fn device_cause(self) -> &'static str {
        match self {
            Self::MissingBeginBoundary => "install-device-no-begin-boundary",
            Self::MissingEndBoundary => "install-device-no-end-boundary",
            Self::LineTooLong { .. } => "install-device-line-too-long",
            Self::NotBase64 => "install-device-not-base64",
            Self::PaddingMisplaced => "install-device-padding-misplaced",
            Self::NotAWholeGroup => "install-device-not-a-whole-group",
            Self::NonCanonicalPadding => "install-device-non-canonical-padding",
            Self::TrailingContent => "install-device-trailing-content",
            Self::CertificateIsEmpty => "install-device-empty",
            Self::CertificateTooLong { .. } => "install-device-too-long",
            Self::TruncatedDer { .. } => "install-device-truncated-der",
            Self::UnexpectedTag { .. } => "install-device-unexpected-tag",
            Self::IndefiniteLength { .. } => "install-device-indefinite-length",
            Self::NonMinimalLength { .. } => "install-device-non-minimal-length",
            Self::LengthOutOfRange { .. } => "install-device-length-out-of-range",
            Self::TrailingDer => "install-device-trailing-der",
        }
    }

    /// The trust anchor's, which are the same rules over the other file.
    #[must_use]
    pub const fn anchor_cause(self) -> &'static str {
        match self {
            Self::MissingBeginBoundary => "install-anchor-no-begin-boundary",
            Self::MissingEndBoundary => "install-anchor-no-end-boundary",
            Self::LineTooLong { .. } => "install-anchor-line-too-long",
            Self::NotBase64 => "install-anchor-not-base64",
            Self::PaddingMisplaced => "install-anchor-padding-misplaced",
            Self::NotAWholeGroup => "install-anchor-not-a-whole-group",
            Self::NonCanonicalPadding => "install-anchor-non-canonical-padding",
            Self::TrailingContent => "install-anchor-trailing-content",
            Self::CertificateIsEmpty => "install-anchor-empty",
            Self::CertificateTooLong { .. } => "install-anchor-too-long",
            Self::TruncatedDer { .. } => "install-anchor-truncated-der",
            Self::UnexpectedTag { .. } => "install-anchor-unexpected-tag",
            Self::IndefiniteLength { .. } => "install-anchor-indefinite-length",
            Self::NonMinimalLength { .. } => "install-anchor-non-minimal-length",
            Self::LengthOutOfRange { .. } => "install-anchor-length-out-of-range",
            Self::TrailingDer => "install-anchor-trailing-der",
        }
    }
}

impl EndpointError {
    /// The endpoint line's own rules. An administrator typed this member, so
    /// every one of them is a thing to go and correct.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::Empty => "install-endpoint-empty",
            Self::NotAscii => "install-endpoint-not-ascii",
            Self::OverBound { .. } => "install-endpoint-over-bound",
            Self::MissingColon => "install-endpoint-no-colon",
            Self::TooManyColons => "install-endpoint-too-many-colons",
            Self::TrailingBytes => "install-endpoint-trailing-bytes",
            Self::AddressHasTooFewOctets { .. } => "install-endpoint-too-few-octets",
            Self::AddressHasTooManyOctets => "install-endpoint-too-many-octets",
            Self::OctetIsEmpty => "install-endpoint-octet-empty",
            Self::OctetIsNotDecimal => "install-endpoint-octet-not-decimal",
            Self::OctetHasLeadingZero => "install-endpoint-octet-leading-zero",
            Self::OctetOutOfRange => "install-endpoint-octet-out-of-range",
            Self::AddressIsUnspecified => "install-endpoint-unspecified",
            Self::AddressIsLoopback => "install-endpoint-loopback",
            Self::AddressIsMulticast => "install-endpoint-multicast",
            Self::AddressIsBroadcast => "install-endpoint-broadcast",
            Self::AddressIsReserved => "install-endpoint-reserved",
            Self::PortIsEmpty => "install-endpoint-port-empty",
            Self::PortIsNotDecimal => "install-endpoint-port-not-decimal",
            Self::PortHasLeadingZero => "install-endpoint-port-leading-zero",
            Self::PortOutOfRange => "install-endpoint-port-out-of-range",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Element;
    use config::{ConfigError, DocumentError, DocumentFault};

    /// One of every archive refusal. The payloads are arbitrary: a token names
    /// the rule, and no rule here reads a number to pick one.
    const ARCHIVE: &[ArchiveError] = &[
        ArchiveError::ArchiveOverBound { len: 1, bound: 0 },
        ArchiveError::NotAWholeNumberOfBlocks { len: 1 },
        ArchiveError::TruncatedHeader { at: 0 },
        ArchiveError::EndsWithoutTerminator,
        ArchiveError::BytesAfterEndOfArchive { at: 0 },
        ArchiveError::NotUstar { at: 0 },
        ArchiveError::ChecksumMismatch {
            at: 0,
            stated: 0,
            computed: 1,
        },
        ArchiveError::NotARegularFile { at: 0 },
        ArchiveError::FieldIsNotEmpty {
            at: 0,
            field: EmptyField::LinkName,
        },
        ArchiveError::FieldIsNotEmpty {
            at: 0,
            field: EmptyField::Prefix,
        },
        ArchiveError::UnknownMember { at: 0 },
        ArchiveError::DuplicateMember {
            member: Member::DeviceCertificate,
        },
        ArchiveError::DuplicateMember {
            member: Member::TrustAnchor,
        },
        ArchiveError::DuplicateMember {
            member: Member::ManagementEndpoint,
        },
        ArchiveError::DuplicateMember {
            member: Member::Configuration,
        },
        ArchiveError::MissingMember {
            member: Member::DeviceCertificate,
        },
        ArchiveError::MissingMember {
            member: Member::TrustAnchor,
        },
        ArchiveError::MissingMember {
            member: Member::ManagementEndpoint,
        },
        ArchiveError::MissingMember {
            member: Member::Configuration,
        },
        ArchiveError::EmptyNumericField {
            at: 0,
            field: NumericField::Size,
        },
        ArchiveError::EmptyNumericField {
            at: 0,
            field: NumericField::Checksum,
        },
        ArchiveError::NotOctal {
            at: 0,
            field: NumericField::Size,
        },
        ArchiveError::NotOctal {
            at: 0,
            field: NumericField::Checksum,
        },
        ArchiveError::NumericFieldOverBound {
            at: 0,
            field: NumericField::Size,
        },
        ArchiveError::NumericFieldOverBound {
            at: 0,
            field: NumericField::Checksum,
        },
        ArchiveError::MemberOverBound {
            member: Member::DeviceCertificate,
            size: 1,
            bound: 0,
        },
        ArchiveError::MemberOverBound {
            member: Member::TrustAnchor,
            size: 1,
            bound: 0,
        },
        ArchiveError::MemberOverBound {
            member: Member::ManagementEndpoint,
            size: 1,
            bound: 0,
        },
        ArchiveError::MemberOverBound {
            member: Member::Configuration,
            size: 1,
            bound: 0,
        },
        ArchiveError::MemberBodyTruncated {
            member: Member::Configuration,
            size: 1,
        },
        ArchiveError::MemberPaddingIsNotZero {
            member: Member::Configuration,
        },
    ];

    /// One of every certificate refusal, which both certificates are read by.
    const CERTIFICATE: &[CertificateError] = &[
        CertificateError::MissingBeginBoundary,
        CertificateError::MissingEndBoundary,
        CertificateError::LineTooLong { len: 1, bound: 0 },
        CertificateError::NotBase64,
        CertificateError::PaddingMisplaced,
        CertificateError::NotAWholeGroup,
        CertificateError::NonCanonicalPadding,
        CertificateError::TrailingContent,
        CertificateError::CertificateIsEmpty,
        CertificateError::CertificateTooLong { len: 1, bound: 0 },
        CertificateError::TruncatedDer {
            element: Element::Certificate,
        },
        CertificateError::UnexpectedTag {
            element: Element::Certificate,
        },
        CertificateError::IndefiniteLength {
            element: Element::Certificate,
        },
        CertificateError::NonMinimalLength {
            element: Element::Certificate,
        },
        CertificateError::LengthOutOfRange {
            element: Element::Certificate,
        },
        CertificateError::TrailingDer,
    ];

    /// One of every endpoint refusal.
    const ENDPOINT: &[EndpointError] = &[
        EndpointError::Empty,
        EndpointError::NotAscii,
        EndpointError::OverBound { len: 1, bound: 0 },
        EndpointError::MissingColon,
        EndpointError::TooManyColons,
        EndpointError::TrailingBytes,
        EndpointError::AddressHasTooFewOctets { octets: 1 },
        EndpointError::AddressHasTooManyOctets,
        EndpointError::OctetIsEmpty,
        EndpointError::OctetIsNotDecimal,
        EndpointError::OctetHasLeadingZero,
        EndpointError::OctetOutOfRange,
        EndpointError::AddressIsUnspecified,
        EndpointError::AddressIsLoopback,
        EndpointError::AddressIsMulticast,
        EndpointError::AddressIsBroadcast,
        EndpointError::AddressIsReserved,
        EndpointError::PortIsEmpty,
        EndpointError::PortIsNotDecimal,
        EndpointError::PortHasLeadingZero,
        EndpointError::PortOutOfRange,
    ];

    /// Every token the catalogue can produce, by the route a caller reaches it
    /// through: the whole of [`PackageError`], which is what a domain holds.
    fn every_token() -> Vec<&'static str> {
        let mut tokens = Vec::new();
        for error in ARCHIVE {
            tokens.push(PackageError::Archive(*error).cause());
        }
        for error in CERTIFICATE {
            tokens.push(PackageError::DeviceCertificate(*error).cause());
            tokens.push(PackageError::TrustAnchor(*error).cause());
        }
        for error in ENDPOINT {
            tokens.push(PackageError::Endpoint(*error).cause());
        }
        tokens.push(PackageError::DeviceKeyIsNotThisAppliance.cause());
        tokens.push(
            PackageError::Configuration(ConfigError::Document(DocumentError {
                fault: DocumentFault::MissingRootElement,
                offset: 0,
            }))
            .cause(),
        );
        tokens.push(PackageError::ChainNotVerified.cause());
        tokens
    }

    /// A refusal an administrator cannot act on is a refusal that told them
    /// nothing, so every token is a name and not a placeholder.
    #[test]
    fn every_refusal_is_named() {
        for token in every_token() {
            assert!(!token.is_empty(), "a refusal reaches the console unnamed");
            assert!(
                token.starts_with("install-"),
                "{token} is not one of this contract's tokens"
            );
            assert!(
                token
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
                "{token} is not written in the alphabet a cause token is read in"
            );
        }
    }

    /// Two rules sharing a token is an administrator told to look in the wrong
    /// place, which is the whole reason the catalogue is one token per rule.
    #[test]
    fn distinct_refusals_carry_distinct_tokens() {
        let tokens = every_token();
        let mut sorted = tokens.clone();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            before,
            "two refusals of the package contract share a cause token"
        );
    }

    /// The two certificates are two files to go and open, so no token sends an
    /// administrator to both.
    #[test]
    fn the_two_certificates_are_never_confused() {
        for error in CERTIFICATE {
            assert_ne!(error.device_cause(), error.anchor_cause());
        }
    }
}
