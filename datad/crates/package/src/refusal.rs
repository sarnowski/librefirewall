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
//! # The numbers beside the token are here too, and in nobody's vocabulary
//!
//! A token names a rule and the numbers beside it place the fault — the offset a
//! header was wrong at, the length that outgrew a bound. Those were once left to
//! the one caller that wrote a record, on the reasoning that a record's shape is
//! the domain's. With two domains reading a package that reasoning inverts: two
//! hand-written mappings from the same variants to the same numbers are two
//! things to keep in step, and the one that fell behind would place a fault
//! wrongly rather than merely differently.
//!
//! So [`Operands`] is here beside the tokens, and it is deliberately **not** a
//! console type: it is a count of numbers, which each domain then writes into
//! whatever its own record carries. What this crate owns is the name and the
//! numbers; what it still does not own is the record.

use crate::{
    ArchiveError, CertificateError, EmptyField, EndpointError, Member, NumericField, PackageError,
};

/// The numbers that place a refusal, in the shape every domain's record can
/// hold: none, one, or two.
///
/// Widened to `u64` here rather than by each reader, so the narrowing decision
/// is made once — every field this is built from is a length, a bound or an
/// offset inside an archive that is bounded well below what a `u64` holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operands {
    None,
    One(u64),
    Two(u64, u64),
}

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

impl PackageError {
    /// The numbers that place this refusal, or none where the token is the whole
    /// of what there is to say.
    #[must_use]
    pub const fn operands(self) -> Operands {
        match self {
            Self::Archive(error) => error.operands(),
            Self::DeviceCertificate(error) | Self::TrustAnchor(error) => error.operands(),
            Self::Endpoint(error) => error.operands(),
            // The key comparison, the configuration reader's own refusal and an
            // unverified chain each name a rule and no number: what an
            // administrator does about them is open a file, not look at an
            // offset in one.
            Self::DeviceKeyIsNotThisAppliance | Self::Configuration(_) | Self::ChainNotVerified => {
                Operands::None
            }
        }
    }
}

impl ArchiveError {
    /// Where in the archive the fault is, or the two numbers a bound turns on.
    #[must_use]
    pub const fn operands(self) -> Operands {
        match self {
            Self::ArchiveOverBound { len, bound }
            | Self::MemberOverBound {
                size: len, bound, ..
            } => Operands::Two(len as u64, bound as u64),
            Self::ChecksumMismatch {
                stated, computed, ..
            } => Operands::Two(stated as u64, computed as u64),
            Self::NotAWholeNumberOfBlocks { len } => Operands::One(len as u64),
            Self::TruncatedHeader { at }
            | Self::BytesAfterEndOfArchive { at }
            | Self::NotUstar { at }
            | Self::NotARegularFile { at }
            | Self::FieldIsNotEmpty { at, .. }
            | Self::UnknownMember { at }
            | Self::EmptyNumericField { at, .. }
            | Self::NotOctal { at, .. }
            | Self::NumericFieldOverBound { at, .. } => Operands::One(at as u64),
            Self::MemberBodyTruncated { size, .. } => Operands::One(size as u64),
            Self::EndsWithoutTerminator
            | Self::DuplicateMember { .. }
            | Self::MissingMember { .. }
            | Self::MemberPaddingIsNotZero { .. } => Operands::None,
        }
    }

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
    /// The two lengths a certificate refusal turns on. The DER faults name an
    /// element of a certificate and it is deliberately not carried: all nine
    /// send an administrator to the same place, which is the tool that wrote the
    /// file.
    #[must_use]
    pub const fn operands(self) -> Operands {
        match self {
            Self::LineTooLong { len, bound } | Self::CertificateTooLong { len, bound } => {
                Operands::Two(len as u64, bound as u64)
            }
            Self::MissingBeginBoundary
            | Self::MissingEndBoundary
            | Self::NotBase64
            | Self::PaddingMisplaced
            | Self::NotAWholeGroup
            | Self::NonCanonicalPadding
            | Self::TrailingContent
            | Self::CertificateIsEmpty
            | Self::TruncatedDer { .. }
            | Self::UnexpectedTag { .. }
            | Self::IndefiniteLength { .. }
            | Self::NonMinimalLength { .. }
            | Self::LengthOutOfRange { .. }
            | Self::TrailingDer => Operands::None,
        }
    }

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
    /// The length a bound turns on, or how many octets an address really had.
    #[must_use]
    pub const fn operands(self) -> Operands {
        match self {
            Self::OverBound { len, bound } => Operands::Two(len as u64, bound as u64),
            Self::AddressHasTooFewOctets { octets } => Operands::One(octets as u64),
            Self::Empty
            | Self::NotAscii
            | Self::MissingColon
            | Self::TooManyColons
            | Self::TrailingBytes
            | Self::AddressHasTooManyOctets
            | Self::OctetIsEmpty
            | Self::OctetIsNotDecimal
            | Self::OctetHasLeadingZero
            | Self::OctetOutOfRange
            | Self::AddressIsUnspecified
            | Self::AddressIsLoopback
            | Self::AddressIsMulticast
            | Self::AddressIsBroadcast
            | Self::AddressIsReserved
            | Self::PortIsEmpty
            | Self::PortIsNotDecimal
            | Self::PortHasLeadingZero
            | Self::PortOutOfRange => Operands::None,
        }
    }

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

    /// Every refusal a caller can hold answers a shape of operands, and no path
    /// through the catalogue faults on the way there. Totality first, because a
    /// domain writing a record calls this on whatever it was handed.
    #[test]
    fn every_refusal_answers_operands() {
        for error in ARCHIVE {
            let _ = PackageError::Archive(*error).operands();
        }
        for error in CERTIFICATE {
            let _ = PackageError::DeviceCertificate(*error).operands();
            let _ = PackageError::TrustAnchor(*error).operands();
        }
        for error in ENDPOINT {
            let _ = PackageError::Endpoint(*error).operands();
        }
        assert_eq!(
            PackageError::DeviceKeyIsNotThisAppliance.operands(),
            Operands::None
        );
        assert_eq!(PackageError::ChainNotVerified.operands(), Operands::None);
        assert_eq!(
            PackageError::Configuration(ConfigError::Document(DocumentError {
                fault: DocumentFault::MissingRootElement,
                offset: 0,
            }))
            .operands(),
            Operands::None
        );
    }

    /// And the numbers are the ones the variant holds, in the order the variant
    /// holds them. A pair written the other way round would place a fault
    /// exactly wrongly — an operator reading "the bound was 1 and the length 0"
    /// goes and shrinks the wrong thing.
    #[test]
    fn the_operands_are_the_numbers_the_variant_holds() {
        assert_eq!(
            PackageError::Archive(ArchiveError::ArchiveOverBound { len: 9, bound: 4 }).operands(),
            Operands::Two(9, 4)
        );
        assert_eq!(
            PackageError::Archive(ArchiveError::MemberOverBound {
                member: Member::Configuration,
                size: 7,
                bound: 3,
            })
            .operands(),
            Operands::Two(7, 3)
        );
        assert_eq!(
            PackageError::Archive(ArchiveError::ChecksumMismatch {
                at: 512,
                stated: 11,
                computed: 12,
            })
            .operands(),
            Operands::Two(11, 12)
        );
        assert_eq!(
            PackageError::Archive(ArchiveError::NotUstar { at: 1024 }).operands(),
            Operands::One(1024)
        );
        assert_eq!(
            PackageError::Archive(ArchiveError::NotAWholeNumberOfBlocks { len: 5 }).operands(),
            Operands::One(5)
        );
        assert_eq!(
            PackageError::Archive(ArchiveError::EndsWithoutTerminator).operands(),
            Operands::None
        );
        assert_eq!(
            PackageError::DeviceCertificate(CertificateError::LineTooLong { len: 80, bound: 64 })
                .operands(),
            Operands::Two(80, 64)
        );
        assert_eq!(
            PackageError::TrustAnchor(CertificateError::NotBase64).operands(),
            Operands::None
        );
        assert_eq!(
            PackageError::Endpoint(EndpointError::OverBound { len: 40, bound: 32 }).operands(),
            Operands::Two(40, 32)
        );
        assert_eq!(
            PackageError::Endpoint(EndpointError::AddressHasTooFewOctets { octets: 3 }).operands(),
            Operands::One(3)
        );
        assert_eq!(
            PackageError::Endpoint(EndpointError::PortOutOfRange).operands(),
            Operands::None
        );
    }

    /// The two certificates place a fault the same way, which is the point of
    /// their sharing one rule set: only the token says which file to open.
    #[test]
    fn the_two_certificates_place_a_fault_identically() {
        for error in CERTIFICATE {
            assert_eq!(
                PackageError::DeviceCertificate(*error).operands(),
                PackageError::TrustAnchor(*error).operands()
            );
        }
    }
}
