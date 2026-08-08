//! The archive layer: locating four members in a plain uncompressed ustar tar,
//! and refusing every other tar there is.
//!
//! # Adversary
//!
//! The **management-plane attacker**. These bytes arrive as the body of an
//! upload, so their every field is that party's choice; the session that
//! carried them authenticates the appliance to an administrator and nobody to
//! the appliance.
//!
//! # Why so little of tar
//!
//! Everything a general reader carries — long names, extended headers, sparse
//! members, link targets, a `prefix` field to rebuild a path from — is a second
//! way to say something this format already says one way, and each is a place
//! two implementations can disagree about what a member is called or how long
//! it is. So none of them is accepted: the type flag must denote a regular
//! file, the two extension fields must be empty, and a name is the whole of a
//! member's identity, compared byte for byte against four constants. What
//! cannot be expressed cannot be disagreed about.

/// Bytes one tar block occupies, header and body alike.
pub const BLOCK: usize = 512;

/// Bytes the two closing blocks occupy.
const TERMINATOR: usize = 2 * BLOCK;

/// Bytes the whole archive may occupy.
///
/// The outer bound, applied to bytes nothing has parsed yet. The four member
/// bounds together are smaller, so a well-formed package never approaches it.
pub const ARCHIVE_BOUND: usize = 128 * 1024;

/// Blocks the archive bound admits, which is what bounds the walk below: the
/// loop consumes at least one block per turn and the adversary chooses neither
/// number.
const MAX_BLOCKS: usize = ARCHIVE_BOUND / BLOCK;

/// The largest value a header checksum can hold: every byte of a block at its
/// maximum.
const MAX_CHECKSUM: usize = BLOCK * 255;

const NAME_AT: usize = 0;
const NAME_LEN: usize = 100;
const SIZE_AT: usize = 124;
const SIZE_LEN: usize = 12;
const CHECKSUM_AT: usize = 148;
const CHECKSUM_LEN: usize = 8;
const TYPE_FLAG_AT: usize = 156;
const LINK_NAME_AT: usize = 157;
const LINK_NAME_LEN: usize = 100;
const MAGIC_AT: usize = 257;
const MAGIC_LEN: usize = 6;
const VERSION_AT: usize = 263;
const VERSION_LEN: usize = 2;
const PREFIX_AT: usize = 345;
const PREFIX_LEN: usize = 155;

/// The magic every header must carry.
const USTAR_MAGIC: &[u8; MAGIC_LEN] = b"ustar\0";

/// The version every header must carry.
const USTAR_VERSION: &[u8; VERSION_LEN] = b"00";

/// The one member kind the archive may carry.
///
/// A closed set rather than a name, so nothing downstream ever holds a member
/// name an uploader chose: the four names exist once, here, and a member is
/// afterwards one of four values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    DeviceCertificate,
    TrustAnchor,
    ManagementEndpoint,
    Configuration,
}

impl Member {
    /// Every member the archive must carry, which is every member it may.
    pub const ALL: [Self; 4] = [
        Self::DeviceCertificate,
        Self::TrustAnchor,
        Self::ManagementEndpoint,
        Self::Configuration,
    ];

    /// The member's name, as the archive spells it.
    #[must_use]
    pub const fn name(self) -> &'static [u8] {
        match self {
            Self::DeviceCertificate => b"device-certificate.pem",
            Self::TrustAnchor => b"trust-anchor.pem",
            Self::ManagementEndpoint => b"management-endpoint",
            Self::Configuration => b"configuration.xml",
        }
    }

    /// Bytes this member may occupy.
    #[must_use]
    pub const fn bound(self) -> usize {
        match self {
            Self::DeviceCertificate | Self::TrustAnchor => 16 * 1024,
            Self::ManagementEndpoint => 32,
            Self::Configuration => 64 * 1024,
        }
    }
}

/// Which numeric field an octal refusal was about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumericField {
    Size,
    Checksum,
}

/// Which always-empty header field carried something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyField {
    LinkName,
    Prefix,
}

/// Why a byte string is not this archive.
///
/// Every variant names what was refused in this crate's own vocabulary, and
/// none carries a byte an uploader chose: a header offset, a member of the
/// closed set above, and numbers this reader computed are all that leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveError {
    /// More bytes than the archive bound, refused before anything is parsed.
    ArchiveOverBound {
        len: usize,
        bound: usize,
    },
    NotAWholeNumberOfBlocks {
        len: usize,
    },
    /// Fewer bytes remain than a header occupies.
    TruncatedHeader {
        at: usize,
    },
    /// The archive ran out with no two closing zero blocks in it.
    EndsWithoutTerminator,
    /// Something other than zero bytes follows the closing blocks.
    BytesAfterEndOfArchive {
        at: usize,
    },
    NotUstar {
        at: usize,
    },
    ChecksumMismatch {
        at: usize,
        stated: usize,
        computed: usize,
    },
    NotARegularFile {
        at: usize,
    },
    /// A field this format never uses carried something, which is a member
    /// claiming a shape — a link target, a path prefix — the format has no
    /// meaning for.
    FieldIsNotEmpty {
        at: usize,
        field: EmptyField,
    },
    /// A name matching none of the four, byte for byte.
    UnknownMember {
        at: usize,
    },
    DuplicateMember {
        member: Member,
    },
    MissingMember {
        member: Member,
    },
    EmptyNumericField {
        at: usize,
        field: NumericField,
    },
    NotOctal {
        at: usize,
        field: NumericField,
    },
    /// An octal field naming a value past what the field can mean here.
    NumericFieldOverBound {
        at: usize,
        field: NumericField,
    },
    MemberOverBound {
        member: Member,
        size: usize,
        bound: usize,
    },
    /// The size field names more bytes than the archive still holds.
    MemberBodyTruncated {
        member: Member,
        size: usize,
    },
    /// A member's body was padded to the block with something other than zero.
    MemberPaddingIsNotZero {
        member: Member,
    },
}

/// The four members, located and bounded, before any rule about what they
/// *say* has run.
///
/// Crate-private and it stays so: it is the half-checked value, and a
/// half-checked value that could leave this crate is a package a caller could
/// act on before the rest of the rules ran.
pub(crate) struct Staged<'a> {
    pub(crate) device_certificate: &'a [u8],
    pub(crate) trust_anchor: &'a [u8],
    pub(crate) management_endpoint: &'a [u8],
    pub(crate) configuration: &'a [u8],
}

/// Locate the four members, or say which rule the archive broke.
///
/// # Errors
/// [`ArchiveError`], one variant per rule this format states.
pub(crate) fn stage(archive: &[u8]) -> Result<Staged<'_>, ArchiveError> {
    let len = archive.len();
    if len > ARCHIVE_BOUND {
        return Err(ArchiveError::ArchiveOverBound {
            len,
            bound: ARCHIVE_BOUND,
        });
    }
    if !len.is_multiple_of(BLOCK) {
        return Err(ArchiveError::NotAWholeNumberOfBlocks { len });
    }

    let mut device_certificate = None;
    let mut trust_anchor = None;
    let mut management_endpoint = None;
    let mut configuration = None;
    let mut rest = archive;
    let mut terminated = false;

    for _ in 0..MAX_BLOCKS {
        let at = len.saturating_sub(rest.len());
        let Some((header, after_header)) = rest.split_at_checked(BLOCK) else {
            break;
        };
        if header.iter().all(|byte| *byte == 0) {
            check_terminator(rest, at)?;
            terminated = true;
            break;
        }

        let (member, size) = read_header(header, at)?;
        let target = match member {
            Member::DeviceCertificate => &mut device_certificate,
            Member::TrustAnchor => &mut trust_anchor,
            Member::ManagementEndpoint => &mut management_endpoint,
            Member::Configuration => &mut configuration,
        };
        if target.is_some() {
            return Err(ArchiveError::DuplicateMember { member });
        }

        let Some((body, after_body)) = after_header.split_at_checked(size) else {
            return Err(ArchiveError::MemberBodyTruncated { member, size });
        };
        // The body is padded to the block; the remainder of the last block is
        // the padding, and it carries nothing.
        let padding_width = match size % BLOCK {
            0 => 0,
            remainder => BLOCK - remainder,
        };
        let Some((padding, next)) = after_body.split_at_checked(padding_width) else {
            return Err(ArchiveError::MemberBodyTruncated { member, size });
        };
        if !padding.iter().all(|byte| *byte == 0) {
            return Err(ArchiveError::MemberPaddingIsNotZero { member });
        }

        *target = Some(body);
        rest = next;
    }

    if !terminated {
        return Err(ArchiveError::EndsWithoutTerminator);
    }

    Ok(Staged {
        device_certificate: device_certificate.ok_or(ArchiveError::MissingMember {
            member: Member::DeviceCertificate,
        })?,
        trust_anchor: trust_anchor.ok_or(ArchiveError::MissingMember {
            member: Member::TrustAnchor,
        })?,
        management_endpoint: management_endpoint.ok_or(ArchiveError::MissingMember {
            member: Member::ManagementEndpoint,
        })?,
        configuration: configuration.ok_or(ArchiveError::MissingMember {
            member: Member::Configuration,
        })?,
    })
}

/// Two zero blocks close the archive, and only zero bytes may follow them.
fn check_terminator(rest: &[u8], at: usize) -> Result<(), ArchiveError> {
    let Some((closing, after)) = rest.split_at_checked(TERMINATOR) else {
        return Err(ArchiveError::EndsWithoutTerminator);
    };
    if !closing.iter().all(|byte| *byte == 0) {
        return Err(ArchiveError::EndsWithoutTerminator);
    }
    if after.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(ArchiveError::BytesAfterEndOfArchive { at })
    }
}

/// Read one header, in the order the format's rules are stated: what kind of
/// archive it claims to be, whether it is intact, what kind of member it is,
/// what it is called, and how long it is.
fn read_header(header: &[u8], at: usize) -> Result<(Member, usize), ArchiveError> {
    let magic = field(header, MAGIC_AT, MAGIC_LEN).ok_or(ArchiveError::TruncatedHeader { at })?;
    let version =
        field(header, VERSION_AT, VERSION_LEN).ok_or(ArchiveError::TruncatedHeader { at })?;
    if magic != USTAR_MAGIC || version != USTAR_VERSION {
        return Err(ArchiveError::NotUstar { at });
    }

    check_checksum(header, at)?;

    let type_flag = field(header, TYPE_FLAG_AT, 1).ok_or(ArchiveError::TruncatedHeader { at })?;
    if type_flag != b"0" && type_flag != b"\0" {
        return Err(ArchiveError::NotARegularFile { at });
    }

    check_empty(
        header,
        at,
        LINK_NAME_AT,
        LINK_NAME_LEN,
        EmptyField::LinkName,
    )?;
    check_empty(header, at, PREFIX_AT, PREFIX_LEN, EmptyField::Prefix)?;

    let name = field(header, NAME_AT, NAME_LEN).ok_or(ArchiveError::TruncatedHeader { at })?;
    let member = member_named(name).ok_or(ArchiveError::UnknownMember { at })?;

    let size_field =
        field(header, SIZE_AT, SIZE_LEN).ok_or(ArchiveError::TruncatedHeader { at })?;
    let size = read_octal(size_field, at, NumericField::Size, ARCHIVE_BOUND)?;
    let bound = member.bound();
    if size > bound {
        return Err(ArchiveError::MemberOverBound {
            member,
            size,
            bound,
        });
    }
    Ok((member, size))
}

/// The checksum, over the header with its own field read as eight spaces.
fn check_checksum(header: &[u8], at: usize) -> Result<(), ArchiveError> {
    let stated_field =
        field(header, CHECKSUM_AT, CHECKSUM_LEN).ok_or(ArchiveError::TruncatedHeader { at })?;
    let end = CHECKSUM_AT
        .checked_add(CHECKSUM_LEN)
        .ok_or(ArchiveError::TruncatedHeader { at })?;
    // Saturating rather than wrapping: a block is 512 bytes of at most 255, so
    // the ceiling is out of reach and changes no meaning here, while a fold that
    // wrapped could fold a longer slice around onto a value that verified.
    let computed = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (CHECKSUM_AT..end).contains(&index) {
                usize::from(b' ')
            } else {
                usize::from(*byte)
            }
        })
        .fold(0_usize, usize::saturating_add);
    let stated = read_octal(stated_field, at, NumericField::Checksum, MAX_CHECKSUM)?;
    if stated == computed {
        Ok(())
    } else {
        Err(ArchiveError::ChecksumMismatch {
            at,
            stated,
            computed,
        })
    }
}

fn check_empty(
    header: &[u8],
    at: usize,
    start: usize,
    width: usize,
    which: EmptyField,
) -> Result<(), ArchiveError> {
    let bytes = field(header, start, width).ok_or(ArchiveError::TruncatedHeader { at })?;
    if bytes.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(ArchiveError::FieldIsNotEmpty { at, field: which })
    }
}

/// The member a name field names: one of the four names, byte for byte, padded
/// with NUL and nothing else. A leading `./`, a directory component or a
/// trailing space all fail this, having no name in the set to equal.
fn member_named(name: &[u8]) -> Option<Member> {
    Member::ALL.into_iter().find(|member| {
        let spelled = member.name();
        name.get(..spelled.len()) == Some(spelled)
            && name
                .get(spelled.len()..)
                .is_some_and(|tail| tail.iter().all(|byte| *byte == 0))
    })
}

/// A numeric field: the bytes before its first NUL, trimmed of the padding
/// spaces the format permits, read as octal and held to `limit`.
fn read_octal(
    bytes: &[u8],
    at: usize,
    which: NumericField,
    limit: usize,
) -> Result<usize, ArchiveError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let digits = bytes.get(..end).unwrap_or_default().trim_ascii();
    if digits.is_empty() {
        return Err(ArchiveError::EmptyNumericField { at, field: which });
    }
    let mut value = 0_usize;
    for byte in digits {
        let Some(digit) = byte.checked_sub(b'0').filter(|digit| *digit < 8) else {
            return Err(ArchiveError::NotOctal { at, field: which });
        };
        value = value
            .checked_mul(8)
            .and_then(|shifted| shifted.checked_add(usize::from(digit)))
            .filter(|candidate| *candidate <= limit)
            .ok_or(ArchiveError::NumericFieldOverBound { at, field: which })?;
    }
    Ok(value)
}

/// One header field, by offset and width.
fn field(header: &[u8], at: usize, width: usize) -> Option<&[u8]> {
    let end = at.checked_add(width)?;
    header.get(at..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header reader is handed a whole block by its only caller, so the
    /// short-slice refusal is reached from here rather than from the walk.
    #[test]
    fn a_block_shorter_than_a_header_is_refused_by_offset() {
        assert_eq!(
            read_header(&[0_u8; 8], 512),
            Err(ArchiveError::TruncatedHeader { at: 512 })
        );
    }

    #[test]
    fn an_empty_numeric_field_and_a_non_octal_one_are_told_apart() {
        assert_eq!(
            read_octal(b"        ", 0, NumericField::Size, ARCHIVE_BOUND),
            Err(ArchiveError::EmptyNumericField {
                at: 0,
                field: NumericField::Size
            })
        );
        assert_eq!(
            read_octal(b"00009999\0", 0, NumericField::Size, ARCHIVE_BOUND),
            Err(ArchiveError::NotOctal {
                at: 0,
                field: NumericField::Size
            })
        );
        assert_eq!(
            read_octal(b"0000!000\0", 0, NumericField::Size, ARCHIVE_BOUND),
            Err(ArchiveError::NotOctal {
                at: 0,
                field: NumericField::Size
            })
        );
    }

    #[test]
    fn an_octal_field_past_its_limit_is_refused_rather_than_wrapped() {
        assert_eq!(
            read_octal(b"77777777777\0", 0, NumericField::Size, ARCHIVE_BOUND),
            Err(ArchiveError::NumericFieldOverBound {
                at: 0,
                field: NumericField::Size
            })
        );
    }

    #[test]
    fn a_name_is_the_whole_field_and_nothing_around_it() {
        let mut name = [0_u8; NAME_LEN];
        let spelled = Member::TrustAnchor.name();
        if let Some(head) = name.get_mut(..spelled.len()) {
            head.copy_from_slice(spelled);
        }
        assert_eq!(member_named(&name), Some(Member::TrustAnchor));
        if let Some(byte) = name.get_mut(spelled.len()) {
            *byte = b' ';
        }
        assert_eq!(member_named(&name), None);
        assert_eq!(member_named(b"./trust-anchor.pem"), None);
    }

    #[test]
    fn a_field_outside_the_block_has_no_bytes_rather_than_a_panic() {
        assert_eq!(field(&[0_u8; 4], 2, 4), None);
        assert_eq!(field(&[0_u8; 4], 1, usize::MAX), None);
    }
}
