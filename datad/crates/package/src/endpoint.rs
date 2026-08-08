//! The `management-endpoint` member: one line naming where this appliance
//! answers to.
//!
//! # Adversary
//!
//! The **management-plane attacker**, whose bytes these are.
//!
//! # Why an address literal, spelled one way
//!
//! There is no resolver on this path, so what the member carries is an address
//! and never a name — nothing between an appliance and its management server
//! can be poisoned into answering for it. That leaves the spelling, and the
//! spelling is where two parsers disagree: an octet written `010` is ten to one
//! reader and eight to another, and an appliance that dialled the second while
//! an operator read the first would be talking to somebody else entirely. So an
//! octet is written the one way a decimal number is written, and a leading zero
//! is refused rather than interpreted.

/// Bytes the member may occupy, which bounds every loop below.
const MEMBER_BOUND: usize = crate::Member::ManagementEndpoint.bound();

/// Octets a dotted quad carries.
const OCTETS: usize = 4;

/// Decimal digits an octet may be written in.
const OCTET_DIGITS: usize = 3;

/// Decimal digits a port may be written in.
const PORT_DIGITS: usize = 5;

/// Where the appliance dials its management server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: [u8; OCTETS],
    pub port: u16,
}

/// Why a member is not an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointError {
    Empty,
    /// A byte outside the printable ASCII the line is written in.
    NotAscii,
    /// The member is longer than the bound the archive admits for it, which is
    /// the one refusal here the archive layer normally makes first.
    OverBound {
        len: usize,
        bound: usize,
    },
    MissingColon,
    /// A second colon, so which part is the port would have two answers.
    TooManyColons,
    /// Something other than a single line feed after the port.
    TrailingBytes,
    AddressHasTooFewOctets {
        octets: usize,
    },
    AddressHasTooManyOctets,
    OctetIsEmpty,
    OctetIsNotDecimal,
    /// An octet written with a leading zero, which two readers read as two
    /// numbers.
    OctetHasLeadingZero,
    OctetOutOfRange,
    PortIsEmpty,
    PortIsNotDecimal,
    PortHasLeadingZero,
    /// A port outside 1 to 65535; zero is not a port to dial.
    PortOutOfRange,
}

/// Read the member, or say what it is instead.
///
/// # Errors
/// [`EndpointError`] naming the rule the line broke.
pub(crate) fn parse(member: &[u8]) -> Result<Endpoint, EndpointError> {
    if member.len() > MEMBER_BOUND {
        return Err(EndpointError::OverBound {
            len: member.len(),
            bound: MEMBER_BOUND,
        });
    }
    if member.is_empty() {
        return Err(EndpointError::Empty);
    }
    if !member.is_ascii() {
        return Err(EndpointError::NotAscii);
    }
    // One optional line feed closes the line, and nothing else may follow it.
    let line = match member.split_last() {
        Some((b'\n', head)) => head,
        _ => member,
    };
    if line.contains(&b'\n') {
        return Err(EndpointError::TrailingBytes);
    }

    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(EndpointError::MissingColon);
    };
    let (address_text, rest) = line
        .split_at_checked(colon)
        .ok_or(EndpointError::MissingColon)?;
    let port_text = rest.get(1..).ok_or(EndpointError::MissingColon)?;
    if port_text.contains(&b':') {
        return Err(EndpointError::TooManyColons);
    }

    Ok(Endpoint {
        address: address(address_text)?,
        port: port(port_text)?,
    })
}

/// Four decimal octets, dot separated, each written the one way it is written.
fn address(text: &[u8]) -> Result<[u8; OCTETS], EndpointError> {
    let mut octets = [0_u8; OCTETS];
    let mut filled = 0_usize;
    let mut rest = text;
    // One turn per octet, plus the turn that finds there is a fifth.
    for _ in 0..=OCTETS {
        let (digits, tail) = match rest.iter().position(|byte| *byte == b'.') {
            Some(dot) => {
                let (head, after) = rest
                    .split_at_checked(dot)
                    .ok_or(EndpointError::OctetIsEmpty)?;
                (head, after.get(1..))
            }
            None => (rest, None),
        };
        let value = decimal(digits, OCTET_DIGITS)
            .map_err(NumberFault::as_octet)
            .and_then(|value| u8::try_from(value).map_err(|_| EndpointError::OctetOutOfRange))?;
        let Some(slot) = octets.get_mut(filled) else {
            return Err(EndpointError::AddressHasTooManyOctets);
        };
        *slot = value;
        filled = filled.saturating_add(1);
        match tail {
            Some(after) => rest = after,
            None => break,
        }
    }
    if filled == OCTETS {
        Ok(octets)
    } else {
        Err(EndpointError::AddressHasTooFewOctets { octets: filled })
    }
}

fn port(text: &[u8]) -> Result<u16, EndpointError> {
    let value = decimal(text, PORT_DIGITS).map_err(NumberFault::as_port)?;
    u16::try_from(value)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(EndpointError::PortOutOfRange)
}

/// Which way a decimal number was not one, before it is told whose it was.
#[derive(Clone, Copy)]
enum NumberFault {
    Empty,
    NotDecimal,
    LeadingZero,
    OutOfRange,
}

impl NumberFault {
    const fn as_octet(self) -> EndpointError {
        match self {
            Self::Empty => EndpointError::OctetIsEmpty,
            Self::NotDecimal => EndpointError::OctetIsNotDecimal,
            Self::LeadingZero => EndpointError::OctetHasLeadingZero,
            Self::OutOfRange => EndpointError::OctetOutOfRange,
        }
    }

    const fn as_port(self) -> EndpointError {
        match self {
            Self::Empty => EndpointError::PortIsEmpty,
            Self::NotDecimal => EndpointError::PortIsNotDecimal,
            Self::LeadingZero => EndpointError::PortHasLeadingZero,
            Self::OutOfRange => EndpointError::PortOutOfRange,
        }
    }
}

/// A decimal number of at most `digits` digits, written without a leading zero
/// unless it is the single digit zero.
fn decimal(text: &[u8], digits: usize) -> Result<u32, NumberFault> {
    if text.is_empty() {
        return Err(NumberFault::Empty);
    }
    if text.len() > digits {
        return Err(NumberFault::OutOfRange);
    }
    if text.first() == Some(&b'0') && text.len() > 1 {
        return Err(NumberFault::LeadingZero);
    }
    let mut value = 0_u32;
    for byte in text {
        let Some(digit) = byte.checked_sub(b'0').filter(|digit| *digit < 10) else {
            return Err(NumberFault::NotDecimal);
        };
        value = value
            .checked_mul(10)
            .and_then(|shifted| shifted.checked_add(u32::from(digit)))
            .ok_or(NumberFault::OutOfRange)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_the_management_server_writes_is_read_back() {
        assert_eq!(
            parse(b"192.0.2.10:8443\n"),
            Ok(Endpoint {
                address: [192, 0, 2, 10],
                port: 8443
            })
        );
        assert_eq!(
            parse(b"10.0.0.1:1"),
            Ok(Endpoint {
                address: [10, 0, 0, 1],
                port: 1
            })
        );
        assert_eq!(
            parse(b"255.255.255.255:65535\n"),
            Ok(Endpoint {
                address: [255, 255, 255, 255],
                port: 65535
            })
        );
    }

    #[test]
    fn every_way_a_line_is_not_an_endpoint_has_its_own_reason() {
        assert_eq!(parse(b""), Err(EndpointError::Empty));
        assert_eq!(parse(b"\xff:1"), Err(EndpointError::NotAscii));
        assert_eq!(parse(b"10.0.0.1"), Err(EndpointError::MissingColon));
        assert_eq!(parse(b"10.0.0.1:1:2"), Err(EndpointError::TooManyColons));
        assert_eq!(parse(b"10.0.0.1:1\n\n"), Err(EndpointError::TrailingBytes));
        assert_eq!(
            parse(b"10.0.0:1"),
            Err(EndpointError::AddressHasTooFewOctets { octets: 3 })
        );
        assert_eq!(
            parse(b"10.0.0.1.2:1"),
            Err(EndpointError::AddressHasTooManyOctets)
        );
        assert_eq!(parse(b":1"), Err(EndpointError::OctetIsEmpty));
        assert_eq!(parse(b"10..0.1:1"), Err(EndpointError::OctetIsEmpty));
        assert_eq!(parse(b"10.0.0.x:1"), Err(EndpointError::OctetIsNotDecimal));
        assert_eq!(
            parse(b"010.0.0.1:1"),
            Err(EndpointError::OctetHasLeadingZero)
        );
        assert_eq!(parse(b"256.0.0.1:1"), Err(EndpointError::OctetOutOfRange));
        assert_eq!(parse(b"1000.0.0.1:1"), Err(EndpointError::OctetOutOfRange));
        assert_eq!(parse(b"10.0.0.1:"), Err(EndpointError::PortIsEmpty));
        assert_eq!(parse(b"10.0.0.1:8x"), Err(EndpointError::PortIsNotDecimal));
        assert_eq!(
            parse(b"10.0.0.1:08"),
            Err(EndpointError::PortHasLeadingZero)
        );
        assert_eq!(parse(b"10.0.0.1:0"), Err(EndpointError::PortOutOfRange));
        assert_eq!(parse(b"10.0.0.1:65536"), Err(EndpointError::PortOutOfRange));
        assert_eq!(
            parse(b"10.0.0.1:999999"),
            Err(EndpointError::PortOutOfRange)
        );
        assert_eq!(
            parse(&[b'1'; MEMBER_BOUND + 1]),
            Err(EndpointError::OverBound {
                len: MEMBER_BOUND + 1,
                bound: MEMBER_BOUND
            })
        );
    }
}
