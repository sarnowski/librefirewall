//! Attribute text to domain type.
//!
//! Every function here is total over arbitrary bytes and none of them are
//! lenient. Leading zeros are refused rather than read as decimal, because a
//! reader that accepts `010` has to decide whether it means eight or ten and
//! either answer is a surprise to somebody; a length is checked before a digit
//! is looked at, so no accumulator ever sees more digits than its type can
//! hold.

use lfw_log::Identifier;
use net_headers::{Ipv4Address, MacAddress, Protocol};

use crate::rule::{
    AddressMatch, IcmpTypeMatch, InterfaceMatch, PortMatch, ProtocolMatch, RuleAction,
};

/// Why a value is not the thing its attribute names.
///
/// Two variants rather than one because they are two different edits: a value
/// that is the wrong shape was typed wrong, and one that is the right shape and
/// out of range was thought wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueError {
    Malformed,
    OutOfRange,
}

/// # Errors
/// [`ValueError::Malformed`] for anything outside `[a-z0-9-]{1,16}`.
pub fn identifier(bytes: &[u8]) -> Result<Identifier, ValueError> {
    Identifier::new(bytes).map_err(|_| ValueError::Malformed)
}

/// # Errors
/// [`ValueError::Malformed`] for anything but `true` or `false`. There is no
/// `1`, no `yes` and no empty-means-true: an interface being up is not
/// something to infer.
pub fn boolean(bytes: &[u8]) -> Result<bool, ValueError> {
    match bytes {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err(ValueError::Malformed),
    }
}

/// # Errors
/// [`ValueError`] for a value that is not a decimal number, or is one and does
/// not fit a `u8`. Whether the port exists on this build is a separate
/// question, answered against a count the document does not supply.
pub fn port(bytes: &[u8]) -> Result<u8, ValueError> {
    decimal(bytes)
}

/// # Errors
/// As [`port`]; whether the length is a legal prefix is decided later, against
/// [`wire::MAX_PREFIX_LENGTH`].
pub fn prefix_length(bytes: &[u8]) -> Result<u8, ValueError> {
    decimal(bytes)
}

/// # Errors
/// [`ValueError::Malformed`] unless the value is exactly four dotted decimal
/// octets.
pub fn ipv4(bytes: &[u8]) -> Result<Ipv4Address, ValueError> {
    let mut octets = [0u8; 4];
    let mut fields = bytes.split(|byte| *byte == b'.');
    for slot in &mut octets {
        let Some(field) = fields.next() else {
            return Err(ValueError::Malformed);
        };
        *slot = decimal(field)?;
    }
    if fields.next().is_some() {
        return Err(ValueError::Malformed);
    }
    Ok(Ipv4Address::from_octets(octets))
}

/// # Errors
/// [`ValueError::Malformed`] unless the value is exactly six colon-separated
/// hexadecimal octet pairs. Whether the address is one an interface may hold is
/// decided later.
pub fn mac(bytes: &[u8]) -> Result<MacAddress, ValueError> {
    const TEXT_LEN: usize = 17;
    const LAST: usize = 5;
    if bytes.len() != TEXT_LEN {
        return Err(ValueError::Malformed);
    }
    let mut octets = [0u8; 6];
    for (index, (chunk, slot)) in bytes.chunks(3).zip(octets.iter_mut()).enumerate() {
        let high = hex_digit(chunk.first())?;
        let low = hex_digit(chunk.get(1))?;
        *slot = (high << 4) | low;
        match chunk.get(2) {
            Some(b':') if index < LAST => {}
            None if index == LAST => {}
            _ => return Err(ValueError::Malformed),
        }
    }
    Ok(MacAddress(octets))
}

/// The wildcard every criterion below admits, spelled out for the reason
/// `enabled` is: a rule that matches everything is the widest thing an operator
/// can write, and it is written rather than inferred from an omission.
const ANY: &[u8] = b"any";

/// # Errors
/// [`ValueError::Malformed`] for anything but `any` or an identifier.
pub fn interface_match(bytes: &[u8]) -> Result<InterfaceMatch, ValueError> {
    if bytes == ANY {
        return Ok(InterfaceMatch::Any);
    }
    identifier(bytes).map(InterfaceMatch::Named)
}

/// # Errors
/// [`ValueError`] for anything but `any` or exactly one dotted quad, a `/` and
/// a prefix length. Whether the length is a legal prefix, and whether the
/// address is the block it names, are decided later against the model.
pub fn address_match(bytes: &[u8]) -> Result<AddressMatch, ValueError> {
    if bytes == ANY {
        return Ok(AddressMatch::Any);
    }
    let mut fields = bytes.split(|byte| *byte == b'/');
    let (Some(address), Some(length), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err(ValueError::Malformed);
    };
    Ok(AddressMatch::Block {
        network: ipv4(address)?,
        prefix_length: decimal(length)?,
    })
}

/// # Errors
/// [`ValueError`] for anything but `any`, one of the three names, or a decimal
/// protocol number.
pub fn protocol_match(bytes: &[u8]) -> Result<ProtocolMatch, ValueError> {
    Ok(match bytes {
        ANY => ProtocolMatch::Any,
        b"tcp" => ProtocolMatch::Only(Protocol::TCP),
        b"udp" => ProtocolMatch::Only(Protocol::UDP),
        b"icmp" => ProtocolMatch::Only(Protocol::ICMP),
        number => ProtocolMatch::Only(Protocol(decimal(number)?)),
    })
}

/// # Errors
/// [`ValueError`] for anything but `any`, one port, or two separated by `-`.
/// Whether the range runs the right way is decided later, the shape being
/// well formed either way.
pub fn port_match(bytes: &[u8]) -> Result<PortMatch, ValueError> {
    if bytes == ANY {
        return Ok(PortMatch::Any);
    }
    let mut fields = bytes.split(|byte| *byte == b'-');
    let (Some(low), high, rest) = (fields.next(), fields.next(), fields.next()) else {
        return Err(ValueError::Malformed);
    };
    if rest.is_some() {
        return Err(ValueError::Malformed);
    }
    let low = decimal16(low)?;
    Ok(PortMatch::Range {
        low,
        high: match high {
            Some(high) => decimal16(high)?,
            None => low,
        },
    })
}

/// # Errors
/// [`ValueError`] for anything but `any` or a decimal message type.
pub fn icmp_type_match(bytes: &[u8]) -> Result<IcmpTypeMatch, ValueError> {
    if bytes == ANY {
        return Ok(IcmpTypeMatch::Any);
    }
    decimal(bytes).map(IcmpTypeMatch::Only)
}

/// # Errors
/// [`ValueError::Malformed`] for anything but `accept` or `drop`. There is no
/// `allow`, no `deny` and no `permit`: one spelling each, so two documents
/// cannot say the same thing two ways.
pub fn action(bytes: &[u8]) -> Result<RuleAction, ValueError> {
    match bytes {
        b"accept" => Ok(RuleAction::Accept),
        b"drop" => Ok(RuleAction::Drop),
        _ => Err(ValueError::Malformed),
    }
}

/// A decimal `u8` with no sign, no padding and no leading zero.
fn decimal(bytes: &[u8]) -> Result<u8, ValueError> {
    const MAX_DIGITS: usize = 3;
    if bytes.is_empty() || bytes.len() > MAX_DIGITS {
        return Err(ValueError::Malformed);
    }
    if bytes.len() > 1 && bytes.first() == Some(&b'0') {
        return Err(ValueError::Malformed);
    }
    let mut value = 0u32;
    for byte in bytes {
        let Some(digit) = char::from(*byte).to_digit(10) else {
            return Err(ValueError::Malformed);
        };
        value = value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(digit))
            .ok_or(ValueError::OutOfRange)?;
    }
    u8::try_from(value).map_err(|_| ValueError::OutOfRange)
}

/// [`decimal`]'s rule at a port's width: five digits rather than three, and the
/// same refusal of a sign, padding and a leading zero.
fn decimal16(bytes: &[u8]) -> Result<u16, ValueError> {
    const MAX_DIGITS: usize = 5;
    if bytes.is_empty() || bytes.len() > MAX_DIGITS {
        return Err(ValueError::Malformed);
    }
    if bytes.len() > 1 && bytes.first() == Some(&b'0') {
        return Err(ValueError::Malformed);
    }
    let mut value = 0u32;
    for byte in bytes {
        let Some(digit) = char::from(*byte).to_digit(10) else {
            return Err(ValueError::Malformed);
        };
        value = value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(digit))
            .ok_or(ValueError::OutOfRange)?;
    }
    u16::try_from(value).map_err(|_| ValueError::OutOfRange)
}

fn hex_digit(byte: Option<&u8>) -> Result<u8, ValueError> {
    let Some(byte) = byte else {
        return Err(ValueError::Malformed);
    };
    let Some(digit) = char::from(*byte).to_digit(16) else {
        return Err(ValueError::Malformed);
    };
    u8::try_from(digit).map_err(|_| ValueError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn an_identifier_is_the_configuration_alphabet_and_nothing_wider() {
        assert_eq!(identifier(b"wan-0").expect("valid").as_str(), "wan-0");
        for text in [&b""[..], b"WAN", b"wan_0", b"abcdefghijklmnopq", b"\xff"] {
            assert_eq!(identifier(text), Err(ValueError::Malformed), "{text:?}");
        }
    }

    #[test]
    fn a_boolean_is_spelled_out_in_full() {
        assert_eq!(boolean(b"true"), Ok(true));
        assert_eq!(boolean(b"false"), Ok(false));
        for text in [&b""[..], b"1", b"0", b"yes", b"TRUE", b"True", b" true"] {
            assert_eq!(boolean(text), Err(ValueError::Malformed), "{text:?}");
        }
    }

    #[test]
    fn a_decimal_covers_the_whole_byte_range_and_stops_there() {
        assert_eq!(port(b"0"), Ok(0));
        assert_eq!(port(b"255"), Ok(255));
        assert_eq!(prefix_length(b"32"), Ok(32));
        assert_eq!(port(b"256"), Err(ValueError::OutOfRange));
        assert_eq!(port(b"999"), Err(ValueError::OutOfRange));
    }

    #[test]
    fn a_decimal_refuses_padding_signs_and_leading_zeros() {
        for text in [
            &b""[..],
            b"00",
            b"01",
            b"+1",
            b"-1",
            b" 1",
            b"1 ",
            b"1000",
            b"1x",
        ] {
            assert_eq!(port(text), Err(ValueError::Malformed), "{text:?}");
        }
    }

    #[test]
    fn an_address_is_four_dotted_octets() {
        assert_eq!(
            ipv4(b"10.0.0.1"),
            Ok(Ipv4Address::from_octets([10, 0, 0, 1]))
        );
        assert_eq!(
            ipv4(b"255.255.255.255"),
            Ok(Ipv4Address::from_octets([255, 255, 255, 255]))
        );
        assert_eq!(ipv4(b"0.0.0.0"), Ok(Ipv4Address::from_octets([0, 0, 0, 0])));
    }

    #[test]
    fn an_address_with_the_wrong_number_of_octets_or_a_bad_one_is_refused() {
        for text in [
            &b""[..],
            b"10.0.0",
            b"10.0.0.1.2",
            b"10.0.0.",
            b".10.0.0.1",
            b"10.0.0.x",
        ] {
            assert_eq!(ipv4(text), Err(ValueError::Malformed), "{text:?}");
        }
        assert_eq!(ipv4(b"10.0.0.256"), Err(ValueError::OutOfRange));
    }

    #[test]
    fn a_mac_is_six_colon_separated_hexadecimal_pairs_in_either_case() {
        assert_eq!(
            mac(b"52:54:00:12:34:50"),
            Ok(MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]))
        );
        assert_eq!(
            mac(b"AB:cd:EF:01:23:45"),
            Ok(MacAddress([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]))
        );
        assert_eq!(mac(b"ff:ff:ff:ff:ff:ff"), Ok(MacAddress([0xff; 6])));
    }

    #[test]
    fn a_mac_of_the_wrong_length_or_separator_or_alphabet_is_refused() {
        for text in [
            &b""[..],
            b"52:54:00:12:34",
            b"52:54:00:12:34:50:66",
            b"52-54-00-12-34-50",
            b"52:54:00:12:34:5g",
            b"52:54:00:12:34:5",
            b"525400123450     ",
            b":2:54:00:12:34:50",
        ] {
            assert_eq!(mac(text), Err(ValueError::Malformed), "{text:?}");
        }
    }

    proptest! {
        /// Total, and never a partial read: whatever comes back, the input was
        /// either wholly a value of that type or wholly refused.
        #[test]
        fn every_parser_is_total_over_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..40),
        ) {
            let _ = identifier(&bytes);
            let _ = boolean(&bytes);
            let _ = port(&bytes);
            let _ = prefix_length(&bytes);
            let _ = ipv4(&bytes);
            let _ = mac(&bytes);
        }

        /// Everything the grammars admit is accepted, so the refusal set is
        /// exactly their complement rather than something narrower.
        #[test]
        fn every_well_formed_value_is_accepted(
            octets in proptest::array::uniform4(any::<u8>()),
            address in proptest::array::uniform6(any::<u8>()),
            number in any::<u8>(),
        ) {
            let dotted = std::format!(
                "{}.{}.{}.{}",
                octets[0], octets[1], octets[2], octets[3]
            );
            prop_assert_eq!(ipv4(dotted.as_bytes()), Ok(Ipv4Address::from_octets(octets)));

            let hex = std::format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                address[0], address[1], address[2], address[3], address[4], address[5]
            );
            prop_assert_eq!(mac(hex.as_bytes()), Ok(MacAddress(address)));

            prop_assert_eq!(port(std::format!("{number}").as_bytes()), Ok(number));
        }
    }
}
