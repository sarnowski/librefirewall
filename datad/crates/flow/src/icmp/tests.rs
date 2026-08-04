use super::*;
use proptest::prelude::*;
use std::vec::Vec;

const CLIENT: Ipv4Address = Ipv4Address::from_octets([10, 0, 1, 10]);
const SERVER: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 20]);

fn icmp(message_type: u8, code: u8, identifier: u16) -> IcmpHeader {
    let [high, low] = identifier.to_be_bytes();
    IcmpHeader {
        message_type,
        code,
        checksum: 0,
        rest_of_header: [high, low, 0, 3],
    }
}

/// A quoted IPv4 header, every field a test may need to spoil reachable.
struct Quote {
    version_and_length: u8,
    fragment_offset: u16,
    protocol: u8,
    source: Ipv4Address,
    destination: Ipv4Address,
    behind: Vec<u8>,
}

impl Quote {
    fn tcp(
        source: Ipv4Address,
        destination: Ipv4Address,
        ports: (u16, u16),
        sequence: u32,
    ) -> Self {
        let mut behind = Vec::new();
        behind.extend_from_slice(&ports.0.to_be_bytes());
        behind.extend_from_slice(&ports.1.to_be_bytes());
        behind.extend_from_slice(&sequence.to_be_bytes());
        Self {
            version_and_length: 0x45,
            fragment_offset: 0,
            protocol: Protocol::TCP.0,
            source,
            destination,
            behind,
        }
    }

    fn udp(source: Ipv4Address, destination: Ipv4Address, ports: (u16, u16)) -> Self {
        let mut behind = Vec::new();
        behind.extend_from_slice(&ports.0.to_be_bytes());
        behind.extend_from_slice(&ports.1.to_be_bytes());
        Self {
            version_and_length: 0x45,
            fragment_offset: 0,
            protocol: Protocol::UDP.0,
            source,
            destination,
            behind,
        }
    }

    fn echo(
        source: Ipv4Address,
        destination: Ipv4Address,
        message_type: u8,
        identifier: u16,
    ) -> Self {
        let [high, low] = identifier.to_be_bytes();
        Self {
            version_and_length: 0x45,
            fragment_offset: 0,
            protocol: Protocol::ICMP.0,
            source,
            destination,
            behind: std::vec![message_type, 0, 0, 0, high, low, 0, 1],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = std::vec![0u8; IPV4_HEADER_LEN];
        let mut write = |offset: usize, value: u8| {
            if let Some(cell) = bytes.get_mut(offset) {
                *cell = value;
            }
        };
        write(0, self.version_and_length);
        let [offset_high, offset_low] = self.fragment_offset.to_be_bytes();
        write(6, offset_high);
        write(7, offset_low);
        write(9, self.protocol);
        for (index, octet) in self.source.octets().into_iter().enumerate() {
            write(12 + index, octet);
        }
        for (index, octet) in self.destination.octets().into_iter().enumerate() {
            write(16 + index, octet);
        }
        bytes.extend_from_slice(&self.behind);
        bytes
    }
}

// --------------------------------------------------------------- messages

#[test]
fn the_three_messages_this_tracker_reads_are_recognised() {
    assert_eq!(
        message(&icmp(IcmpHeader::ECHO_REQUEST, 0, 0x1234)),
        Some(Message::EchoRequest { identifier: 0x1234 })
    );
    assert_eq!(
        message(&icmp(IcmpHeader::ECHO_REPLY, 0, 0x1234)),
        Some(Message::EchoReply { identifier: 0x1234 })
    );
    for message_type in [
        IcmpHeader::DESTINATION_UNREACHABLE,
        IcmpHeader::TIME_EXCEEDED,
        IcmpHeader::PARAMETER_PROBLEM,
    ] {
        // The code says why, which changes nothing about which flow is named.
        for code in [0u8, 3, 13] {
            assert_eq!(message(&icmp(message_type, code, 0)), Some(Message::Error));
        }
    }
}

/// A redirect is a routing instruction rather than a report about a datagram, so
/// admitting one under cover of a guessed flow is refused by not reading it.
#[test]
fn a_redirect_and_the_unread_types_are_no_message_at_all() {
    for message_type in [IcmpHeader::REDIRECT, 4, 9, 10, 13, 14, 17, 18, 42] {
        assert_eq!(message(&icmp(message_type, 0, 0)), None);
    }
}

/// An echo with a non-zero code is not an echo: the code is part of what
/// identifies the message.
#[test]
fn an_echo_with_a_code_is_not_an_echo() {
    for message_type in [IcmpHeader::ECHO_REQUEST, IcmpHeader::ECHO_REPLY] {
        assert_eq!(message(&icmp(message_type, 1, 0)), None);
    }
}

#[test]
fn the_quoted_bytes_are_what_sits_behind_the_error_header() {
    let mut message = std::vec![0u8; ICMP_HEADER_LEN];
    message.extend_from_slice(b"quoted");
    assert_eq!(quoted_bytes(&message), b"quoted");
    assert!(quoted_bytes(&[0u8; 3]).is_empty());
    assert!(quoted_bytes(&[]).is_empty());
}

// ---------------------------------------------------------------- quotes

#[test]
fn a_well_formed_tcp_quote_yields_its_tuple() {
    let quote = Quote::tcp(CLIENT, SERVER, (40_000, 443), 0xabcd_1234);
    let read = quoted(CLIENT, &quote.bytes()).expect("a quote");
    assert_eq!(read.source, CLIENT);
    assert_eq!(read.destination, SERVER);
    assert_eq!(read.protocol, Protocol::TCP);
    assert_eq!(read.source_port, 40_000);
    assert_eq!(read.destination_port, 443);
    assert_eq!(read.sequence, Some(SeqNumber::new(0xabcd_1234)));
}

#[test]
fn a_udp_quote_yields_its_ports_and_no_sequence() {
    let quote = Quote::udp(CLIENT, SERVER, (50_000, 53));
    let read = quoted(CLIENT, &quote.bytes()).expect("a quote");
    assert_eq!(read.source_port, 50_000);
    assert_eq!(read.destination_port, 53);
    assert_eq!(read.sequence, None);
}

/// An echo's identifier stands where a port would at both ends, so the tuple a
/// quote yields is the one the echo flow was keyed by.
#[test]
fn an_echo_quote_yields_its_identifier_at_both_ends() {
    let quote = Quote::echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 0x2a2a);
    let read = quoted(CLIENT, &quote.bytes()).expect("a quote");
    assert_eq!(read.source_port, 0x2a2a);
    assert_eq!(read.destination_port, 0x2a2a);
    assert_eq!(read.sequence, None);
}

/// The bind that stops an error being attached to a flow its sender merely knows
/// about: the quoted datagram must have been travelling away from the party being
/// told.
#[test]
fn a_quote_not_from_the_party_being_told_is_refused() {
    let quote = Quote::tcp(SERVER, CLIENT, (443, 40_000), 1);
    assert_eq!(
        quoted(CLIENT, &quote.bytes()),
        Err(QuotedError::NotFromTheReporter {
            quoted_source: SERVER
        })
    );
}

#[test]
fn a_quote_that_is_not_ipv4_is_refused() {
    let mut quote = Quote::tcp(CLIENT, SERVER, (1, 2), 3);
    quote.version_and_length = 0x65;
    assert_eq!(
        quoted(CLIENT, &quote.bytes()),
        Err(QuotedError::NotIpv4 { version: 6 })
    );
}

#[test]
fn a_quote_whose_header_length_is_impossible_is_refused() {
    for words in [0u8, 1, 4, 15] {
        let mut quote = Quote::tcp(CLIENT, SERVER, (1, 2), 3);
        quote.version_and_length = 0x40 | words;
        assert_eq!(
            quoted(CLIENT, &quote.bytes()),
            Err(QuotedError::HeaderLengthInvalid {
                header_words: words
            }),
            "{words} words was admitted"
        );
    }
}

#[test]
fn a_quoted_fragment_carries_no_ports_and_is_refused() {
    let mut quote = Quote::tcp(CLIENT, SERVER, (1, 2), 3);
    quote.fragment_offset = 185;
    assert_eq!(
        quoted(CLIENT, &quote.bytes()),
        Err(QuotedError::Fragmented {
            fragment_offset: 185
        })
    );
}

#[test]
fn a_quoted_protocol_this_tracker_holds_no_flow_for_is_refused() {
    let mut quote = Quote::tcp(CLIENT, SERVER, (1, 2), 3);
    quote.protocol = 47;
    assert_eq!(
        quoted(CLIENT, &quote.bytes()),
        Err(QuotedError::ProtocolUnsupported(Protocol(47)))
    );
}

#[test]
fn a_quoted_icmp_message_that_is_not_an_echo_is_refused() {
    let quote = Quote::echo(CLIENT, SERVER, IcmpHeader::DESTINATION_UNREACHABLE, 0);
    assert_eq!(
        quoted(CLIENT, &quote.bytes()),
        Err(QuotedError::NotAnEcho {
            message_type: IcmpHeader::DESTINATION_UNREACHABLE
        })
    );
}

/// Every prefix of a well-formed quote is refused rather than read past, for each
/// of the three protocols and their different field requirements.
#[test]
fn every_short_quote_is_refused() {
    for quote in [
        Quote::tcp(CLIENT, SERVER, (1, 2), 3),
        Quote::udp(CLIENT, SERVER, (1, 2)),
        Quote::echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 4),
    ] {
        let whole = quote.bytes();
        assert!(quoted(CLIENT, &whole).is_ok());
        for length in 0..whole.len() {
            let short = whole.get(..length).unwrap_or_default();
            assert!(
                matches!(
                    quoted(CLIENT, short),
                    Err(QuotedError::Truncated { .. } | QuotedError::HeaderLengthInvalid { .. })
                ),
                "a {length}-byte quote was read"
            );
        }
    }
}

/// A quoted header carrying options is skipped by its own declared length, and
/// the length is held to what was actually quoted rather than to what the
/// datagram claimed about itself.
#[test]
fn a_quoted_header_with_options_is_skipped_by_its_own_length() {
    let mut quote = Quote::tcp(CLIENT, SERVER, (40_000, 443), 9);
    quote.version_and_length = 0x46;
    // One word of options in front of the transport fields.
    let mut behind = std::vec![0u8; 4];
    behind.extend_from_slice(&quote.behind);
    quote.behind = behind;
    let read = quoted(CLIENT, &quote.bytes()).expect("a quote");
    assert_eq!(read.source_port, 40_000);
    assert_eq!(read.destination_port, 443);
    assert_eq!(read.sequence, Some(SeqNumber::new(9)));
}

/// The seven refusals are seven distinct values, so a refused quote names the
/// claim that did not hold rather than a category.
#[test]
fn the_quoted_refusals_are_distinct() {
    let errors = [
        QuotedError::Truncated { needed: 1, got: 0 },
        QuotedError::NotIpv4 { version: 6 },
        QuotedError::HeaderLengthInvalid { header_words: 1 },
        QuotedError::Fragmented { fragment_offset: 1 },
        QuotedError::ProtocolUnsupported(Protocol(47)),
        QuotedError::NotFromTheReporter {
            quoted_source: CLIENT,
        },
        QuotedError::NotAnEcho { message_type: 3 },
    ];
    for (position, error) in errors.into_iter().enumerate() {
        for (other_position, other) in errors.into_iter().enumerate() {
            assert_eq!(position == other_position, error == other);
        }
    }
}

proptest! {
    /// Reading a quote out of arbitrary bytes never panics and never reads past
    /// the slice: every byte of a quote is chosen by whoever sent the error.
    #[test]
    fn reading_an_arbitrary_quote_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..80),
        target in any::<u32>(),
    ) {
        let target = Ipv4Address::from_octets(target.to_be_bytes());
        if let Ok(read) = quoted(target, &bytes) {
            // Anything accepted names the party being told as its source, which
            // is the one claim corroborated inside this function.
            prop_assert_eq!(read.source, target);
            prop_assert!(matches!(
                read.protocol,
                Protocol::TCP | Protocol::UDP | Protocol::ICMP
            ));
            prop_assert_eq!(read.sequence.is_some(), read.protocol == Protocol::TCP);
        }
    }

    /// A well-formed quote is read back exactly, for any tuple: the fields a flow
    /// is looked up by must survive the round trip or the lookup names the wrong
    /// flow.
    #[test]
    fn a_well_formed_quote_round_trips(
        destination in any::<u32>(),
        source_port in any::<u16>(),
        destination_port in any::<u16>(),
        sequence in any::<u32>(),
    ) {
        let destination = Ipv4Address::from_octets(destination.to_be_bytes());
        let quote = Quote::tcp(CLIENT, destination, (source_port, destination_port), sequence);
        let read = quoted(CLIENT, &quote.bytes()).expect("a quote");
        prop_assert_eq!(read.destination, destination);
        prop_assert_eq!(read.source_port, source_port);
        prop_assert_eq!(read.destination_port, destination_port);
        prop_assert_eq!(read.sequence, Some(SeqNumber::new(sequence)));
    }
}
