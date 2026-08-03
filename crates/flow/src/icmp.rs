//! ICMP: the echo exchange this tracker holds a flow for, and the error message
//! it relates to somebody else's flow.
//!
//! # Adversary
//!
//! **Untrusted network traffic**, and this module is the sharpest edge of it in
//! the crate. An ICMP error carries a copy of the datagram that provoked it, and
//! relating the error to a flow means reading a five-tuple *out of bytes the
//! sender chose*. A tracker that believed that copy would let anyone who can
//! send one packet have it classified as belonging to an established flow — which
//! is a misclassification with real consequence: `Related` is what decides where
//! the error *goes*, and a rule that names related traffic decides it against a
//! flow the sender merely guessed at rather than against the one it belongs to.
//!
//! It is not, and must not become, a way past the filter. Relating an error to a
//! flow does not admit it: the filter is still asked, and a policy that says
//! nothing about related traffic denies it — which is why the agreements below
//! bound what a sender can have *attributed* to a conversation rather than what it
//! can have carried.
//!
//! So the quoted datagram is treated as a claim to be corroborated, never as a
//! header to be read. Four things have to agree before it names a flow at all:
//!
//! * The **quoted source must be the party the error is addressed to.** An error
//!   travels from a router back to the sender of the datagram it quotes, so the
//!   datagram must be one that was travelling *away* from the address in the
//!   error's own destination field. This is what stops an attacker quoting a flow
//!   it merely knows about.
//! * The quoted **five-tuple must name a flow the table holds**, and the
//!   direction it implies must be one that flow has actually carried traffic in.
//! * For TCP, the quoted **sequence number must lie inside the window** that
//!   direction was authorised to send in. This is the expensive part to forge:
//!   without it, guessing a five-tuple is enough, and with it an off-path attacker
//!   needs the sequence number too.
//! * For an echo, the quoted **identifier must match** the flow's.
//!
//! # Why no checksum is verified here
//!
//! Neither the error's own checksum nor the quoted header's is checked, and that
//! is a decision rather than an omission. A checksum is not a signature: any party
//! that can compose the message can compute it, so verifying one refuses a
//! corrupted message and nothing else — while the four agreements above refuse a
//! *forged* one. A corrupted quote fails them too, because a flipped bit in an
//! address, a port or a sequence number is exactly what they compare. Adding a
//! second ones'-complement accumulator to this workspace to gain nothing is worse
//! than not having it.
//!
//! # Which error types relate, and which do not
//!
//! Destination-unreachable, time-exceeded and parameter-problem, and no others.
//! Redirect is deliberately outside the list: it is a routing instruction rather
//! than a report about a datagram, and admitting one as `Related` would let an
//! attacker have a routing change carried under cover of a flow it guessed. It is
//! refused, and a rule that wants redirects has to name them.

use net_headers::{
    ICMP_HEADER_LEN, IPV4_HEADER_LEN, IcmpHeader, Ipv4Address, Protocol, TCP_HEADER_LEN,
    UDP_HEADER_LEN,
};

use lfw_tcp::SeqNumber;

/// The code an echo request and an echo reply both carry.
const ECHO_CODE: u8 = 0;

/// What an ICMP message is, as this tracker reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Message {
    /// An echo request, which opens a flow.
    EchoRequest { identifier: u16 },
    /// An echo reply, which answers one.
    EchoReply { identifier: u16 },
    /// An error report quoting the datagram that provoked it.
    Error,
}

/// Which message a header is, or `None` for a type this tracker neither tracks
/// nor relates.
#[must_use]
pub(crate) fn message(header: &IcmpHeader) -> Option<Message> {
    let [identifier_high, identifier_low, _, _] = header.rest_of_header;
    let identifier = u16::from_be_bytes([identifier_high, identifier_low]);
    match (header.message_type, header.code) {
        (IcmpHeader::ECHO_REQUEST, ECHO_CODE) => Some(Message::EchoRequest { identifier }),
        (IcmpHeader::ECHO_REPLY, ECHO_CODE) => Some(Message::EchoReply { identifier }),
        // The code is not examined for an error: it says *why* the datagram was
        // refused, which changes nothing about which flow the quote names.
        (
            IcmpHeader::DESTINATION_UNREACHABLE
            | IcmpHeader::TIME_EXCEEDED
            | IcmpHeader::PARAMETER_PROBLEM,
            _,
        ) => Some(Message::Error),
        _ => None,
    }
}

/// Why a quoted datagram does not name a flow.
///
/// Every variant carries the value that refused it, so a refusal is attributable
/// to a byte the sender chose rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotedError {
    /// Fewer bytes quoted than the header and the transport fields a five-tuple
    /// is read from.
    Truncated {
        needed: usize,
        got: usize,
    },
    NotIpv4 {
        version: u8,
    },
    /// A header length below the five words a header is, or past what was quoted.
    HeaderLengthInvalid {
        header_words: u8,
    },
    /// A quoted fragment carrying no transport header, so no ports to read.
    Fragmented {
        fragment_offset: u16,
    },
    /// A protocol this tracker holds no flow for, so nothing the quote could name.
    ProtocolUnsupported(Protocol),
    /// The quoted datagram was not one travelling away from the address this
    /// error is addressed to, so it is not a datagram this error can be about.
    NotFromTheReporter {
        quoted_source: Ipv4Address,
    },
    /// The quoted datagram is an ICMP message that is not an echo, so it belongs
    /// to no flow either.
    NotAnEcho {
        message_type: u8,
    },
}

/// The five-tuple a quoted datagram claims, once every claim about it that can be
/// corroborated here has been.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Quoted {
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub protocol: Protocol,
    pub source_port: u16,
    pub destination_port: u16,
    /// The sequence number a quoted TCP header carried, which the flow's window
    /// is what corroborates. Absent for the two protocols that have none.
    pub sequence: Option<SeqNumber>,
}

/// How many bytes of the quoted transport header each protocol's fields need.
const TCP_FIELDS: usize = 8;
const UDP_FIELDS: usize = 4;
const ICMP_FIELDS: usize = ICMP_HEADER_LEN;

/// Read the datagram an ICMP error quotes.
///
/// `reporter_target` is the destination address of the error message itself — the
/// party being told — and the quoted datagram must have been travelling away from
/// it. `quoted` is the bytes behind the error's own eight-byte header.
///
/// Every read is a pattern match on a fixed-size chunk rather than an index, and
/// every length is checked before it is used, because none of these bytes is
/// anything but a sender's choosing.
///
/// # Errors
/// [`QuotedError`], naming the claim that did not hold.
pub(crate) fn quoted(reporter_target: Ipv4Address, quoted: &[u8]) -> Result<Quoted, QuotedError> {
    let Some((header, behind)) = quoted.split_first_chunk::<IPV4_HEADER_LEN>() else {
        return Err(QuotedError::Truncated {
            needed: IPV4_HEADER_LEN,
            got: quoted.len(),
        });
    };
    let [
        version_and_length,
        _service,
        _total_high,
        _total_low,
        _id_high,
        _id_low,
        flags_and_offset_high,
        offset_low,
        _ttl,
        protocol,
        _checksum_high,
        _checksum_low,
        source0,
        source1,
        source2,
        source3,
        destination0,
        destination1,
        destination2,
        destination3,
    ] = *header;

    let version = version_and_length >> 4;
    if version != 4 {
        return Err(QuotedError::NotIpv4 { version });
    }
    let header_words = version_and_length & 0x0f;
    // Five words is a header with no options. The upper bound is what was quoted,
    // not what the datagram claimed: an error carries a prefix of the original, so
    // its own total length says nothing about how much is here.
    let header_len = usize::from(header_words) * 4;
    if header_words < 5 || header_len > quoted.len() {
        return Err(QuotedError::HeaderLengthInvalid { header_words });
    }
    let fragment_offset = u16::from_be_bytes([flags_and_offset_high & 0x1f, offset_low]);
    if fragment_offset != 0 {
        return Err(QuotedError::Fragmented { fragment_offset });
    }
    let source = Ipv4Address::from_octets([source0, source1, source2, source3]);
    if source != reporter_target {
        return Err(QuotedError::NotFromTheReporter {
            quoted_source: source,
        });
    }
    let destination =
        Ipv4Address::from_octets([destination0, destination1, destination2, destination3]);
    let protocol = Protocol(protocol);

    // Options between the fixed header and the transport are skipped by the length
    // the header itself declared, which the bound above already held to what was
    // quoted.
    let transport = behind
        .get(header_len.saturating_sub(IPV4_HEADER_LEN)..)
        .unwrap_or_default();
    match protocol {
        Protocol::TCP => {
            let Some((fields, _)) = transport.split_first_chunk::<TCP_FIELDS>() else {
                return Err(QuotedError::Truncated {
                    needed: header_len.saturating_add(TCP_FIELDS),
                    got: quoted.len(),
                });
            };

            let [
                source_high,
                source_low,
                destination_high,
                destination_low,
                sequence0,
                sequence1,
                sequence2,
                sequence3,
            ] = *fields;
            Ok(Quoted {
                source,
                destination,
                protocol,
                source_port: u16::from_be_bytes([source_high, source_low]),
                destination_port: u16::from_be_bytes([destination_high, destination_low]),
                sequence: Some(SeqNumber::new(u32::from_be_bytes([
                    sequence0, sequence1, sequence2, sequence3,
                ]))),
            })
        }
        Protocol::UDP => {
            let Some((fields, _)) = transport.split_first_chunk::<UDP_FIELDS>() else {
                return Err(QuotedError::Truncated {
                    needed: header_len.saturating_add(UDP_FIELDS),
                    got: quoted.len(),
                });
            };
            let [source_high, source_low, destination_high, destination_low] = *fields;
            Ok(Quoted {
                source,
                destination,
                protocol,
                source_port: u16::from_be_bytes([source_high, source_low]),
                destination_port: u16::from_be_bytes([destination_high, destination_low]),
                sequence: None,
            })
        }
        // An echo's identifier stands where a port would, in both directions, so
        // the tuple is formed the same way as the other two.
        Protocol::ICMP => {
            let Some((fields, _)) = transport.split_first_chunk::<ICMP_FIELDS>() else {
                return Err(QuotedError::Truncated {
                    needed: header_len.saturating_add(ICMP_FIELDS),
                    got: quoted.len(),
                });
            };
            let [
                message_type,
                code,
                _,
                _,
                identifier_high,
                identifier_low,
                _,
                _,
            ] = *fields;
            let identifier = u16::from_be_bytes([identifier_high, identifier_low]);
            if !matches!(
                (message_type, code),
                (IcmpHeader::ECHO_REQUEST | IcmpHeader::ECHO_REPLY, ECHO_CODE)
            ) {
                return Err(QuotedError::NotAnEcho { message_type });
            }
            Ok(Quoted {
                source,
                destination,
                protocol,
                source_port: identifier,
                destination_port: identifier,
                sequence: None,
            })
        }
        other => Err(QuotedError::ProtocolUnsupported(other)),
    }
}

/// The bytes an error message quotes: everything behind its own header.
#[must_use]
pub(crate) fn quoted_bytes(message: &[u8]) -> &[u8] {
    message.get(ICMP_HEADER_LEN..).unwrap_or_default()
}

/// Guard against a protocol's field requirement outgrowing the header it is read
/// from. Evaluated at compile time, so it constrains what this module may ask for
/// rather than what a sender may send: a requirement past its own header would be
/// a field this module reads out of the next protocol's bytes.
const _: () = {
    assert!(TCP_FIELDS <= TCP_HEADER_LEN);
    assert!(UDP_FIELDS <= UDP_HEADER_LEN);
    assert!(ICMP_FIELDS <= ICMP_HEADER_LEN);
};

#[cfg(test)]
mod tests;
