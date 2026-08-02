//! Ethernet, IPv4, UDP, ARP and ICMP-echo header parsing, the four in-place
//! edits routing a frame requires, and the two replies an addressed endpoint
//! sends.
//!
//! Faces untrusted network traffic: every byte reaching
//! [`Frame::parse`] was put on the wire by whatever is attached to a dataplane
//! port. The ARP and ICMP halves additionally face the management-plane
//! attacker, reached through `lfw_ip_endpoint`, which is what puts them on a
//! path where a reply is composed rather than a verdict reached. Nothing here
//! panics, indexes past a bound, or truncates a value into a meaning it did not
//! have; a header that is not exactly what it claims is a typed error the caller
//! must handle.
//!
//! # Why the parser hands back fixed-size arrays
//!
//! Splitting the frame into `&mut [u8; N]` chunks up front is what removes the
//! bounds check from every later access: once [`Frame::parse`] has returned, the
//! only indices in play are compile-time constants into arrays of known length,
//! so no accessor and no edit has a panicking path to begin with. The length
//! rejections all happen once, in `parse`, where they are real checks against a
//! real adversary rather than unreachable branches.
//!
//! # Deliberate narrowness, and what it costs
//!
//! * **IPv4 options are refused, not skipped.** `IHL != 5` is a
//!   [`ParseError::Ipv4OptionsUnsupported`]. Options carry source routing and
//!   record-route, both of which redirect a packet around the topology a
//!   routing decision was made against; refusing the packet is the conservative
//!   reading, and it is what keeps the header a fixed 20 bytes.
//! * **A VLAN tag is parsed but never stripped.** It is surfaced on
//!   [`Frame::vlan`] so a caller decides for itself; this crate holds no
//!   sub-interface model and so cannot know which tag is legitimate.
//! * **Only the first fragment carries a transport header.** A non-initial
//!   fragment reports [`Transport::NonInitialFragment`] rather than reading
//!   payload bytes as though they were a UDP header.
//! * **IPv6 is absent**: of the two L3 protocols the design names, only
//!   IPv4 is handled.
//! * **ARP is IPv4-over-Ethernet or nothing.** Any other hardware type,
//!   protocol type or address length is an [`ArpError`] rather than a packet
//!   with fields nobody checked, and the only operations that decode are request
//!   and reply.
//! * **ICMP is echo or nothing.** [`IcmpEcho::parse_request`] is the whole of
//!   what this crate reads of ICMP; every other type and code is refused, so no
//!   error message, redirect or timestamp is parsed here.
//! * **TCP is not parsed here.** A segment's header is inseparable from the state
//!   machine that judges it, so `lfw_tcp` owns that parser and reaches this crate's
//!   arithmetic through [`Checksum`]; [`Ipv4Frame`] is the datagram around one.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// Destination and source MAC: the part of an Ethernet header a router
/// rewrites, and the whole of what [`Frame`] keeps mutable at L2.
pub const MAC_PAIR_LEN: usize = 12;

/// `MAC_PAIR_LEN` plus the EtherType.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// An 802.1Q tag: the TPID that replaced the EtherType, plus the TCI.
pub const VLAN_TAG_LEN: usize = 4;

/// Fixed, because [`ParseError::Ipv4OptionsUnsupported`] refuses every other
/// `IHL`; see the crate header.
pub const IPV4_HEADER_LEN: usize = 20;

/// Bits an IPv4 address has, and so the longest prefix one can name. `wire`
/// states the same bound for the handover ABI without depending on this crate;
/// `config` const-asserts the two equal, so the pair cannot drift.
pub const MAX_PREFIX_LENGTH: u8 = 32;

pub const UDP_HEADER_LEN: usize = 8;

/// The smallest frame that can carry anything this crate parses.
pub const MIN_ROUTABLE_FRAME_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;

/// An ARP packet for IPv4 over Ethernet, which is the only shape
/// [`ArpPacket::parse`] admits.
pub const ARP_PAYLOAD_LEN: usize = 28;

/// The whole of an ARP frame, and so the whole of an ARP reply.
pub const ARP_FRAME_LEN: usize = ETHERNET_HEADER_LEN + ARP_PAYLOAD_LEN;

/// Type, code, checksum, identifier, sequence.
pub const ICMP_ECHO_HEADER_LEN: usize = 8;

/// The frame an [`EchoReply`] with no payload occupies.
pub const MIN_ECHO_REPLY_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + ICMP_ECHO_HEADER_LEN;

const ARP_HARDWARE_ETHERNET: u16 = 1;
const ARP_HARDWARE_LEN: u8 = 6;
const ARP_PROTOCOL_LEN: u8 = 4;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

const ICMP_ECHO_REQUEST_TYPE: u8 = 8;
const ICMP_ECHO_REPLY_TYPE: u8 = 0;
const ICMP_ECHO_CODE: u8 = 0;

/// Where a checksum field sits inside the block it covers, and so the two bytes
/// summed as zero when one is recomputed (RFC 1071).
const IPV4_CHECKSUM_AT: usize = 10;
const ICMP_CHECKSUM_AT: usize = 2;

/// The network mask for a prefix length, saturating rather than rejecting: a
/// length above 32 is a host route and 0 matches everything, so every `u8` maps
/// to a mask and no invalid configuration is representable.
#[must_use]
pub const fn prefix_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else if prefix_length >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_length)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// The group bit (IEEE 802.3 3.2.3): set on broadcast and multicast alike.
    #[must_use]
    pub const fn is_group(self) -> bool {
        let Self([first, ..]) = self;
        first & 0x01 != 0
    }

    #[must_use]
    pub const fn is_broadcast(self) -> bool {
        matches!(self, Self([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))
    }

    /// An address that names exactly one station: a source a frame may be
    /// answered to, and a destination the appliance may claim as its own.
    #[must_use]
    pub const fn is_unicast(self) -> bool {
        !self.is_group() && !matches!(self, Self([0, 0, 0, 0, 0, 0]))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self([a, b, c, d, e, g]) = *self;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// An IPv4 address held as the host-order integer, because every use here is a
/// prefix comparison rather than a byte-wise one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Address(u32);

impl Ipv4Address {
    #[must_use]
    pub const fn from_octets(octets: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(octets))
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// 224.0.0.0/4, which a unicast routing decision must never be made for.
    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0 & 0xf000_0000 == 0xe000_0000
    }

    /// 255.255.255.255, the limited broadcast address.
    #[must_use]
    pub const fn is_broadcast(self) -> bool {
        self.0 == u32::MAX
    }

    /// 127.0.0.0/8, which must not appear on a wire.
    #[must_use]
    pub const fn is_loopback(self) -> bool {
        self.0 & 0xff00_0000 == 0x7f00_0000
    }

    #[must_use]
    pub const fn is_unspecified(self) -> bool {
        self.0 == 0
    }

    /// An address a host may hold and a packet may be answered to: neither
    /// multicast, broadcast, loopback nor unspecified.
    #[must_use]
    pub const fn is_unicast(self) -> bool {
        !(self.is_multicast() || self.is_broadcast() || self.is_loopback() || self.is_unspecified())
    }

    /// Whether `self` and `other` share their first `prefix_length` bits.
    #[must_use]
    pub const fn shares_prefix(self, other: Self, prefix_length: u8) -> bool {
        let mask = prefix_mask(prefix_length);
        self.0 & mask == other.0 & mask
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);
    pub const VLAN: Self = Self(0x8100);
    pub const IPV6: Self = Self(0x86dd);
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

/// An IANA IP protocol number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Protocol(pub u8);

impl Protocol {
    pub const ICMP: Self = Self(1);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The 802.1Q Tag Control Information, split into its three fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VlanTag {
    /// Priority Code Point, 0..=7.
    pub priority: u8,
    /// Drop Eligible Indicator.
    pub drop_eligible: bool,
    /// VLAN Identifier, 0..=4095.
    pub id: u16,
}

impl VlanTag {
    const fn from_tci(tci: u16) -> Self {
        Self {
            // Lossless: the shift leaves three bits.
            priority: (tci >> 13) as u8,
            drop_eligible: tci & 0x1000 != 0,
            id: tci & 0x0fff,
        }
    }
}

/// The IPv4 header as values, snapshotted from the frame at the moment of the
/// call. Returned by [`Frame::ipv4`] rather than cached in [`Frame`], so an edit
/// cannot leave a reader holding a header that no longer describes the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// In units of 8 bytes, as it is on the wire.
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub checksum: u16,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
}

impl Ipv4Header {
    /// Whether this packet is one piece of a fragmented datagram — either not
    /// the first piece, or a first piece with more to follow.
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    /// Header plus payload, as it is on the wire; at least [`UDP_HEADER_LEN`].
    pub length: u16,
    pub checksum: u16,
}

/// What sits behind the IPv4 header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp(UdpHeader),
    /// A fragment carrying no transport header at its offset, so none was read.
    NonInitialFragment,
    /// A protocol this crate does not parse. Carried rather than rejected: a
    /// router forwards it, and only a filtering decision needs it broken down.
    Unparsed(Protocol),
}

/// The Ethernet header as values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    pub destination: MacAddress,
    pub source: MacAddress,
    /// As it appears on the wire, so a VLAN TPID reaches the caller as itself:
    /// this crate holds no sub-interface model and cannot decide which tag is
    /// legitimate.
    pub ether_type: EtherType,
}

/// An Ethernet frame split at its header, for a caller that dispatches on the
/// EtherType rather than assuming IPv4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ethernet<'a> {
    pub header: EthernetHeader,
    pub payload: &'a [u8],
}

impl<'a> Ethernet<'a> {
    /// # Errors
    /// [`ParseError::FrameTooShort`] for fewer bytes than an Ethernet header.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let Some((header, payload)) = bytes.split_first_chunk::<ETHERNET_HEADER_LEN>() else {
            return Err(ParseError::FrameTooShort {
                needed: ETHERNET_HEADER_LEN,
                got: bytes.len(),
            });
        };
        let [
            d0,
            d1,
            d2,
            d3,
            d4,
            d5,
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            type_high,
            type_low,
        ] = *header;
        Ok(Self {
            header: EthernetHeader {
                destination: MacAddress([d0, d1, d2, d3, d4, d5]),
                source: MacAddress([s0, s1, s2, s3, s4, s5]),
                ether_type: EtherType(u16::from_be_bytes([type_high, type_low])),
            },
            payload,
        })
    }
}

/// A read-only IPv4 packet: the header as values, and exactly the payload its
/// own total length claims.
///
/// The counterpart of [`Frame`], which borrows mutably because it exists to
/// rewrite. An endpoint answering for itself alters nothing it received, so it
/// takes this and composes a new frame instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    header: Ipv4Header,
    payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// # Errors
    /// [`ParseError`], on the same terms as [`Frame::parse`] and through the
    /// same checks: no length, version, option or checksum rule differs between
    /// the two.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let available = bytes.len();
        let Some((raw, rest)) = bytes.split_first_chunk::<IPV4_HEADER_LEN>() else {
            return Err(ParseError::FrameTooShort {
                needed: IPV4_HEADER_LEN,
                got: available,
            });
        };
        let (header, payload_len) = validate_ipv4(raw, rest.len(), available)?;
        let Some(payload) = rest.get(..payload_len) else {
            return Err(ParseError::Ipv4TotalLengthExceedsFrame {
                total_length: header.total_length,
                available,
            });
        };
        Ok(Self { header, payload })
    }

    #[must_use]
    pub const fn header(&self) -> Ipv4Header {
        self.header
    }

    /// Everything the datagram's own total length covers, and nothing of the
    /// Ethernet padding behind it.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Which of the two operations this crate decodes an ARP packet carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

/// An ARP packet for IPv4 over Ethernet, every field decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_address: Ipv4Address,
    pub target_mac: MacAddress,
    pub target_address: Ipv4Address,
}

/// Why an ARP payload is not one this crate reads. Every variant carries the
/// value that refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpError {
    PayloadTooShort {
        got: usize,
    },
    /// Anything but Ethernet (1).
    HardwareTypeUnsupported {
        hardware_type: u16,
    },
    /// Anything but IPv4.
    ProtocolTypeUnsupported {
        protocol_type: EtherType,
    },
    /// Lengths that contradict the pair of types above, which would make every
    /// field offset behind them a different one.
    AddressLengthsUnsupported {
        hardware_len: u8,
        protocol_len: u8,
    },
    /// Neither request (1) nor reply (2).
    OperationUnsupported {
        operation: u16,
    },
}

impl ArpPacket {
    /// Parse the payload behind an ARP EtherType.
    ///
    /// Bytes past [`ARP_PAYLOAD_LEN`] are Ethernet padding to the 60-byte
    /// minimum and are neither read nor refused.
    ///
    /// # Errors
    /// [`ArpError`], for a packet this crate will not interpret.
    pub fn parse(payload: &[u8]) -> Result<Self, ArpError> {
        let Some((fixed, _padding)) = payload.split_first_chunk::<ARP_PAYLOAD_LEN>() else {
            return Err(ArpError::PayloadTooShort { got: payload.len() });
        };
        let [
            ht_high,
            ht_low,
            pt_high,
            pt_low,
            hardware_len,
            protocol_len,
            op_high,
            op_low,
            sha0,
            sha1,
            sha2,
            sha3,
            sha4,
            sha5,
            spa0,
            spa1,
            spa2,
            spa3,
            tha0,
            tha1,
            tha2,
            tha3,
            tha4,
            tha5,
            tpa0,
            tpa1,
            tpa2,
            tpa3,
        ] = *fixed;

        let hardware_type = u16::from_be_bytes([ht_high, ht_low]);
        if hardware_type != ARP_HARDWARE_ETHERNET {
            return Err(ArpError::HardwareTypeUnsupported { hardware_type });
        }
        let protocol_type = EtherType(u16::from_be_bytes([pt_high, pt_low]));
        if protocol_type != EtherType::IPV4 {
            return Err(ArpError::ProtocolTypeUnsupported { protocol_type });
        }
        if hardware_len != ARP_HARDWARE_LEN || protocol_len != ARP_PROTOCOL_LEN {
            return Err(ArpError::AddressLengthsUnsupported {
                hardware_len,
                protocol_len,
            });
        }
        let operation = match u16::from_be_bytes([op_high, op_low]) {
            ARP_REQUEST => ArpOperation::Request,
            ARP_REPLY => ArpOperation::Reply,
            operation => return Err(ArpError::OperationUnsupported { operation }),
        };

        Ok(Self {
            operation,
            sender_mac: MacAddress([sha0, sha1, sha2, sha3, sha4, sha5]),
            sender_address: Ipv4Address::from_octets([spa0, spa1, spa2, spa3]),
            target_mac: MacAddress([tha0, tha1, tha2, tha3, tha4, tha5]),
            target_address: Ipv4Address::from_octets([tpa0, tpa1, tpa2, tpa3]),
        })
    }
}

/// An ICMP echo, as the message this crate reads and the one it writes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpEcho<'a> {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

/// Why an ICMP message is not an echo request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpError {
    HeaderTruncated { got: usize },
    NotAnEchoRequest { message_type: u8, code: u8 },
    ChecksumInvalid { found: u16, computed: u16 },
}

impl<'a> IcmpEcho<'a> {
    /// Read an ICMP message as an echo request, verifying its checksum over the
    /// whole message.
    ///
    /// # Errors
    /// [`IcmpError`]. The message is identified before its checksum is
    /// verified, so a corrupt error message is refused as the wrong type rather
    /// than as a bad sum.
    pub fn parse_request(message: &'a [u8]) -> Result<Self, IcmpError> {
        let Some((header, payload)) = message.split_first_chunk::<ICMP_ECHO_HEADER_LEN>() else {
            return Err(IcmpError::HeaderTruncated { got: message.len() });
        };
        let [
            message_type,
            code,
            ck_high,
            ck_low,
            id_high,
            id_low,
            seq_high,
            seq_low,
        ] = *header;
        if message_type != ICMP_ECHO_REQUEST_TYPE || code != ICMP_ECHO_CODE {
            return Err(IcmpError::NotAnEchoRequest { message_type, code });
        }
        if fold(accumulate(0, message)) != u16::MAX {
            return Err(IcmpError::ChecksumInvalid {
                found: u16::from_be_bytes([ck_high, ck_low]),
                computed: checksum_over(message, ICMP_CHECKSUM_AT),
            });
        }
        Ok(Self {
            identifier: u16::from_be_bytes([id_high, id_low]),
            sequence: u16::from_be_bytes([seq_high, seq_low]),
            payload,
        })
    }
}

/// Why a reply could not be written. Both variants are about the *caller's*
/// storage or a value it composed, never about the packet that prompted the
/// reply — a malformed request is refused before a reply is attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    DoesNotFit {
        needed: usize,
        capacity: usize,
    },
    /// An echo whose payload no IPv4 total length can name.
    PayloadTooLong {
        len: usize,
    },
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoesNotFit { needed, capacity } => {
                write!(f, "a {needed}-byte reply does not fit {capacity} bytes")
            }
            Self::PayloadTooLong { len } => {
                write!(f, "a {len}-byte echo payload exceeds an IPv4 datagram")
            }
        }
    }
}

/// The ARP reply an addressed endpoint answers a request with: our own pair at
/// both layers, and the requester's as the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpReply {
    pub mac: MacAddress,
    pub address: Ipv4Address,
    pub target_mac: MacAddress,
    pub target_address: Ipv4Address,
}

impl ArpReply {
    /// Write this reply into `out`, returning its length on the wire.
    ///
    /// # Errors
    /// [`ReplyError::DoesNotFit`] for storage shorter than [`ARP_FRAME_LEN`].
    /// Nothing is written.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, ReplyError> {
        let Some(frame) = out.first_chunk_mut::<ARP_FRAME_LEN>() else {
            return Err(ReplyError::DoesNotFit {
                needed: ARP_FRAME_LEN,
                capacity: out.len(),
            });
        };
        let MacAddress([d0, d1, d2, d3, d4, d5]) = self.target_mac;
        let MacAddress([s0, s1, s2, s3, s4, s5]) = self.mac;
        let [ether_high, ether_low] = EtherType::ARP.0.to_be_bytes();
        let [protocol_high, protocol_low] = EtherType::IPV4.0.to_be_bytes();
        let [hardware_high, hardware_low] = ARP_HARDWARE_ETHERNET.to_be_bytes();
        let [op_high, op_low] = ARP_REPLY.to_be_bytes();
        let [a0, a1, a2, a3] = self.address.octets();
        let [t0, t1, t2, t3] = self.target_address.octets();
        *frame = [
            d0,
            d1,
            d2,
            d3,
            d4,
            d5,
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            ether_high,
            ether_low,
            hardware_high,
            hardware_low,
            protocol_high,
            protocol_low,
            ARP_HARDWARE_LEN,
            ARP_PROTOCOL_LEN,
            op_high,
            op_low,
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            a0,
            a1,
            a2,
            a3,
            d0,
            d1,
            d2,
            d3,
            d4,
            d5,
            t0,
            t1,
            t2,
            t3,
        ];
        Ok(ARP_FRAME_LEN)
    }
}

/// A running RFC 1071 ones' complement sum, for a transport whose checksum spans
/// more than one block — the TCP pseudo-header, nowhere in memory, followed by the
/// segment. One implementation serves the workspace: two that disagreed would
/// produce a stack that talks to nobody. Continuation is exact only across an even
/// boundary, a property of the sum rather than a rule this type enforces:
/// [`add_bytes`](Self::add_bytes) pads an odd-length piece with a zero byte, so such
/// a piece must be the last.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Checksum(u32);

impl Checksum {
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Add a block of bytes; see the type's note on odd lengths. Not named `add`,
    /// because `Add` is a trait this type must not implement.
    #[must_use]
    pub fn add_bytes(self, bytes: &[u8]) -> Self {
        Self(accumulate(self.0, bytes))
    }

    #[must_use]
    pub const fn add_u16(self, value: u16) -> Self {
        Self(self.0.saturating_add(value as u32))
    }

    #[must_use]
    pub const fn add_address(self, address: Ipv4Address) -> Self {
        let bits = address.bits();
        // Lossless: each shift-and-mask leaves 16 bits.
        self.add_u16((bits >> 16) as u16)
            .add_u16((bits & 0xffff) as u16)
    }

    /// The value the checksum field should carry.
    #[must_use]
    pub const fn finish(self) -> u16 {
        !fold(self.0)
    }

    #[must_use]
    pub const fn is_consistent(self) -> bool {
        fold(self.0) == u16::MAX
    }
}

/// The Ethernet and IPv4 headers of a datagram this appliance originates, stamped
/// in front of a transport payload already written at [`Ipv4Frame::PAYLOAD_AT`].
///
/// The order is why this exists rather than a `write` taking a payload slice: a TCP
/// segment's checksum covers its payload, so the segment must be complete before
/// the datagram can be sized — and writing it in place is what lets it be written
/// exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Frame {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub protocol: Protocol,
}

impl Ipv4Frame {
    /// Where the transport payload sits, and so where a caller composes it.
    pub const PAYLOAD_AT: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;

    /// The TTL such a datagram leaves with; see [`EchoReply::TTL`].
    pub const TTL: u8 = 64;

    /// Stamp the two headers in front of `payload_len` bytes already at
    /// [`PAYLOAD_AT`](Self::PAYLOAD_AT), returning the frame's length on the wire.
    ///
    /// # Errors
    /// [`ReplyError`], for storage too small or a payload no IPv4 total length can
    /// name; nothing is written on either, so the payload survives a refusal.
    pub fn write(&self, out: &mut [u8], payload_len: usize) -> Result<usize, ReplyError> {
        let Some(total_length) = IPV4_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|total| u16::try_from(total).ok())
        else {
            return Err(ReplyError::PayloadTooLong { len: payload_len });
        };
        let needed = ETHERNET_HEADER_LEN + usize::from(total_length);
        if out.len() < needed {
            return Err(ReplyError::DoesNotFit {
                needed,
                capacity: out.len(),
            });
        }
        let Some(head) = out.first_chunk_mut::<{ Self::PAYLOAD_AT }>() else {
            return Err(ReplyError::DoesNotFit {
                needed,
                capacity: out.len(),
            });
        };

        let MacAddress([d0, d1, d2, d3, d4, d5]) = self.destination_mac;
        let MacAddress([s0, s1, s2, s3, s4, s5]) = self.source_mac;
        let [ether_high, ether_low] = EtherType::IPV4.0.to_be_bytes();
        let [len_high, len_low] = total_length.to_be_bytes();
        let [src0, src1, src2, src3] = self.source.octets();
        let [dst0, dst1, dst2, dst3] = self.destination.octets();

        let mut ipv4 = [
            0x45,
            0,
            len_high,
            len_low,
            0,
            0,
            0,
            0,
            Self::TTL,
            self.protocol.0,
            0,
            0,
            src0,
            src1,
            src2,
            src3,
            dst0,
            dst1,
            dst2,
            dst3,
        ];
        let [ck_high, ck_low] = checksum_over(&ipv4, IPV4_CHECKSUM_AT).to_be_bytes();
        ipv4[IPV4_CHECKSUM_AT] = ck_high;
        ipv4[IPV4_CHECKSUM_AT + 1] = ck_low;

        let [
            i0,
            i1,
            i2,
            i3,
            i4,
            i5,
            i6,
            i7,
            i8,
            i9,
            i10,
            i11,
            i12,
            i13,
            i14,
            i15,
            i16,
            i17,
            i18,
            i19,
        ] = ipv4;
        *head = [
            d0, d1, d2, d3, d4, d5, s0, s1, s2, s3, s4, s5, ether_high, ether_low, i0, i1, i2, i3,
            i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15, i16, i17, i18, i19,
        ];
        Ok(needed)
    }
}

/// The ICMP echo reply an addressed endpoint answers a request with.
///
/// The echo is carried whole rather than field by field, because identifier,
/// sequence and payload must all come back unaltered for the sender to match the
/// reply to its request (RFC 792).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoReply<'a> {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub echo: IcmpEcho<'a>,
}

impl EchoReply<'_> {
    /// The TTL a reply leaves with. A fresh value rather than the request's:
    /// what remained of the request's TTL is a property of the path it took,
    /// and the reply's path is not that one.
    pub const TTL: u8 = 64;

    /// Write this reply into `out`, returning its length on the wire.
    ///
    /// # Errors
    /// [`ReplyError`], for storage that cannot hold the frame or an echo payload
    /// no datagram can name. Bytes of `out` may have been written on the
    /// [`ReplyError::DoesNotFit`] path only up to the length that did fit, which
    /// the caller discards along with the outcome.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, ReplyError> {
        let payload = self.echo.payload;
        let Some(total_length) = (IPV4_HEADER_LEN + ICMP_ECHO_HEADER_LEN)
            .checked_add(payload.len())
            .and_then(|total| u16::try_from(total).ok())
        else {
            return Err(ReplyError::PayloadTooLong { len: payload.len() });
        };
        let needed = ETHERNET_HEADER_LEN + usize::from(total_length);
        let Some(frame) = out.get_mut(..needed) else {
            return Err(ReplyError::DoesNotFit {
                needed,
                capacity: out.len(),
            });
        };
        let Some((head, tail)) = frame.split_first_chunk_mut::<MIN_ECHO_REPLY_LEN>() else {
            return Err(ReplyError::DoesNotFit {
                needed,
                capacity: out.len(),
            });
        };

        let MacAddress([d0, d1, d2, d3, d4, d5]) = self.destination_mac;
        let MacAddress([s0, s1, s2, s3, s4, s5]) = self.source_mac;
        let [ether_high, ether_low] = EtherType::IPV4.0.to_be_bytes();
        let [len_high, len_low] = total_length.to_be_bytes();
        let [src0, src1, src2, src3] = self.source.octets();
        let [dst0, dst1, dst2, dst3] = self.destination.octets();
        let [id_high, id_low] = self.echo.identifier.to_be_bytes();
        let [seq_high, seq_low] = self.echo.sequence.to_be_bytes();

        let mut ipv4 = [
            0x45,
            0,
            len_high,
            len_low,
            0,
            0,
            0,
            0,
            Self::TTL,
            Protocol::ICMP.0,
            0,
            0,
            src0,
            src1,
            src2,
            src3,
            dst0,
            dst1,
            dst2,
            dst3,
        ];
        let [ipv4_ck_high, ipv4_ck_low] = checksum_over(&ipv4, IPV4_CHECKSUM_AT).to_be_bytes();
        ipv4[IPV4_CHECKSUM_AT] = ipv4_ck_high;
        ipv4[IPV4_CHECKSUM_AT + 1] = ipv4_ck_low;

        let mut icmp = [
            ICMP_ECHO_REPLY_TYPE,
            ICMP_ECHO_CODE,
            0,
            0,
            id_high,
            id_low,
            seq_high,
            seq_low,
        ];
        // The sum spans header and payload, and the header's length is even, so
        // the payload continues the same byte pairing.
        let [icmp_ck_high, icmp_ck_low] =
            (!fold(accumulate(accumulate(0, &icmp), payload))).to_be_bytes();
        icmp[ICMP_CHECKSUM_AT] = icmp_ck_high;
        icmp[ICMP_CHECKSUM_AT + 1] = icmp_ck_low;

        let [
            i0,
            i1,
            i2,
            i3,
            i4,
            i5,
            i6,
            i7,
            i8,
            i9,
            i10,
            i11,
            i12,
            i13,
            i14,
            i15,
            i16,
            i17,
            i18,
            i19,
        ] = ipv4;
        let [c0, c1, c2, c3, c4, c5, c6, c7] = icmp;
        *head = [
            d0, d1, d2, d3, d4, d5, s0, s1, s2, s3, s4, s5, ether_high, ether_low, i0, i1, i2, i3,
            i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15, i16, i17, i18, i19, c0, c1, c2,
            c3, c4, c5, c6, c7,
        ];
        for (slot, byte) in tail.iter_mut().zip(payload) {
            *slot = *byte;
        }
        Ok(needed)
    }
}

/// Why a frame is not a routable IPv4 packet. Every variant carries the values
/// that made it one, so a drop is attributable to a byte rather than to a
/// category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    FrameTooShort {
        needed: usize,
        got: usize,
    },
    /// Not IPv4, and not a VLAN tag wrapping one.
    UnsupportedEtherType(EtherType),
    /// Two or more stacked 802.1Q tags. One is modelled; QinQ is not.
    StackedVlanTags,
    Ipv4VersionNotFour(u8),
    /// `IHL != 5`; see the crate header for why options are refused.
    Ipv4OptionsUnsupported {
        ihl: u8,
    },
    /// The datagram claims to be shorter than its own header.
    Ipv4TotalLengthBelowHeader {
        total_length: u16,
    },
    /// The datagram claims more bytes than the frame carries. The converse —
    /// a frame longer than the datagram — is normal Ethernet padding and is
    /// accepted.
    Ipv4TotalLengthExceedsFrame {
        total_length: u16,
        available: usize,
    },
    Ipv4ChecksumInvalid {
        found: u16,
        computed: u16,
    },
    /// The datagram claims UDP but leaves no room for a UDP header.
    UdpHeaderTruncated {
        available: usize,
    },
    /// A UDP length below its own header, which would make the payload length
    /// negative.
    UdpLengthBelowHeader {
        length: u16,
    },
    UdpLengthExceedsDatagram {
        length: u16,
        available: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { needed, got } => {
                write!(
                    f,
                    "frame of {got} bytes is shorter than the {needed} needed"
                )
            }
            Self::UnsupportedEtherType(ether_type) => {
                write!(f, "ethertype {ether_type} is not routed")
            }
            Self::StackedVlanTags => write!(f, "stacked 802.1Q tags are not parsed"),
            Self::Ipv4VersionNotFour(version) => write!(f, "IP version {version} is not 4"),
            Self::Ipv4OptionsUnsupported { ihl } => {
                write!(f, "IHL {ihl} carries options, which are refused")
            }
            Self::Ipv4TotalLengthBelowHeader { total_length } => write!(
                f,
                "total length {total_length} is below the {IPV4_HEADER_LEN}-byte header"
            ),
            Self::Ipv4TotalLengthExceedsFrame {
                total_length,
                available,
            } => write!(
                f,
                "total length {total_length} exceeds the {available} bytes the frame carries"
            ),
            Self::Ipv4ChecksumInvalid { found, computed } => write!(
                f,
                "header checksum 0x{found:04x} does not match the computed 0x{computed:04x}"
            ),
            Self::UdpHeaderTruncated { available } => write!(
                f,
                "{available} bytes leave no room for a {UDP_HEADER_LEN}-byte UDP header"
            ),
            Self::UdpLengthBelowHeader { length } => write!(
                f,
                "UDP length {length} is below the {UDP_HEADER_LEN}-byte header"
            ),
            Self::UdpLengthExceedsDatagram { length, available } => write!(
                f,
                "UDP length {length} exceeds the {available} bytes the datagram carries"
            ),
        }
    }
}

/// The packet's TTL will not survive another hop, so it may not be forwarded.
/// RFC 791 requires the datagram be discarded once the field reaches zero, and
/// a router must not emit a packet it has just decremented to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtlExpired {
    /// The value as received, before any decrement.
    pub ttl: u8,
}

impl fmt::Display for TtlExpired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TTL {} does not survive a hop", self.ttl)
    }
}

/// A parsed, rewritable view of one Ethernet frame carrying IPv4.
///
/// It borrows the frame mutably for its whole life, which is what makes an edit
/// to an unparsed frame — or a read of a header a later edit has invalidated —
/// unrepresentable rather than merely discouraged.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Destination then source MAC. The EtherType is deliberately outside this
    /// borrow: routing never rewrites it, and a tagged frame keeps it elsewhere.
    macs: &'a mut [u8; MAC_PAIR_LEN],
    ipv4: &'a mut [u8; IPV4_HEADER_LEN],
    vlan: Option<VlanTag>,
    transport: Transport,
}

impl<'a> Frame<'a> {
    /// Parse `bytes` as an Ethernet frame carrying IPv4, validating every length
    /// and the IPv4 header checksum before any of it is believed.
    ///
    /// # Errors
    /// [`ParseError`], with the values that made the frame unroutable. Nothing
    /// is modified on any error path.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let frame_len = bytes.len();
        let too_short = |needed: usize| ParseError::FrameTooShort {
            needed,
            got: frame_len,
        };

        let Some((macs, after_macs)) = bytes.split_first_chunk_mut::<MAC_PAIR_LEN>() else {
            return Err(too_short(MIN_ROUTABLE_FRAME_LEN));
        };
        let Some((ether_type, after_ether_type)) = after_macs.split_first_chunk_mut::<2>() else {
            return Err(too_short(MIN_ROUTABLE_FRAME_LEN));
        };

        let (ether_type, vlan, after_l2) = match EtherType(u16::from_be_bytes(*ether_type)) {
            EtherType::VLAN => {
                let Some((tag, rest)) = after_ether_type.split_first_chunk_mut::<VLAN_TAG_LEN>()
                else {
                    return Err(too_short(MIN_ROUTABLE_FRAME_LEN + VLAN_TAG_LEN));
                };
                let [tci_high, tci_low, inner_high, inner_low] = *tag;
                let inner = EtherType(u16::from_be_bytes([inner_high, inner_low]));
                if inner == EtherType::VLAN {
                    return Err(ParseError::StackedVlanTags);
                }
                (
                    inner,
                    Some(VlanTag::from_tci(u16::from_be_bytes([tci_high, tci_low]))),
                    rest,
                )
            }
            plain => (plain, None, after_ether_type),
        };

        if ether_type != EtherType::IPV4 {
            return Err(ParseError::UnsupportedEtherType(ether_type));
        }

        let available_for_ip = after_l2.len();
        let Some((ipv4, payload)) = after_l2.split_first_chunk_mut::<IPV4_HEADER_LEN>() else {
            return Err(too_short(frame_len + (IPV4_HEADER_LEN - available_for_ip)));
        };

        let (header, datagram_payload_len) = validate_ipv4(ipv4, payload.len(), available_for_ip)?;
        // Everything past `total_length` is padding the sender's L3 disclaims,
        // so no transport field may be read from it.
        let Some(datagram_payload) = payload.get(..datagram_payload_len) else {
            return Err(ParseError::Ipv4TotalLengthExceedsFrame {
                total_length: header.total_length,
                available: available_for_ip,
            });
        };

        let transport = parse_transport(&header, datagram_payload)?;

        Ok(Self {
            macs,
            ipv4,
            vlan,
            transport,
        })
    }

    #[must_use]
    pub fn destination_mac(&self) -> MacAddress {
        let [a, b, c, d, e, f, ..] = *self.macs;
        MacAddress([a, b, c, d, e, f])
    }

    #[must_use]
    pub fn source_mac(&self) -> MacAddress {
        let [.., a, b, c, d, e, f] = *self.macs;
        MacAddress([a, b, c, d, e, f])
    }

    /// The 802.1Q tag, if the frame carried one. It is never stripped; see the
    /// crate header.
    #[must_use]
    pub const fn vlan(&self) -> Option<VlanTag> {
        self.vlan
    }

    /// The IPv4 header as it stands now, re-read from the frame on every call.
    #[must_use]
    pub fn ipv4(&self) -> Ipv4Header {
        read_ipv4(self.ipv4)
    }

    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// Apply, as one step, every edit forwarding this packet to a next hop
    /// requires: both MAC addresses, the TTL decrement, and the header checksum
    /// the decrement invalidates.
    ///
    /// One call rather than four setters because three of the four are only
    /// ever correct together: a frame with rewritten MACs and an untouched TTL
    /// loops, and a decremented TTL under a stale checksum is discarded by the
    /// next hop. There is no way to perform a subset.
    ///
    /// # Errors
    /// [`TtlExpired`] if the packet cannot survive another hop. The frame is
    /// left byte-for-byte unmodified, so the caller may still count, discard, or
    /// report it against the header it arrived with.
    pub fn rewrite_for_forwarding(
        &mut self,
        source: MacAddress,
        destination: MacAddress,
    ) -> Result<(), TtlExpired> {
        let ttl = ttl_of(self.ipv4);
        let Some(next_ttl) = ttl.checked_sub(1).filter(|remaining| *remaining > 0) else {
            return Err(TtlExpired { ttl });
        };

        let MacAddress([d0, d1, d2, d3, d4, d5]) = destination;
        let MacAddress([s0, s1, s2, s3, s4, s5]) = source;
        *self.macs = [d0, d1, d2, d3, d4, d5, s0, s1, s2, s3, s4, s5];

        self.ipv4[8] = next_ttl;
        // Zeroed first because the field is part of its own input (RFC 1071).
        self.ipv4[10] = 0;
        self.ipv4[11] = 0;
        let [high, low] = recomputed_checksum(self.ipv4).to_be_bytes();
        self.ipv4[10] = high;
        self.ipv4[11] = low;
        Ok(())
    }
}

/// Every rule an IPv4 header is held to, and the payload length its total
/// length claims. One body, so [`Frame::parse`] and [`Ipv4Packet::parse`] cannot
/// come to disagree about what a valid header is.
///
/// `payload_available` is what follows the header in the frame and
/// `available_for_ip` the whole of what L2 handed over — the number a rejection
/// reports.
fn validate_ipv4(
    raw: &[u8; IPV4_HEADER_LEN],
    payload_available: usize,
    available_for_ip: usize,
) -> Result<(Ipv4Header, usize), ParseError> {
    let header = read_ipv4(raw);
    let version = version_of(raw);
    if version != 4 {
        return Err(ParseError::Ipv4VersionNotFour(version));
    }
    let ihl = ihl_of(raw);
    if ihl != 5 {
        return Err(ParseError::Ipv4OptionsUnsupported { ihl });
    }
    if header_checksum(raw) != 0 {
        return Err(ParseError::Ipv4ChecksumInvalid {
            found: header.checksum,
            computed: recomputed_checksum(raw),
        });
    }
    let total_length = usize::from(header.total_length);
    // `total_length` counts the header, so a value below it would make the
    // payload length negative.
    let Some(datagram_payload_len) = total_length.checked_sub(IPV4_HEADER_LEN) else {
        return Err(ParseError::Ipv4TotalLengthBelowHeader {
            total_length: header.total_length,
        });
    };
    // A frame LONGER than the datagram is ordinary Ethernet padding to the
    // 60-byte minimum, so only the shortfall is an error.
    if datagram_payload_len > payload_available {
        return Err(ParseError::Ipv4TotalLengthExceedsFrame {
            total_length: header.total_length,
            available: available_for_ip,
        });
    }
    Ok((header, datagram_payload_len))
}

fn parse_transport(header: &Ipv4Header, payload: &[u8]) -> Result<Transport, ParseError> {
    if header.fragment_offset != 0 {
        return Ok(Transport::NonInitialFragment);
    }
    if header.protocol != Protocol::UDP {
        return Ok(Transport::Unparsed(header.protocol));
    }
    let Some((udp, _)) = payload.split_first_chunk::<UDP_HEADER_LEN>() else {
        return Err(ParseError::UdpHeaderTruncated {
            available: payload.len(),
        });
    };
    let [
        sp_high,
        sp_low,
        dp_high,
        dp_low,
        len_high,
        len_low,
        ck_high,
        ck_low,
    ] = *udp;
    let length = u16::from_be_bytes([len_high, len_low]);
    let Some(udp_payload_len) = usize::from(length).checked_sub(UDP_HEADER_LEN) else {
        return Err(ParseError::UdpLengthBelowHeader { length });
    };
    // A fragmented first piece legitimately carries less than the UDP length
    // announces, the rest being in the following fragments.
    if !header.more_fragments && udp_payload_len > payload.len() - UDP_HEADER_LEN {
        return Err(ParseError::UdpLengthExceedsDatagram {
            length,
            available: payload.len(),
        });
    }
    Ok(Transport::Udp(UdpHeader {
        source_port: u16::from_be_bytes([sp_high, sp_low]),
        destination_port: u16::from_be_bytes([dp_high, dp_low]),
        length,
        checksum: u16::from_be_bytes([ck_high, ck_low]),
    }))
}

const fn version_of(header: &[u8; IPV4_HEADER_LEN]) -> u8 {
    header[0] >> 4
}

const fn ihl_of(header: &[u8; IPV4_HEADER_LEN]) -> u8 {
    header[0] & 0x0f
}

const fn ttl_of(header: &[u8; IPV4_HEADER_LEN]) -> u8 {
    header[8]
}

fn read_ipv4(header: &[u8; IPV4_HEADER_LEN]) -> Ipv4Header {
    let [
        _version_ihl,
        _dscp_ecn,
        tl_high,
        tl_low,
        id_high,
        id_low,
        flags_high,
        flags_low,
        ttl,
        protocol,
        ck_high,
        ck_low,
        s0,
        s1,
        s2,
        s3,
        d0,
        d1,
        d2,
        d3,
    ] = *header;
    let flags_fragment = u16::from_be_bytes([flags_high, flags_low]);
    Ipv4Header {
        total_length: u16::from_be_bytes([tl_high, tl_low]),
        identification: u16::from_be_bytes([id_high, id_low]),
        dont_fragment: flags_fragment & 0x4000 != 0,
        more_fragments: flags_fragment & 0x2000 != 0,
        fragment_offset: flags_fragment & 0x1fff,
        ttl,
        protocol: Protocol(protocol),
        checksum: u16::from_be_bytes([ck_high, ck_low]),
        source: Ipv4Address::from_octets([s0, s1, s2, s3]),
        destination: Ipv4Address::from_octets([d0, d1, d2, d3]),
    }
}

/// Add `bytes` to a running RFC 1071 ones' complement sum.
///
/// Byte-pair driven rather than index driven so an odd-length input is the
/// documented "pad with a zero byte" case instead of a bounds question. Callers
/// that continue a sum across two pieces therefore split on an even boundary or
/// the pairing shifts. Saturating rather than wrapping: the length is
/// attacker-controlled, and a `u32` holds a folded sum plus every pair of a
/// 64 KiB datagram with orders of magnitude to spare, so the bound is
/// unreachable rather than lossy.
fn accumulate(sum: u32, bytes: &[u8]) -> u32 {
    let mut sum = sum;
    let mut octets = bytes.iter().copied();
    loop {
        let pair = match (octets.next(), octets.next()) {
            (Some(high), Some(low)) => [high, low],
            (Some(high), None) => [high, 0],
            _ => break,
        };
        sum = sum.saturating_add(u32::from(u16::from_be_bytes(pair)));
    }
    sum
}

/// Fold a running sum to the 16 bits a checksum field carries.
const fn fold(sum: u32) -> u16 {
    // `u16::MAX as u32` rather than `u32::from`: `From` is not a const trait on
    // the pinned toolchain, and the widening of a literal maximum is exact.
    const HALF: u32 = u16::MAX as u32;
    let mut sum = sum;
    while sum > HALF {
        sum = (sum & HALF) + (sum >> 16);
    }
    // Lossless: the fold above leaves at most 16 significant bits.
    sum as u16
}

/// What the two-byte checksum field at `field` should hold, whatever it holds
/// now: the field is part of its own input, so it is summed as zero.
fn checksum_over(bytes: &[u8], field: usize) -> u16 {
    let before = bytes.get(..field).unwrap_or_default();
    let after = bytes.get(field + 2..).unwrap_or_default();
    !fold(accumulate(accumulate(0, before), after))
}

/// Zero exactly when the header's own checksum field is consistent with the
/// rest of it.
fn header_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    !fold(accumulate(0, header))
}

/// What the header's checksum field should hold, ignoring what it currently
/// holds.
fn recomputed_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    checksum_over(header, IPV4_CHECKSUM_AT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;

    /// A well-formed UDP-over-IPv4 frame, as the harness endpoints build one.
    fn udp_frame(ttl: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());

        let total_length = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_length.to_be_bytes());
        ip[8] = ttl;
        ip[9] = Protocol::UDP.0;
        ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
        ip[16..20].copy_from_slice(&[10, 0, 1, 2]);
        let checksum = recomputed_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);

        let udp_length = (UDP_HEADER_LEN + payload.len()) as u16;
        frame.extend_from_slice(&4444u16.to_be_bytes());
        frame.extend_from_slice(&5000u16.to_be_bytes());
        frame.extend_from_slice(&udp_length.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn a_well_formed_udp_frame_parses_to_its_fields() {
        let mut bytes = udp_frame(64, b"hello");
        let frame = Frame::parse(&mut bytes).expect("well-formed frame");

        assert_eq!(
            frame.destination_mac(),
            MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x02])
        );
        assert_eq!(
            frame.source_mac(),
            MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(frame.vlan(), None);

        let ip = frame.ipv4();
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, Protocol::UDP);
        assert_eq!(ip.source, Ipv4Address::from_octets([10, 0, 0, 2]));
        assert_eq!(ip.destination, Ipv4Address::from_octets([10, 0, 1, 2]));
        assert!(!ip.is_fragment());

        match frame.transport() {
            Transport::Udp(udp) => {
                assert_eq!(udp.source_port, 4444);
                assert_eq!(udp.destination_port, 5000);
                assert_eq!(usize::from(udp.length), UDP_HEADER_LEN + 5);
            }
            other => panic!("expected UDP, got {other:?}"),
        }
    }

    #[test]
    fn a_rewrite_replaces_both_macs_decrements_the_ttl_and_fixes_the_checksum() {
        let mut bytes = udp_frame(64, b"hello");
        let mut frame = Frame::parse(&mut bytes).expect("well-formed frame");
        let before = frame.ipv4();

        let gateway = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]);
        let next_hop = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
        frame
            .rewrite_for_forwarding(gateway, next_hop)
            .expect("a TTL of 64 survives a hop");

        assert_eq!(frame.destination_mac(), next_hop);
        assert_eq!(frame.source_mac(), gateway);

        let after = frame.ipv4();
        assert_eq!(after.ttl, before.ttl - 1);
        assert_eq!(after.source, before.source);
        assert_eq!(after.destination, before.destination);
        assert_eq!(after.total_length, before.total_length);

        // The rewritten frame must survive the very parser that accepted it,
        // which is the checksum assertion stated as the next hop would see it.
        Frame::parse(&mut bytes).expect("a rewritten frame stays well-formed");
    }

    #[test]
    fn a_ttl_that_cannot_survive_a_hop_leaves_the_frame_untouched() {
        for ttl in [0, 1] {
            let mut bytes = udp_frame(ttl, b"x");
            let original = bytes.clone();
            let mut frame = Frame::parse(&mut bytes).expect("well-formed frame");
            assert_eq!(
                frame.rewrite_for_forwarding(MacAddress([1; 6]), MacAddress([2; 6])),
                Err(TtlExpired { ttl })
            );
            assert_eq!(bytes, original, "a refused rewrite modified the frame");
        }
    }

    #[test]
    fn ipv4_options_are_refused_rather_than_skipped() {
        let mut bytes = udp_frame(64, b"x");
        bytes[ETHERNET_HEADER_LEN] = 0x46;
        let ip: &mut [u8; IPV4_HEADER_LEN] = (&mut bytes
            [ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN])
            .try_into()
            .expect("a 20-byte window");
        let checksum = recomputed_checksum(ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            Frame::parse(&mut bytes).unwrap_err(),
            ParseError::Ipv4OptionsUnsupported { ihl: 6 }
        );
    }

    #[test]
    fn a_corrupted_checksum_is_reported_with_what_it_should_have_been() {
        let mut bytes = udp_frame(64, b"x");
        bytes[ETHERNET_HEADER_LEN + 10] ^= 0xff;
        match Frame::parse(&mut bytes) {
            Err(ParseError::Ipv4ChecksumInvalid { found, computed }) => {
                assert_ne!(found, computed);
            }
            other => panic!("expected a checksum rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_total_length_beyond_the_frame_is_refused() {
        let mut bytes = udp_frame(64, b"x");
        let ip_start = ETHERNET_HEADER_LEN;
        bytes[ip_start + 2..ip_start + 4].copy_from_slice(&9000u16.to_be_bytes());
        let ip: &mut [u8; IPV4_HEADER_LEN] = (&mut bytes[ip_start..ip_start + IPV4_HEADER_LEN])
            .try_into()
            .expect("a 20-byte window");
        let checksum = recomputed_checksum(ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());

        assert!(matches!(
            Frame::parse(&mut bytes),
            Err(ParseError::Ipv4TotalLengthExceedsFrame { .. })
        ));
    }

    #[test]
    fn ethernet_padding_below_the_datagram_length_is_accepted() {
        let mut bytes = udp_frame(64, b"x");
        // The 60-byte minimum frame is padding the IPv4 total length disclaims;
        // a router must forward it rather than read the pad as payload.
        bytes.resize(60, 0);
        let frame = Frame::parse(&mut bytes).expect("a padded frame is well-formed");
        assert!(matches!(frame.transport(), Transport::Udp(_)));
    }

    #[test]
    fn a_non_initial_fragment_carries_no_transport_header() {
        let mut bytes = udp_frame(64, b"abcdefgh");
        let ip_start = ETHERNET_HEADER_LEN;
        bytes[ip_start + 6..ip_start + 8].copy_from_slice(&0x0001u16.to_be_bytes());
        let ip: &mut [u8; IPV4_HEADER_LEN] = (&mut bytes[ip_start..ip_start + IPV4_HEADER_LEN])
            .try_into()
            .expect("a 20-byte window");
        let checksum = recomputed_checksum(ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());

        let frame = Frame::parse(&mut bytes).expect("a fragment is still routable");
        assert_eq!(frame.transport(), Transport::NonInitialFragment);
        assert!(frame.ipv4().is_fragment());
    }

    #[test]
    fn a_single_vlan_tag_is_surfaced_and_the_inner_ethertype_is_parsed() {
        let plain = udp_frame(64, b"x");
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&plain[..MAC_PAIR_LEN]);
        tagged.extend_from_slice(&EtherType::VLAN.0.to_be_bytes());
        tagged.extend_from_slice(&0x2064u16.to_be_bytes());
        tagged.extend_from_slice(&plain[MAC_PAIR_LEN..]);

        let frame = Frame::parse(&mut tagged).expect("a tagged IPv4 frame parses");
        assert_eq!(
            frame.vlan(),
            Some(VlanTag {
                priority: 1,
                drop_eligible: false,
                id: 100,
            })
        );
        assert!(matches!(frame.transport(), Transport::Udp(_)));
    }

    #[test]
    fn stacked_vlan_tags_are_refused() {
        let plain = udp_frame(64, b"x");
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&plain[..MAC_PAIR_LEN]);
        tagged.extend_from_slice(&EtherType::VLAN.0.to_be_bytes());
        tagged.extend_from_slice(&0x0064u16.to_be_bytes());
        tagged.extend_from_slice(&EtherType::VLAN.0.to_be_bytes());
        tagged.extend_from_slice(&plain[MAC_PAIR_LEN + 2..]);

        assert_eq!(
            Frame::parse(&mut tagged).unwrap_err(),
            ParseError::StackedVlanTags
        );
    }

    #[test]
    fn a_udp_length_below_its_own_header_is_refused() {
        let mut bytes = udp_frame(64, b"abcd");
        let udp_start = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
        bytes[udp_start + 4..udp_start + 6].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            Frame::parse(&mut bytes).unwrap_err(),
            ParseError::UdpLengthBelowHeader { length: 4 }
        );
    }

    #[test]
    fn non_ipv4_ethertypes_are_named_in_the_rejection() {
        for ether_type in [EtherType::ARP, EtherType::IPV6, EtherType(0x88b5)] {
            let mut bytes = udp_frame(64, b"x");
            bytes[MAC_PAIR_LEN..ETHERNET_HEADER_LEN].copy_from_slice(&ether_type.0.to_be_bytes());
            assert_eq!(
                Frame::parse(&mut bytes).unwrap_err(),
                ParseError::UnsupportedEtherType(ether_type)
            );
        }
    }

    /// Rebuild the header checksum after an edit, the way a hostile sender
    /// would: a rejection that only ever fired because the checksum was stale
    /// would prove nothing about the field the test is aimed at.
    fn reseal(bytes: &mut [u8]) {
        let ip: &mut [u8; IPV4_HEADER_LEN] = (&mut bytes
            [ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN])
            .try_into()
            .expect("a 20-byte window");
        let checksum = recomputed_checksum(ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
    fn a_header_that_contradicts_itself_is_refused_field_by_field() {
        // One malformed frame per rejection the IPv4 and UDP paths can reach,
        // each resealed so the checksum is not what refuses it.
        let mut version = udp_frame(64, b"xy");
        version[ETHERNET_HEADER_LEN] = 0x65;
        reseal(&mut version);
        assert_eq!(
            Frame::parse(&mut version).unwrap_err(),
            ParseError::Ipv4VersionNotFour(6)
        );

        let mut short_datagram = udp_frame(64, b"xy");
        short_datagram[ETHERNET_HEADER_LEN + 2..ETHERNET_HEADER_LEN + 4]
            .copy_from_slice(&8u16.to_be_bytes());
        reseal(&mut short_datagram);
        assert_eq!(
            Frame::parse(&mut short_datagram).unwrap_err(),
            ParseError::Ipv4TotalLengthBelowHeader { total_length: 8 }
        );

        // A datagram whose total length leaves no room for the UDP header it
        // claims to carry.
        let mut truncated_udp = udp_frame(64, b"xy");
        let total_length = (IPV4_HEADER_LEN + 4) as u16;
        truncated_udp[ETHERNET_HEADER_LEN + 2..ETHERNET_HEADER_LEN + 4]
            .copy_from_slice(&total_length.to_be_bytes());
        reseal(&mut truncated_udp);
        assert_eq!(
            Frame::parse(&mut truncated_udp).unwrap_err(),
            ParseError::UdpHeaderTruncated { available: 4 }
        );

        let mut long_udp = udp_frame(64, b"xy");
        let udp_at = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
        long_udp[udp_at + 4..udp_at + 6].copy_from_slice(&1000u16.to_be_bytes());
        assert_eq!(
            Frame::parse(&mut long_udp).unwrap_err(),
            ParseError::UdpLengthExceedsDatagram {
                length: 1000,
                available: UDP_HEADER_LEN + 2,
            }
        );

        // Four bytes are not an 802.1Q tag and an inner EtherType.
        let mut stub = udp_frame(64, b"xy");
        stub[MAC_PAIR_LEN..ETHERNET_HEADER_LEN].copy_from_slice(&EtherType::VLAN.0.to_be_bytes());
        stub.truncate(ETHERNET_HEADER_LEN + 2);
        assert_eq!(
            Frame::parse(&mut stub).unwrap_err(),
            ParseError::FrameTooShort {
                needed: MIN_ROUTABLE_FRAME_LEN + VLAN_TAG_LEN,
                got: ETHERNET_HEADER_LEN + 2,
            }
        );
    }

    #[test]
    fn a_protocol_this_crate_does_not_parse_is_carried_rather_than_refused() {
        // A router forwards TCP and ICMP; only a filtering decision needs them
        // broken down, so the protocol number is surfaced and the packet stays
        // routable.
        for protocol in [Protocol::TCP, Protocol::ICMP, Protocol(253)] {
            let mut bytes = udp_frame(64, b"payload!");
            bytes[ETHERNET_HEADER_LEN + 9] = protocol.0;
            reseal(&mut bytes);
            let frame = Frame::parse(&mut bytes).expect("only the transport is unknown");
            assert_eq!(frame.transport(), Transport::Unparsed(protocol));
        }
    }

    #[test]
    fn every_rejection_renders_as_the_values_that_caused_it() {
        // A drop is currently unobservable on any operator surface: these
        // renderings are what a rejection will read as once it is, so a `{}`
        // that printed the variant name and none of its values would be
        // discovered on the one path where nothing else is available.
        let renderings = [
            format!("{}", ParseError::FrameTooShort { needed: 34, got: 9 }),
            format!("{}", ParseError::UnsupportedEtherType(EtherType::ARP)),
            format!("{}", ParseError::StackedVlanTags),
            format!("{}", ParseError::Ipv4VersionNotFour(6)),
            format!("{}", ParseError::Ipv4OptionsUnsupported { ihl: 6 }),
            format!(
                "{}",
                ParseError::Ipv4TotalLengthBelowHeader { total_length: 8 }
            ),
            format!(
                "{}",
                ParseError::Ipv4TotalLengthExceedsFrame {
                    total_length: 9000,
                    available: 60,
                }
            ),
            format!(
                "{}",
                ParseError::Ipv4ChecksumInvalid {
                    found: 0x1234,
                    computed: 0x5678,
                }
            ),
            format!("{}", ParseError::UdpHeaderTruncated { available: 4 }),
            format!("{}", ParseError::UdpLengthBelowHeader { length: 4 }),
            format!(
                "{}",
                ParseError::UdpLengthExceedsDatagram {
                    length: 1000,
                    available: 10,
                }
            ),
        ];
        for rendering in &renderings {
            assert!(!rendering.is_empty());
        }
        // The values, not merely the category: each rendering names what was
        // found, which is what makes a counted drop actionable.
        assert!(renderings[0].contains("34") && renderings[0].contains('9'));
        assert!(renderings[1].contains("0x0806"));
        assert!(renderings[7].contains("0x1234") && renderings[7].contains("0x5678"));

        let mut distinct: Vec<&str> = renderings.iter().map(String::as_str).collect();
        distinct.sort_unstable();
        let count = distinct.len();
        distinct.dedup();
        assert_eq!(distinct.len(), count, "two rejections read alike");

        assert_eq!(
            format!("{}", TtlExpired { ttl: 1 }),
            "TTL 1 does not survive a hop"
        );
        assert_eq!(
            format!("{}", MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50])),
            "52:54:00:12:34:50"
        );
        assert_eq!(
            format!("{}", Ipv4Address::from_octets([10, 0, 1, 255])),
            "10.0.1.255"
        );
        assert_eq!(format!("{}", EtherType::IPV4), "0x0800");
        assert_eq!(format!("{}", Protocol::UDP), "17");
    }

    #[test]
    fn address_predicates_match_their_ranges() {
        assert!(Ipv4Address::from_octets([224, 0, 0, 1]).is_multicast());
        assert!(!Ipv4Address::from_octets([223, 255, 255, 255]).is_multicast());
        assert!(Ipv4Address::from_octets([255, 255, 255, 255]).is_broadcast());
        assert!(Ipv4Address::from_octets([127, 0, 0, 1]).is_loopback());
        assert!(Ipv4Address::from_octets([0, 0, 0, 0]).is_unspecified());
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(MacAddress::BROADCAST.is_group());
        assert!(MacAddress([0x01, 0, 0, 0, 0, 0]).is_group());
        assert!(!MacAddress([0x52, 0x54, 0, 0, 0, 1]).is_group());
    }

    proptest! {
        /// The whole adversary model in one property: arbitrary bytes of
        /// arbitrary length, straight off a wire, must never panic the parser.
        #[test]
        fn arbitrary_bytes_never_panic_the_parser(mut bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = Frame::parse(&mut bytes);
        }

        /// A parse that succeeds must leave the frame byte-identical: parsing is
        /// a read, and the rewrite is the only writer.
        #[test]
        fn parsing_never_modifies_the_frame(mut bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let original = bytes.clone();
            let _ = Frame::parse(&mut bytes);
            prop_assert_eq!(bytes, original);
        }

        /// Whatever the payload, a rewritten frame re-parses — which is the
        /// checksum being right stated as the next hop would test it.
        #[test]
        fn a_rewritten_frame_always_reparses(
            payload in prop::collection::vec(any::<u8>(), 0..512),
            ttl in 2u8..=255,
        ) {
            let mut bytes = udp_frame(ttl, &payload);
            let mut frame = Frame::parse(&mut bytes).expect("constructed well-formed");
            frame.rewrite_for_forwarding(MacAddress([1; 6]), MacAddress([2; 6]))
                .expect("a TTL above 1 survives a hop");

            let reparsed = Frame::parse(&mut bytes).expect("a rewrite keeps the frame well-formed");
            prop_assert_eq!(reparsed.ipv4().ttl, ttl - 1);
            prop_assert_eq!(reparsed.destination_mac(), MacAddress([2; 6]));
            prop_assert_eq!(reparsed.source_mac(), MacAddress([1; 6]));
        }

        /// A rewrite touches the two MACs, the TTL and the checksum, and nothing
        /// else — in particular no payload byte and neither address.
        #[test]
        fn a_rewrite_touches_only_the_four_fields_it_names(
            payload in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let mut bytes = udp_frame(64, &payload);
            let original = bytes.clone();
            let mut frame = Frame::parse(&mut bytes).expect("constructed well-formed");
            frame.rewrite_for_forwarding(MacAddress([1; 6]), MacAddress([2; 6]))
                .expect("a TTL of 64 survives a hop");

            let untouched = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
            prop_assert_eq!(&bytes[untouched..], &original[untouched..]);
            // Source and destination addresses sit at 12..20 of the IPv4 header.
            let addresses = ETHERNET_HEADER_LEN + 12..untouched;
            prop_assert_eq!(&bytes[addresses.clone()], &original[addresses]);
        }

        /// The ones' complement sum is what makes a checksum verifiable at all,
        /// so it is checked against its defining property rather than a table:
        /// summing a header that already carries its checksum yields zero.
        #[test]
        fn a_recomputed_checksum_validates_the_header_it_came_from(
            mut header in prop::array::uniform20(any::<u8>()),
        ) {
            let checksum = recomputed_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            prop_assert_eq!(header_checksum(&header), 0);
        }

        #[test]
        fn ipv4_addresses_round_trip_through_their_octets(octets in any::<[u8; 4]>()) {
            prop_assert_eq!(Ipv4Address::from_octets(octets).octets(), octets);
        }
    }

    const OUR_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
    const PEER_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0c]);
    const OUR_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
    const PEER_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

    /// An ARP request for `target`, as a station puts it on the wire:
    /// broadcast at L2, unpadded at 42 bytes.
    fn arp_request(target: Ipv4Address) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&MacAddress::BROADCAST.0);
        frame.extend_from_slice(&PEER_MAC.0);
        frame.extend_from_slice(&EtherType::ARP.0.to_be_bytes());
        frame.extend_from_slice(&ARP_HARDWARE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
        frame.push(ARP_HARDWARE_LEN);
        frame.push(ARP_PROTOCOL_LEN);
        frame.extend_from_slice(&ARP_REQUEST.to_be_bytes());
        frame.extend_from_slice(&PEER_MAC.0);
        frame.extend_from_slice(&PEER_ADDRESS.octets());
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&target.octets());
        frame
    }

    /// An ICMP echo request to `destination`, checksummed the naive way rather
    /// than through the crate's own routine.
    fn echo_request(
        destination: Ipv4Address,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut icmp = Vec::new();
        icmp.push(ICMP_ECHO_REQUEST_TYPE);
        icmp.push(ICMP_ECHO_CODE);
        icmp.extend_from_slice(&[0, 0]);
        icmp.extend_from_slice(&identifier.to_be_bytes());
        icmp.extend_from_slice(&sequence.to_be_bytes());
        icmp.extend_from_slice(payload);
        let checksum = naive_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = Vec::new();
        frame.extend_from_slice(&OUR_MAC.0);
        frame.extend_from_slice(&PEER_MAC.0);
        frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
        let total_length = (IPV4_HEADER_LEN + icmp.len()) as u16;
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_length.to_be_bytes());
        ip[8] = 64;
        ip[9] = Protocol::ICMP.0;
        ip[12..16].copy_from_slice(&PEER_ADDRESS.octets());
        ip[16..20].copy_from_slice(&destination.octets());
        let checksum = naive_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&icmp);
        frame
    }

    /// The RFC 1071 sum written independently of the crate's own, so a builder
    /// and a verifier that were both wrong could not agree.
    fn naive_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for index in 0..bytes.len().div_ceil(2) {
            let high = bytes[index * 2];
            let low = bytes.get(index * 2 + 1).copied().unwrap_or(0);
            sum += u32::from(u16::from_be_bytes([high, low]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn an_ethernet_header_parses_to_its_three_fields_and_the_rest() {
        let frame = arp_request(OUR_ADDRESS);
        let ethernet = Ethernet::parse(&frame).expect("42 bytes carry a header");
        assert_eq!(ethernet.header.destination, MacAddress::BROADCAST);
        assert_eq!(ethernet.header.source, PEER_MAC);
        assert_eq!(ethernet.header.ether_type, EtherType::ARP);
        assert_eq!(ethernet.payload.len(), ARP_PAYLOAD_LEN);

        for len in 0..ETHERNET_HEADER_LEN {
            assert_eq!(
                Ethernet::parse(&frame[..len]).unwrap_err(),
                ParseError::FrameTooShort {
                    needed: ETHERNET_HEADER_LEN,
                    got: len,
                }
            );
        }
    }

    /// A VLAN TPID reaches the caller as itself rather than being unwrapped:
    /// this crate holds no sub-interface model, so the decision is the caller's.
    #[test]
    fn a_tagged_frame_reports_the_tag_ethertype_rather_than_the_inner_one() {
        let mut frame = arp_request(OUR_ADDRESS);
        frame[MAC_PAIR_LEN..ETHERNET_HEADER_LEN].copy_from_slice(&EtherType::VLAN.0.to_be_bytes());
        let ethernet = Ethernet::parse(&frame).expect("a header is a header");
        assert_eq!(ethernet.header.ether_type, EtherType::VLAN);
    }

    #[test]
    fn a_well_formed_arp_request_parses_to_its_fields() {
        let frame = arp_request(OUR_ADDRESS);
        let ethernet = Ethernet::parse(&frame).expect("a header");
        let packet = ArpPacket::parse(ethernet.payload).expect("IPv4 over Ethernet");
        assert_eq!(packet.operation, ArpOperation::Request);
        assert_eq!(packet.sender_mac, PEER_MAC);
        assert_eq!(packet.sender_address, PEER_ADDRESS);
        assert_eq!(packet.target_mac, MacAddress([0; 6]));
        assert_eq!(packet.target_address, OUR_ADDRESS);
    }

    /// Padding to the 60-byte Ethernet minimum is neither read nor refused.
    #[test]
    fn a_padded_arp_packet_parses_to_the_same_fields() {
        let frame = arp_request(OUR_ADDRESS);
        let mut padded = frame.clone();
        padded.resize(60, 0);
        let plain = Ethernet::parse(&frame).expect("a header");
        let with_padding = Ethernet::parse(&padded).expect("a header");
        assert_eq!(
            ArpPacket::parse(plain.payload),
            ArpPacket::parse(with_padding.payload)
        );
    }

    #[test]
    fn an_arp_packet_this_crate_will_not_interpret_is_refused_by_the_field_that_refused_it() {
        let base = arp_request(OUR_ADDRESS);
        let payload = ETHERNET_HEADER_LEN;

        for len in 0..ARP_PAYLOAD_LEN {
            assert_eq!(
                ArpPacket::parse(&base[payload..payload + len]).unwrap_err(),
                ArpError::PayloadTooShort { got: len }
            );
        }

        let mut hardware = base.clone();
        hardware[payload..payload + 2].copy_from_slice(&6u16.to_be_bytes());
        assert_eq!(
            ArpPacket::parse(&hardware[payload..]).unwrap_err(),
            ArpError::HardwareTypeUnsupported { hardware_type: 6 }
        );

        let mut protocol = base.clone();
        protocol[payload + 2..payload + 4].copy_from_slice(&EtherType::IPV6.0.to_be_bytes());
        assert_eq!(
            ArpPacket::parse(&protocol[payload..]).unwrap_err(),
            ArpError::ProtocolTypeUnsupported {
                protocol_type: EtherType::IPV6,
            }
        );

        for (hardware_len, protocol_len) in [(8u8, 4u8), (6, 16), (0, 0)] {
            let mut lengths = base.clone();
            lengths[payload + 4] = hardware_len;
            lengths[payload + 5] = protocol_len;
            assert_eq!(
                ArpPacket::parse(&lengths[payload..]).unwrap_err(),
                ArpError::AddressLengthsUnsupported {
                    hardware_len,
                    protocol_len,
                }
            );
        }

        for operation in [0u16, 3, 8, u16::MAX] {
            let mut wrong = base.clone();
            wrong[payload + 6..payload + 8].copy_from_slice(&operation.to_be_bytes());
            assert_eq!(
                ArpPacket::parse(&wrong[payload..]).unwrap_err(),
                ArpError::OperationUnsupported { operation }
            );
        }

        let mut reply = base;
        reply[payload + 6..payload + 8].copy_from_slice(&ARP_REPLY.to_be_bytes());
        assert_eq!(
            ArpPacket::parse(&reply[payload..])
                .expect("a reply decodes")
                .operation,
            ArpOperation::Reply
        );
    }

    #[test]
    fn an_arp_reply_carries_our_pair_and_answers_the_requester() {
        let frame = arp_request(OUR_ADDRESS);
        let request = ArpPacket::parse(&frame[ETHERNET_HEADER_LEN..]).expect("a request");
        let mut out = [0u8; 64];
        let len = ArpReply {
            mac: OUR_MAC,
            address: OUR_ADDRESS,
            target_mac: request.sender_mac,
            target_address: request.sender_address,
        }
        .write(&mut out)
        .expect("64 bytes hold a 42-byte reply");
        assert_eq!(len, ARP_FRAME_LEN);

        let ethernet = Ethernet::parse(&out[..len]).expect("a reply is a frame");
        assert_eq!(ethernet.header.destination, PEER_MAC);
        assert_eq!(ethernet.header.source, OUR_MAC);
        assert_eq!(ethernet.header.ether_type, EtherType::ARP);
        let reply = ArpPacket::parse(ethernet.payload).expect("a reply re-parses");
        assert_eq!(reply.operation, ArpOperation::Reply);
        assert_eq!(reply.sender_mac, OUR_MAC);
        assert_eq!(reply.sender_address, OUR_ADDRESS);
        assert_eq!(reply.target_mac, PEER_MAC);
        assert_eq!(reply.target_address, PEER_ADDRESS);
        // Nothing past the frame is touched.
        assert!(out[len..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_reply_that_does_not_fit_is_refused_with_nothing_written() {
        for capacity in 0..ARP_FRAME_LEN {
            let mut out = vec![0u8; capacity];
            assert_eq!(
                ArpReply {
                    mac: OUR_MAC,
                    address: OUR_ADDRESS,
                    target_mac: PEER_MAC,
                    target_address: PEER_ADDRESS,
                }
                .write(&mut out),
                Err(ReplyError::DoesNotFit {
                    needed: ARP_FRAME_LEN,
                    capacity,
                })
            );
            assert!(out.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn a_well_formed_echo_request_parses_to_its_echo() {
        let frame = echo_request(OUR_ADDRESS, 0x1234, 7, b"ping-payload");
        let ethernet = Ethernet::parse(&frame).expect("a header");
        assert_eq!(ethernet.header.ether_type, EtherType::IPV4);
        let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
        assert_eq!(packet.header().protocol, Protocol::ICMP);
        assert_eq!(packet.header().destination, OUR_ADDRESS);
        assert_eq!(packet.header().source, PEER_ADDRESS);
        let echo = IcmpEcho::parse_request(packet.payload()).expect("an echo request");
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence, 7);
        assert_eq!(echo.payload, b"ping-payload");
    }

    /// The read-only view and the rewritable one are one validator, so a header
    /// either passes both or neither.
    #[test]
    fn the_two_ipv4_parsers_agree_on_every_header_rule() {
        let mut cases = vec![
            udp_frame(64, b"hello"),
            echo_request(OUR_ADDRESS, 1, 1, b"x"),
        ];
        let mut version = udp_frame(64, b"xy");
        version[ETHERNET_HEADER_LEN] = 0x65;
        reseal(&mut version);
        cases.push(version);
        let mut options = udp_frame(64, b"xy");
        options[ETHERNET_HEADER_LEN] = 0x46;
        reseal(&mut options);
        cases.push(options);
        let mut checksum = udp_frame(64, b"xy");
        checksum[ETHERNET_HEADER_LEN + 10] ^= 0xff;
        cases.push(checksum);
        let mut short = udp_frame(64, b"xy");
        short[ETHERNET_HEADER_LEN + 2..ETHERNET_HEADER_LEN + 4]
            .copy_from_slice(&8u16.to_be_bytes());
        reseal(&mut short);
        cases.push(short);
        let mut beyond = udp_frame(64, b"xy");
        beyond[ETHERNET_HEADER_LEN + 2..ETHERNET_HEADER_LEN + 4]
            .copy_from_slice(&9000u16.to_be_bytes());
        reseal(&mut beyond);
        cases.push(beyond);

        for frame in cases {
            let expected = Frame::parse(&mut frame.clone()).map(|parsed| parsed.ipv4());
            let observed =
                Ipv4Packet::parse(&frame[ETHERNET_HEADER_LEN..]).map(|packet| packet.header());
            match (expected, observed) {
                (Ok(left), Ok(right)) => assert_eq!(left, right),
                (Err(left), Err(right)) => assert_eq!(left, right),
                // The transport rules are `Frame`'s alone, so a UDP rejection
                // is not one `Ipv4Packet` makes; every case above is an L3 one.
                (left, right) => panic!("{left:?} against {right:?}"),
            }
        }
    }

    #[test]
    fn an_icmp_message_that_is_not_an_echo_request_is_refused_by_what_refused_it() {
        let frame = echo_request(OUR_ADDRESS, 1, 1, b"payload!");
        let icmp_at = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;

        for len in 0..ICMP_ECHO_HEADER_LEN {
            assert_eq!(
                IcmpEcho::parse_request(&frame[icmp_at..icmp_at + len]).unwrap_err(),
                IcmpError::HeaderTruncated { got: len }
            );
        }

        for (message_type, code) in [(0u8, 0u8), (8, 1), (3, 3), (255, 255)] {
            let mut wrong = frame.clone();
            wrong[icmp_at] = message_type;
            wrong[icmp_at + 1] = code;
            assert_eq!(
                IcmpEcho::parse_request(&wrong[icmp_at..]).unwrap_err(),
                IcmpError::NotAnEchoRequest { message_type, code }
            );
        }

        let mut corrupt = frame.clone();
        corrupt[icmp_at + 6] ^= 0xff;
        match IcmpEcho::parse_request(&corrupt[icmp_at..]) {
            Err(IcmpError::ChecksumInvalid { found, computed }) => assert_ne!(found, computed),
            other => panic!("expected a checksum rejection, got {other:?}"),
        }
    }

    #[test]
    fn an_echo_reply_repeats_the_echo_and_reverses_both_layers() {
        let request = echo_request(OUR_ADDRESS, 0xbeef, 3, b"0123456789abcdef");
        let ethernet = Ethernet::parse(&request).expect("a header");
        let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
        let echo = IcmpEcho::parse_request(packet.payload()).expect("an echo request");

        let mut out = [0u8; 128];
        let len = EchoReply {
            destination_mac: ethernet.header.source,
            source_mac: OUR_MAC,
            source: OUR_ADDRESS,
            destination: packet.header().source,
            echo,
        }
        .write(&mut out)
        .expect("128 bytes hold the reply");
        assert_eq!(len, MIN_ECHO_REPLY_LEN + 16);

        let reply_ethernet = Ethernet::parse(&out[..len]).expect("a reply is a frame");
        assert_eq!(reply_ethernet.header.destination, PEER_MAC);
        assert_eq!(reply_ethernet.header.source, OUR_MAC);
        // Re-parsing is the checksum asserted the way the sender tests it.
        let reply_packet = Ipv4Packet::parse(reply_ethernet.payload).expect("a valid datagram");
        assert_eq!(reply_packet.header().source, OUR_ADDRESS);
        assert_eq!(reply_packet.header().destination, PEER_ADDRESS);
        assert_eq!(reply_packet.header().ttl, EchoReply::TTL);
        assert_eq!(reply_packet.header().protocol, Protocol::ICMP);
        assert!(!reply_packet.header().is_fragment());

        let message = reply_packet.payload();
        assert_eq!(message[0], ICMP_ECHO_REPLY_TYPE);
        assert_eq!(message[1], ICMP_ECHO_CODE);
        assert_eq!(naive_checksum(message), 0, "the reply's own sum validates");
        assert_eq!(u16::from_be_bytes([message[4], message[5]]), 0xbeef);
        assert_eq!(u16::from_be_bytes([message[6], message[7]]), 3);
        assert_eq!(&message[ICMP_ECHO_HEADER_LEN..], b"0123456789abcdef");
        assert!(out[len..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn an_echo_reply_that_does_not_fit_is_refused_rather_than_truncated() {
        let echo = IcmpEcho {
            identifier: 1,
            sequence: 1,
            payload: &[0xaa; 32],
        };
        let needed = MIN_ECHO_REPLY_LEN + 32;
        for capacity in [0, 1, MIN_ECHO_REPLY_LEN, needed - 1] {
            let mut out = vec![0u8; capacity];
            assert_eq!(
                EchoReply {
                    destination_mac: PEER_MAC,
                    source_mac: OUR_MAC,
                    source: OUR_ADDRESS,
                    destination: PEER_ADDRESS,
                    echo,
                }
                .write(&mut out),
                Err(ReplyError::DoesNotFit { needed, capacity })
            );
        }
    }

    #[test]
    fn an_echo_payload_no_datagram_can_name_is_refused() {
        let payload = vec![0u8; usize::from(u16::MAX)];
        let mut out = vec![0u8; payload.len() + MIN_ECHO_REPLY_LEN];
        assert_eq!(
            EchoReply {
                destination_mac: PEER_MAC,
                source_mac: OUR_MAC,
                source: OUR_ADDRESS,
                destination: PEER_ADDRESS,
                echo: IcmpEcho {
                    identifier: 0,
                    sequence: 0,
                    payload: &payload,
                },
            }
            .write(&mut out),
            Err(ReplyError::PayloadTooLong { len: payload.len() })
        );
    }

    #[test]
    fn address_and_mac_predicates_answer_the_questions_an_endpoint_asks() {
        assert!(OUR_ADDRESS.is_unicast());
        for octets in [
            [224, 0, 0, 1],
            [255, 255, 255, 255],
            [127, 0, 0, 1],
            [0, 0, 0, 0],
        ] {
            assert!(!Ipv4Address::from_octets(octets).is_unicast(), "{octets:?}");
        }
        assert!(OUR_MAC.is_unicast());
        assert!(!MacAddress::BROADCAST.is_unicast());
        assert!(!MacAddress([0x01, 0, 0, 0, 0, 1]).is_unicast());
        assert!(!MacAddress([0; 6]).is_unicast());

        assert!(OUR_ADDRESS.shares_prefix(PEER_ADDRESS, 24));
        assert!(!OUR_ADDRESS.shares_prefix(Ipv4Address::from_octets([10, 0, 3, 2]), 24));
        assert!(OUR_ADDRESS.shares_prefix(Ipv4Address::from_octets([9, 9, 9, 9]), 0));
        assert!(!OUR_ADDRESS.shares_prefix(PEER_ADDRESS, 32));
        assert!(OUR_ADDRESS.shares_prefix(OUR_ADDRESS, 32));
    }

    #[test]
    fn prefix_masks_saturate_at_both_ends() {
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(1), 0x8000_0000);
        assert_eq!(prefix_mask(24), 0xffff_ff00);
        assert_eq!(prefix_mask(32), u32::MAX);
        assert_eq!(prefix_mask(255), u32::MAX);
    }

    proptest! {
        /// The whole adversary model over the new parsers: arbitrary bytes of
        /// arbitrary length, straight off a wire, answered rather than crashed.
        #[test]
        fn arbitrary_bytes_never_panic_the_l2_parsers(
            bytes in prop::collection::vec(any::<u8>(), 0..2048),
        ) {
            if let Ok(ethernet) = Ethernet::parse(&bytes) {
                let _ = ArpPacket::parse(ethernet.payload);
                let _ = IcmpEcho::parse_request(ethernet.payload);
                if let Ok(packet) = Ipv4Packet::parse(ethernet.payload) {
                    prop_assert!(
                        packet.payload().len()
                            == usize::from(packet.header().total_length) - IPV4_HEADER_LEN
                    );
                    let _ = IcmpEcho::parse_request(packet.payload());
                }
            }
        }

        /// A reply is written whole or not at all, and never past the storage it
        /// was given.
        #[test]
        fn a_reply_stays_inside_the_storage_it_was_handed(
            payload in prop::collection::vec(any::<u8>(), 0..600),
            capacity in 0usize..700,
        ) {
            let mut out = vec![0xffu8; capacity];
            let echo = IcmpEcho { identifier: 9, sequence: 4, payload: &payload };
            let reply = EchoReply {
                destination_mac: PEER_MAC,
                source_mac: OUR_MAC,
                source: OUR_ADDRESS,
                destination: PEER_ADDRESS,
                echo,
            };
            match reply.write(&mut out) {
                Ok(len) => {
                    prop_assert_eq!(len, MIN_ECHO_REPLY_LEN + payload.len());
                    prop_assert!(len <= capacity);
                    let ethernet = Ethernet::parse(&out[..len]).expect("a frame");
                    let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
                    let message = packet.payload();
                    prop_assert_eq!(naive_checksum(message), 0);
                    prop_assert_eq!(&message[ICMP_ECHO_HEADER_LEN..], &payload[..]);
                }
                Err(ReplyError::DoesNotFit { needed, .. }) => {
                    prop_assert!(needed > capacity);
                }
                Err(other) => prop_assert!(false, "{other:?}"),
            }
        }

        /// An echo request this crate accepts is one whose reply it can build,
        /// and the reply repeats every field the sender matches on.
        #[test]
        fn every_accepted_echo_request_round_trips_into_its_reply(
            payload in prop::collection::vec(any::<u8>(), 0..512),
            identifier in any::<u16>(),
            sequence in any::<u16>(),
        ) {
            let request = echo_request(OUR_ADDRESS, identifier, sequence, &payload);
            let ethernet = Ethernet::parse(&request).expect("a header");
            let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
            let echo = IcmpEcho::parse_request(packet.payload()).expect("an echo request");
            prop_assert_eq!(echo.identifier, identifier);
            prop_assert_eq!(echo.sequence, sequence);
            prop_assert_eq!(echo.payload, &payload[..]);

            let mut out = vec![0u8; MIN_ECHO_REPLY_LEN + payload.len()];
            let len = EchoReply {
                destination_mac: ethernet.header.source,
                source_mac: OUR_MAC,
                source: OUR_ADDRESS,
                destination: packet.header().source,
                echo,
            }
            .write(&mut out)
            .expect("storage sized from the payload");
            let reply_ethernet = Ethernet::parse(&out[..len]).expect("a frame");
            let reply_packet = Ipv4Packet::parse(reply_ethernet.payload).expect("a datagram");
            let message = reply_packet.payload();
            prop_assert_eq!(naive_checksum(message), 0);
            prop_assert_eq!(u16::from_be_bytes([message[4], message[5]]), identifier);
            prop_assert_eq!(u16::from_be_bytes([message[6], message[7]]), sequence);
        }

        /// The two ways a checksum is asked about agree: a block carrying the
        /// value `checksum_over` computes validates.
        #[test]
        fn a_computed_checksum_validates_the_block_it_came_from(
            bytes in prop::collection::vec(any::<u8>(), 4..64),
        ) {
            let mut block = bytes;
            let checksum = checksum_over(&block, ICMP_CHECKSUM_AT);
            block[ICMP_CHECKSUM_AT..ICMP_CHECKSUM_AT + 2]
                .copy_from_slice(&checksum.to_be_bytes());
            prop_assert_eq!(fold(accumulate(0, &block)), u16::MAX);
            prop_assert_eq!(naive_checksum(&block), 0);
        }
    }
}
