//! Ethernet, IPv4 and UDP header parsing, and the four in-place edits routing a
//! frame requires.
//!
//! Faces untrusted network traffic (CONCEPT §7.1): every byte reaching
//! [`Frame::parse`] was put on the wire by whatever is attached to a dataplane
//! port. Nothing here panics, indexes past a bound, or truncates a value into a
//! meaning it did not have; a header that is not exactly what it claims is a
//! [`ParseError`] the caller must handle.
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
//! * **IPv6 is absent**, so CONCEPT §5's L3 row is met for one of its two
//!   protocols.

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

pub const UDP_HEADER_LEN: usize = 8;

/// The smallest frame that can carry anything this crate parses.
pub const MIN_ROUTABLE_FRAME_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;

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

        let header = read_ipv4(ipv4);

        let version = version_of(ipv4);
        if version != 4 {
            return Err(ParseError::Ipv4VersionNotFour(version));
        }
        let ihl = ihl_of(ipv4);
        if ihl != 5 {
            return Err(ParseError::Ipv4OptionsUnsupported { ihl });
        }

        let computed = header_checksum(ipv4);
        if computed != 0 {
            return Err(ParseError::Ipv4ChecksumInvalid {
                found: header.checksum,
                computed: recomputed_checksum(ipv4),
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
        if datagram_payload_len > payload.len() {
            return Err(ParseError::Ipv4TotalLengthExceedsFrame {
                total_length: header.total_length,
                available: available_for_ip,
            });
        }
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

/// The RFC 1071 ones' complement sum folded to 16 bits.
///
/// Byte-pair driven rather than index driven so an odd-length input is the
/// documented "pad with a zero byte" case instead of a bounds question. The
/// accumulator cannot overflow: each addend is at most `u16::MAX` and the
/// longest input here is one IPv4 header.
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut octets = bytes.iter().copied();
    loop {
        let pair = match (octets.next(), octets.next()) {
            (Some(high), Some(low)) => [high, low],
            (Some(high), None) => [high, 0],
            _ => break,
        };
        sum += u32::from(u16::from_be_bytes(pair));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    // Lossless: the fold above leaves at most 16 significant bits.
    sum as u16
}

/// Zero exactly when the header's own checksum field is consistent with the
/// rest of it, the field being part of its own input.
fn header_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    !ones_complement_sum(header)
}

/// What the checksum field should hold, ignoring what it currently holds.
fn recomputed_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    let mut zeroed = *header;
    zeroed[10] = 0;
    zeroed[11] = 0;
    !ones_complement_sum(&zeroed)
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
        // MONITORING.md records that a drop is currently unobservable: these
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
}
