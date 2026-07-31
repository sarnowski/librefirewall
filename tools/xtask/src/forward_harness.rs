//! QEMU virtio-net routing harness: two dataplane ports and a management one.
//!
//! Attaches a `virtio-net-pci` NIC per port whose backend is a host-controlled
//! TCP socket to a caller-built QEMU invocation (the OVMF/GRUB boot of the
//! deployable disk), plays one host endpoint on each dataplane port and one
//! station on the management port, and judges the boot against a
//! [`BootContract`].
//!
//! # The management port is a different kind of thing, not a third port
//!
//! It is not in [`PORTS`], carries no [`Endpoint`], and **no probe crosses it**:
//! the routed contract must never expect it to forward anything, because CONCEPT
//! §9.1 says it carries no forwarded traffic. What it gets instead is a contract
//! of its own, injected once at the point the capture proves every port is up so
//! an exact count is possible:
//!
//! * [`MANAGEMENT_FRAMES`] opaque frames, whose only purpose is to be counted —
//!   four different lengths, so the console's byte total is evidence rather than
//!   a multiple of one number;
//! * an **ARP request** for the management address, which must be answered with
//!   the MAC the document gives that port;
//! * an **ICMP echo request** to it, which must be answered with a reply
//!   carrying the same identifier, sequence and payload and a valid checksum.
//!
//! Both replies are decoded field by field by this harness's own reader, never
//! matched as bytes and never as text: a reply built by the appliance's own
//! builder and compared against the appliance's own expectation would agree with
//! itself. What was injected travels back to the caller as a
//! [`ManagementInjection`] for `management_contract` to judge the console
//! against.
//!
//! # The isolation is asserted in both directions, not described
//!
//! CONCEPT §9.1's mutual exclusion is two prohibitions, and a boot must satisfy
//! both: **no frame the harness put on the management wire may appear on either
//! dataplane port**, and **no dataplane probe may appear on the management
//! port**. Neither is a property of what the appliance was asked to do — it is a
//! property of a grant set no domain spans — so each is a machine-checked
//! assertion here rather than a sentence in the system description. The only
//! frames that may come back on the management port at all are the two replies
//! above, exactly once each: the port answers for itself and forwards nothing.
//!
//! The primary contract, [`BootContract::Routed`], is the system's real
//! observable behaviour. The guest is an IPv4 router between two directly
//! attached subnets, so a datagram from the endpoint on one port must reach the
//! endpoint on the other rewritten for its next hop — new MAC pair, one less
//! TTL, header checksum redone — and unchanged in every other byte. The same
//! boot injects the packets the appliance must refuse, and success needs both
//! deliveries *and* the absence of every refusal. Nothing about it involves
//! serial text. Its negative, [`BootContract::Halted`], proves the opposite for
//! a disk with no bootable slot: the same packets are injected and nothing at
//! all may come back, while the boot manager's structured halt record must
//! appear on the serial channel.
//!
//! The captured serial output is always written to the run log — behind a
//! harness-generated header describing how QEMU was configured — and returned
//! to the caller. The returned bytes are the guest's output alone, never the
//! header, so a caller asserting on the guest's structured records can never
//! match something the harness itself wrote.
//!
//! The addresses both sides of that contract are stated in are not written
//! here. They come from the configuration document the image under test was
//! built from, read by [`crate::topology`]: an endpoint is one of the
//! document's own `<neighbour>` elements, and the gateway MAC a routed frame
//! must carry is the MAC of the `<interface>` that neighbour names — which is
//! also the MAC QEMU is told to put on the port. A contract that expected an
//! address the appliance had never been configured with is therefore not
//! something this file can express.
//!
//! Every run also yields a [`TrafficReport`]: what each probe was observed to
//! do, with the delivered ones described by the frame that came back — its
//! addresses, its TTL, the MAC pair the appliance rewrote it to, its length on
//! the wire — rather than by the expectation it was matched against. Reporting
//! the expectation would make the table agree with the contract by
//! construction and say nothing about the appliance. The report is a rendering
//! of the verdict and never an input to it; it is printed on the way out of a
//! failed run too, ahead of the verdict, because "which probe" is the first
//! question a failure raises.

use std::{
    fmt, fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::management_contract::{self, ManagementInjection};
use crate::metrics_contract::{self, Scrape};
use crate::qemu::{GuestNic, every_guest_nic};
use crate::topology::{Endpoint, ManagementPort, PORTS, Topology};

/// Total wall-clock budget from QEMU launch to the contract being decided. A
/// TCG (no KVM) walk through OVMF, GRUB signature verification, seL4 boot, and
/// two polling virtio drivers is slow, hence the generous ceiling.
const BOOT_TEST_TIMEOUT: Duration = Duration::from_secs(180);

/// How long to wait for QEMU to dial back into both listeners before giving
/// up. The netdev sockets connect when QEMU starts, well before guest boot.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);

/// How often an endpoint retransmits a probe it has not seen delivered.
///
/// The endpoints are stations, and a station sends more than once. A packet put
/// on the wire before the appliance has booted is simply lost — QEMU's
/// virtio-net drops a receive while the guest has posted no RX buffer, as a
/// real link drops one to a peer that is not up yet — and nothing here
/// compensates for that loss or hides it. Injecting once and waiting would not
/// be a stricter test but a different one: a station that sends a single
/// datagram and gives up, which no appliance booting after QEMU starts could
/// ever answer.
const REINJECT_INTERVAL: Duration = Duration::from_millis(500);

/// How long the refused packets are watched for after both routed packets have
/// arrived. Both directions having completed is what proves the guest is taking
/// frames off both ports at all, so this window is not a guess about boot
/// progress — it is the round trip a delivery would need, and the two
/// deliveries already observed within one [`REINJECT_INTERVAL`] bound that.
const SETTLE_WINDOW: Duration = Duration::from_secs(2);

/// Minimum Ethernet frame size on the wire without FCS.
const MIN_ETHERNET_FRAME: usize = 60;

/// Upper bound on a frame length announced by QEMU's socket framing; anything
/// larger means a corrupt stream, not a jumbo frame.
const MAX_WIRE_FRAME: usize = 65535;

const MAC_PAIR_LEN: usize = 12;
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const MIN_UDP_FRAME: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;
const IPV4_ETHERTYPE: u16 = 0x0800;
const UDP_PROTOCOL: u8 = 17;

/// The EtherType of the frame the retired L2 contract required to be forwarded
/// byte-identical; see [`legacy_broadcast_frame`].
const LOCAL_EXPERIMENTAL_ETHERTYPE: u16 = 0x88b5;

/// The destination the `no-route` probe is sent to: a documentation address
/// (RFC 5737) no plausible bench terminates on.
///
/// [`probes`] refuses a bench whose document *does* cover it rather than
/// injecting it anyway, because a probe the appliance has a route for is one
/// the appliance may legitimately deliver — and the run would then fail with
/// the appliance in the right and the harness in the wrong.
const UNROUTED_DESTINATION: [u8; 4] = [192, 0, 2, 9];

/// The destination MAC the `not-our-mac` probe carries: a station that is not
/// on this bench, so a frame addressed to it is addressed to nobody the
/// appliance is. Checked against the bench for the same reason as above.
const FOREIGN_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x99, 0x99, 0x99];

/// The station the harness plays on the management wire.
///
/// The one address on the bench the document does not name, and the reason is the
/// port itself: it is not in the router's port set, so it has no `<neighbour>`
/// for a station to be. Its *address* is derived from the management prefix
/// (`crate::topology`); only this MAC is the harness's own, and the tests below
/// hold it to belonging to nothing on either bench.
const MANAGEMENT_STATION_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0c];

/// The identifier, sequence and payload the echo request carries, and so exactly
/// what its reply must carry back (RFC 792). None of the three is derivable from
/// the frame the appliance received, so a reply that reproduces all three
/// reproduces the request rather than a shape.
const ECHO_IDENTIFIER: u16 = 0x4c46;
const ECHO_SEQUENCE: u16 = 0x2711;
const ECHO_PAYLOAD: &[u8] = b"LFW-PROBE/mgmt-echo-0123456789";

/// The TTL an echo reply is expected to leave with. It is not the request's
/// decremented: a reply is a new datagram, and this is what
/// `net_headers::EchoReply::TTL` puts on one.
const ECHO_REPLY_TTL: u8 = 64;

/// The management HTTP port the appliance listens on, and the whole of what a
/// station may open a connection to (`lfw_ip_endpoint::MANAGEMENT_PORT`). Stated
/// here rather than imported, because a client that took the port from the code
/// under test could not catch that code listening somewhere else.
const MANAGEMENT_TCP_PORT: u16 = 80;

/// The ephemeral port this harness's client opens from, and the initial sequence
/// number it opens with.
///
/// The client's own number may be fixed — nothing about the contract depends on
/// it being unpredictable — but it is deliberately *not* round: a sequence
/// arithmetic error that dropped or duplicated the low bits would still produce a
/// plausible-looking number from a round one.
const CLIENT_PORT: u16 = 0xc350;
const CLIENT_ISN: u32 = 0x3b9a_ca07;

/// The request the client sends over the connection.
///
/// It is a real scrape rather than an opaque payload, so what the appliance
/// answers with is a real exposition — tens of kibibytes over twenty-odd
/// segments, which is what makes this exchange a test of the *stream* rather
/// than of one segment. The one scenario that judges the exposition's contents
/// points `curl` at the endpoint instead (`crate::metrics_contract`); what is
/// judged here is every field of every segment that carries it.
const TCP_REQUEST: &[u8] = b"GET /metrics HTTP/1.1\r\nHost: librefirewall\r\n\r\n";

/// What a 200 response begins with, matched as the exact prefix of the first
/// body bytes rather than searched for.
const HTTP_OK: &[u8] = b"HTTP/1.1 200 OK\r\n";

/// The window the client advertises. Comfortably above one segment and well
/// below the response, so the exchange is carried by acknowledgements opening
/// the window again — which is the multi-segment path a single-segment reply
/// would never reach.
const CLIENT_WINDOW: u16 = 8192;

/// Scrapes the metrics scenario takes, and why it is not one: a scrape cannot
/// contain the response it is, so the second is what carries the first's
/// request and response (`crate::metrics_contract`).
const SCRAPES: usize = 2;

/// Response bytes the client will hold before it calls the appliance broken.
///
/// A bound on the harness rather than on the appliance: `Content-Length` says
/// how long the response is and the client stops there, so this only catches a
/// node that keeps sending past what it declared.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

const TCP_PROTOCOL: u8 = 6;
const TCP_HEADER_LEN: usize = 20;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

const ARP_ETHERTYPE: u16 = 0x0806;
const ARP_PAYLOAD_LEN: usize = 28;
const ARP_FRAME_LEN: usize = ETHERNET_HEADER_LEN + ARP_PAYLOAD_LEN;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const ICMP_PROTOCOL: u8 = 1;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_HEADER_LEN: usize = 8;

/// The lengths of the frames injected into the management port, and the whole of
/// what the console's byte total is judged against.
///
/// **Four different lengths, none of them a multiple of another**, because that
/// is what makes the byte total evidence: a domain that summed a constant, or
/// summed the descriptor's offset, or counted notifications rather than frames,
/// reproduces the frame count and cannot reproduce 352. All four are at or above
/// the 60-byte Ethernet minimum, so nothing pads them and the length QEMU
/// delivers is the length written.
const MANAGEMENT_FRAMES: [usize; 4] = [60, 64, 100, 128];

/// The marker every *opaque* management frame carries, so a frame of this
/// harness's on that wire is never confused with a dataplane probe's — and so a
/// frame coming back on the management port is attributable rather than merely
/// unexpected.
///
/// It is deliberately not a prefix of [`ECHO_PAYLOAD`]: the two must be
/// distinguishable as byte strings, or a returned echo reply would read as an
/// opaque frame the endpoint should never have answered.
const MANAGEMENT_MARKER: &[u8] = b"LFW-PROBE/mgmt-opaque";

/// The UDP port pair every probe uses. Fixed rather than varied per probe: the
/// payload marker is what attributes a delivery, so a second varying field
/// would only add a way for two probes to become confusable.
const SOURCE_PORT: u16 = 4444;
const DESTINATION_PORT: u16 = 5000;

/// The TTL a routed probe is injected with, chosen well above the one hop it
/// takes so the decrement is visible rather than decisive.
const INJECTED_TTL: u8 = 64;

/// A UDP-over-IPv4 Ethernet frame as fields: what an endpoint puts on the wire,
/// and — with the next hop's MAC pair and one less TTL — the shape the routed
/// result must have.
#[derive(Clone, Debug, PartialEq, Eq)]
struct UdpPacket {
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    payload: Vec<u8>,
}

impl UdpPacket {
    /// Serialize to the bytes an endpoint's NIC would put on the wire, padded
    /// to the 60-byte Ethernet minimum. The IPv4 total length counts only the
    /// datagram, so any padding is bytes L3 disclaims — which is what a real
    /// endpoint emits and what a router must carry unread.
    fn build(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(MIN_UDP_FRAME + self.payload.len());
        frame.extend_from_slice(&self.destination_mac);
        frame.extend_from_slice(&self.source_mac);
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());

        let datagram_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + self.payload.len();
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(datagram_len as u16).to_be_bytes());
        ip[8] = self.ttl;
        ip[9] = UDP_PROTOCOL;
        ip[12..16].copy_from_slice(&self.source);
        ip[16..20].copy_from_slice(&self.destination);
        let checksum = header_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);

        frame.extend_from_slice(&self.source_port.to_be_bytes());
        frame.extend_from_slice(&self.destination_port.to_be_bytes());
        frame.extend_from_slice(&((UDP_HEADER_LEN + self.payload.len()) as u16).to_be_bytes());
        // No UDP checksum, which IPv4 permits and which keeps the datagram's
        // correctness a property of the header this harness recomputes alone.
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&self.payload);

        if frame.len() < MIN_ETHERNET_FRAME {
            frame.resize(MIN_ETHERNET_FRAME, 0);
        }
        frame
    }

    /// Read `frame` back into its fields, validating the header checksum and
    /// every length the field view rests on.
    ///
    /// # Errors
    /// [`FrameDefect`], carrying the values that made the frame something other
    /// than the UDP-over-IPv4 packet the routed contract is stated in.
    fn decode(frame: &[u8]) -> Result<Self, FrameDefect> {
        let too_short = FrameDefect::TooShort {
            needed: MIN_UDP_FRAME,
            got: frame.len(),
        };
        let Some((ethernet, after_ethernet)) = frame.split_first_chunk::<ETHERNET_HEADER_LEN>()
        else {
            return Err(too_short);
        };
        let [
            dm0,
            dm1,
            dm2,
            dm3,
            dm4,
            dm5,
            sm0,
            sm1,
            sm2,
            sm3,
            sm4,
            sm5,
            et_high,
            et_low,
        ] = *ethernet;
        let ether_type = u16::from_be_bytes([et_high, et_low]);
        if ether_type != IPV4_ETHERTYPE {
            return Err(FrameDefect::NotIpv4 { ether_type });
        }

        let Some((ip, after_ip)) = after_ethernet.split_first_chunk::<IPV4_HEADER_LEN>() else {
            return Err(too_short);
        };
        let [
            version_ihl,
            _dscp_ecn,
            tl_high,
            tl_low,
            _id_high,
            _id_low,
            _flags_high,
            _flags_low,
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
        ] = *ip;
        let version = version_ihl >> 4;
        if version != 4 {
            return Err(FrameDefect::VersionNotFour { version });
        }
        let ihl = version_ihl & 0x0f;
        if ihl != 5 {
            return Err(FrameDefect::OptionsPresent { ihl });
        }
        let found = u16::from_be_bytes([ck_high, ck_low]);
        let computed = header_checksum(ip);
        if found != computed {
            return Err(FrameDefect::HeaderChecksumInvalid { found, computed });
        }
        if protocol != UDP_PROTOCOL {
            return Err(FrameDefect::NotUdp { protocol });
        }

        let total_length = u16::from_be_bytes([tl_high, tl_low]);
        let Some(payload_len) =
            usize::from(total_length).checked_sub(IPV4_HEADER_LEN + UDP_HEADER_LEN)
        else {
            return Err(FrameDefect::TotalLengthBelowHeaders { total_length });
        };
        let Some((udp, after_udp)) = after_ip.split_first_chunk::<UDP_HEADER_LEN>() else {
            return Err(too_short);
        };
        let [
            sp_high,
            sp_low,
            dp_high,
            dp_low,
            ul_high,
            ul_low,
            uc_high,
            uc_low,
        ] = *udp;
        let udp_length = u16::from_be_bytes([ul_high, ul_low]);
        let expected_udp_length = (UDP_HEADER_LEN + payload_len) as u16;
        if udp_length != expected_udp_length {
            return Err(FrameDefect::UdpLengthDisagrees {
                udp_length,
                total_length,
            });
        }
        let udp_checksum = u16::from_be_bytes([uc_high, uc_low]);
        if udp_checksum != 0 {
            return Err(FrameDefect::UdpChecksumAdded { udp_checksum });
        }
        let Some(payload) = after_udp.get(..payload_len) else {
            return Err(FrameDefect::TotalLengthBeyondFrame {
                total_length,
                frame_len: frame.len(),
            });
        };

        Ok(Self {
            destination_mac: [dm0, dm1, dm2, dm3, dm4, dm5],
            source_mac: [sm0, sm1, sm2, sm3, sm4, sm5],
            source: [s0, s1, s2, s3],
            destination: [d0, d1, d2, d3],
            source_port: u16::from_be_bytes([sp_high, sp_low]),
            destination_port: u16::from_be_bytes([dp_high, dp_low]),
            ttl,
            payload: payload.to_vec(),
        })
    }
}

/// Why a delivered frame is not the UDP-over-IPv4 packet the routed contract is
/// stated in. Each variant carries the values that made it one, so a delivery
/// that never reaches the field comparison still names what was wrong with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameDefect {
    TooShort { needed: usize, got: usize },
    NotIpv4 { ether_type: u16 },
    VersionNotFour { version: u8 },
    OptionsPresent { ihl: u8 },
    HeaderChecksumInvalid { found: u16, computed: u16 },
    NotUdp { protocol: u8 },
    TotalLengthBelowHeaders { total_length: u16 },
    TotalLengthBeyondFrame { total_length: u16, frame_len: usize },
    UdpLengthDisagrees { udp_length: u16, total_length: u16 },
    UdpChecksumAdded { udp_checksum: u16 },
}

impl fmt::Display for FrameDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { needed, got } => {
                write!(f, "{got} bytes is short of the {needed} a datagram needs")
            }
            Self::NotIpv4 { ether_type } => write!(f, "EtherType 0x{ether_type:04x} is not IPv4"),
            Self::VersionNotFour { version } => write!(f, "IP version {version} is not 4"),
            Self::OptionsPresent { ihl } => write!(f, "IHL {ihl} carries options"),
            Self::HeaderChecksumInvalid { found, computed } => write!(
                f,
                "header checksum 0x{found:04x} should have been 0x{computed:04x}"
            ),
            Self::NotUdp { protocol } => write!(f, "IP protocol {protocol} is not UDP"),
            Self::TotalLengthBelowHeaders { total_length } => write!(
                f,
                "total length {total_length} is below the {} bytes of IPv4 and UDP header",
                IPV4_HEADER_LEN + UDP_HEADER_LEN
            ),
            Self::TotalLengthBeyondFrame {
                total_length,
                frame_len,
            } => write!(
                f,
                "total length {total_length} exceeds the {frame_len}-byte frame"
            ),
            Self::UdpLengthDisagrees {
                udp_length,
                total_length,
            } => write!(
                f,
                "UDP length {udp_length} contradicts the IPv4 total length {total_length}"
            ),
            Self::UdpChecksumAdded { udp_checksum } => write!(
                f,
                "UDP checksum 0x{udp_checksum:04x} was added to a datagram sent without one"
            ),
        }
    }
}

/// The RFC 1071 ones' complement sum, folded and inverted, over a header whose
/// own checksum field is treated as zero — so this yields what the field must
/// hold whatever it currently holds.
///
/// Written straightforwardly and independently of the guest's implementation:
/// the value of the check is that the two were arrived at separately.
fn header_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    let mut zeroed = *header;
    zeroed[10] = 0;
    zeroed[11] = 0;
    let mut sum: u32 = 0;
    for pair in zeroed.chunks(2) {
        let value = match pair {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from_be_bytes([*high, 0]),
            _ => 0,
        };
        sum += u32::from(value);
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

/// What must become of one injected packet.
#[derive(Debug)]
enum Expectation {
    /// It must arrive at endpoint `to`, and be exactly `delivered`. `sent` is
    /// the same packet as it went in, kept so the report can put the TTL the
    /// appliance produced beside the one it was handed.
    Routed {
        to: Endpoint,
        sent: UdpPacket,
        delivered: UdpPacket,
    },
    /// It must never arrive anywhere; `because` names the rule that forbids it,
    /// so a wrongly delivered packet says which one the guest broke — and the
    /// report says which one each refusal demonstrates.
    Dropped { because: &'static str },
}

/// One injected packet and the single thing it proves.
#[derive(Debug)]
struct Probe {
    /// Names the probe in a verdict.
    name: &'static str,
    /// The bytes that distinguish this probe's frames from every other probe's,
    /// so a delivery is attributed to the packet that caused it and a stray can
    /// never satisfy the wrong assertion.
    marker: &'static [u8],
    /// The endpoint that injects it, rather than its port alone: the report
    /// names both ends of a probe's path, and a port number recovers the
    /// endpoint only through a lookup that can fail.
    from: Endpoint,
    frame: Vec<u8>,
    expectation: Expectation,
}

impl Probe {
    /// Judge one frame that carried this probe's marker back to the harness.
    ///
    /// # Errors
    /// The verdict, naming this probe and — where the delivery differs from the
    /// contract — every field it differs in. A hex dump would say the frame was
    /// wrong; naming the field says whether the router rewrote the wrong MAC,
    /// failed to decrement, or corrupted the payload.
    fn judge(&self, egress: usize, frame: &[u8]) -> Result<Delivery, String> {
        let name = self.name;
        let (expected_egress, expected) = match &self.expectation {
            Expectation::Dropped { because } => {
                return Err(format!(
                    "probe {name} came back on port{egress}, but {because}, so the appliance \
                     must never put it on a wire"
                ));
            }
            Expectation::Routed { to, delivered, .. } => (to.port, delivered),
        };
        if egress != expected_egress {
            return Err(format!(
                "probe {name} was delivered on port{egress}, but the route it takes puts it on \
                 port{expected_egress}"
            ));
        }

        // Decoded before the whole-frame comparison rather than after it, so an
        // accepted delivery is described by fields read back off the wire; a
        // frame that only matched byte for byte would otherwise have to be
        // reported from the expectation it matched.
        let observed = match UdpPacket::decode(frame) {
            Ok(packet) => packet,
            Err(defect) => {
                return Err(format!(
                    "probe {name}: the frame delivered on port{egress} is not a well-formed \
                     datagram: {defect}"
                ));
            }
        };
        let fields = differences(expected, &observed);
        if !fields.is_empty() {
            return Err(format!(
                "probe {name}: the frame delivered on port{egress} departs from the routed \
                 contract in {}",
                fields.join("; ")
            ));
        }
        let expected_bytes = expected.build();
        if frame != expected_bytes {
            // Every field the contract is written in agrees, so what differs is
            // a byte the field view does not model — Ethernet padding, an IPv4
            // identification or flag the router must carry through untouched.
            return Err(format!(
                "probe {name}: the frame delivered on port{egress} carries every field of the \
                 routed contract but differs outside them: {}",
                byte_difference(&expected_bytes, frame)
            ));
        }
        Ok(Delivery {
            packet: observed,
            bytes: frame.len(),
        })
    }
}

/// One accepted delivery as it arrived: the frame's own fields, and its length
/// on the wire including any padding the field view disclaims.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Delivery {
    packet: UdpPacket,
    bytes: usize,
}

/// What one probe was seen to do. The four states are what a reader has to be
/// able to tell apart: a delivery that met the contract, a refusal that is the
/// contract, a routed probe that never came back, and the one probe whose
/// delivery broke the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    Delivered,
    Refused,
    Missing,
    Broke,
}

impl Seen {
    fn label(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Refused => "dropped",
            Self::Missing => "missing",
            Self::Broke => "failed",
        }
    }
}

/// One rendered line of the traffic report.
#[derive(Debug)]
struct Row {
    seen: Seen,
    name: &'static str,
    path: String,
    detail: String,
}

/// What the injected probes were observed to do over one boot.
#[derive(Debug)]
pub struct TrafficReport {
    rows: Vec<Row>,
    /// The bench the rows are read against, kept so the topology block heading
    /// the table is the one the run was actually stated between.
    endpoints: [Endpoint; PORTS],
}

impl TrafficReport {
    /// Derive the report from what the run recorded: the delivery accepted for
    /// each probe, if any, and the index of the probe whose delivery ended the
    /// run. Deriving it here rather than accumulating lines as the run goes
    /// keeps one place deciding what each state means.
    fn new(
        endpoints: [Endpoint; PORTS],
        probes: &[Probe],
        deliveries: &[Option<Delivery>],
        broke: Option<usize>,
    ) -> Self {
        let rows = probes
            .iter()
            .zip(deliveries)
            .enumerate()
            .map(|(index, (probe, delivery))| {
                let routed = match &probe.expectation {
                    Expectation::Routed { to, sent, .. } => Some((to, sent)),
                    Expectation::Dropped { .. } => None,
                };
                let path = match routed {
                    Some((to, _)) => format!("{}->{}", probe.from.name(), to.name()),
                    // Nothing left the appliance, so naming a far end would
                    // claim a journey the packet never made.
                    None => format!("{}->.", probe.from.name()),
                };
                let (seen, detail) = match (broke == Some(index), delivery, &probe.expectation) {
                    (true, _, _) => (Seen::Broke, "see the verdict below".to_owned()),
                    (false, Some(delivery), Expectation::Routed { sent, .. }) => {
                        (Seen::Delivered, describe(delivery, sent.ttl))
                    }
                    // A refused probe that arrived is the `broke` case above,
                    // so a delivery here can only belong to a routed probe.
                    (false, Some(delivery), Expectation::Dropped { because }) => (
                        Seen::Broke,
                        format!("{because}, yet {} bytes came back", delivery.bytes),
                    ),
                    (false, None, Expectation::Routed { .. }) => {
                        (Seen::Missing, "never came back".to_owned())
                    }
                    (false, None, Expectation::Dropped { because }) => {
                        (Seen::Refused, (*because).to_owned())
                    }
                };
                Row {
                    seen,
                    name: probe.name,
                    path,
                    detail,
                }
            })
            .collect();
        Self { rows, endpoints }
    }

    /// The topology the probes cross, then one line per probe. Printed on a
    /// successful run because a boolean is not evidence that two endpoints on
    /// separate subnets exchanged anything.
    pub fn render(&self) -> String {
        let mut out = String::from("  librefirewall routed smoke test");
        if !self.finished() {
            // A run that ended early never reached the window a refusal is
            // judged over, so its `dropped` rows report what had not come back
            // rather than what the appliance refused.
            out.push_str(" (unfinished: a dropped row is only what had not come back yet)");
        }
        out.push('\n');
        for endpoint in self.endpoints {
            out.push_str(&format!(
                "    endpoint {}  {}  {}  --  port {}  {}\n",
                endpoint.name(),
                ipv4(endpoint.address),
                mac(endpoint.mac),
                endpoint.port,
                mac(endpoint.gateway_mac),
            ));
        }
        out.push('\n');
        let width = self
            .rows
            .iter()
            .map(|row| row.name.len())
            .max()
            .unwrap_or(0);
        for row in &self.rows {
            out.push_str(&format!(
                "  {:<9}  {:<width$}  {}  {}\n",
                row.seen.label(),
                row.name,
                row.path,
                row.detail,
            ));
        }
        out
    }

    /// The same run as one clause. Counts only, and no claim about whether they
    /// are the right counts: the caller ran the contract and is the one that
    /// can say so.
    pub fn summary(&self) -> String {
        format!(
            "{} routed, {} dropped",
            self.count(Seen::Delivered),
            self.count(Seen::Refused)
        )
    }

    fn count(&self, seen: Seen) -> usize {
        self.rows.iter().filter(|row| row.seen == seen).count()
    }

    /// Whether every probe reached an end state the contract defines. A run
    /// that broke, or that is still waiting on a direction, reached neither.
    fn finished(&self) -> bool {
        self.rows
            .iter()
            .all(|row| matches!(row.seen, Seen::Delivered | Seen::Refused))
    }
}

/// Render one delivery as the frame that arrived, beside the TTL it was handed.
/// Every other number is the wire's own.
fn describe(delivery: &Delivery, sent_ttl: u8) -> String {
    let packet = &delivery.packet;
    format!(
        "{}:{} -> {}:{}  ttl {sent_ttl}->{}  mac {}->{}  {} bytes",
        ipv4(packet.source),
        packet.source_port,
        ipv4(packet.destination),
        packet.destination_port,
        packet.ttl,
        mac(packet.source_mac),
        mac(packet.destination_mac),
        delivery.bytes,
    )
}

/// Name every field in which `observed` departs from `expected`.
fn differences(expected: &UdpPacket, observed: &UdpPacket) -> Vec<String> {
    let mut found = Vec::new();
    if observed.destination_mac != expected.destination_mac {
        found.push(format!(
            "destination MAC {} (expected {})",
            mac(observed.destination_mac),
            mac(expected.destination_mac)
        ));
    }
    if observed.source_mac != expected.source_mac {
        found.push(format!(
            "source MAC {} (expected {})",
            mac(observed.source_mac),
            mac(expected.source_mac)
        ));
    }
    if observed.source != expected.source {
        found.push(format!(
            "source address {} (expected {})",
            ipv4(observed.source),
            ipv4(expected.source)
        ));
    }
    if observed.destination != expected.destination {
        found.push(format!(
            "destination address {} (expected {})",
            ipv4(observed.destination),
            ipv4(expected.destination)
        ));
    }
    if observed.source_port != expected.source_port {
        found.push(format!(
            "source port {} (expected {})",
            observed.source_port, expected.source_port
        ));
    }
    if observed.destination_port != expected.destination_port {
        found.push(format!(
            "destination port {} (expected {})",
            observed.destination_port, expected.destination_port
        ));
    }
    if observed.ttl != expected.ttl {
        found.push(format!("TTL {} (expected {})", observed.ttl, expected.ttl));
    }
    if observed.payload != expected.payload {
        found.push(format!(
            "payload: {}",
            byte_difference(&expected.payload, &observed.payload)
        ));
    }
    found
}

/// Describe how two byte strings differ without printing either: the length,
/// and the offset where they part company.
fn byte_difference(expected: &[u8], observed: &[u8]) -> String {
    let at = expected
        .iter()
        .zip(observed)
        .position(|(left, right)| left != right);
    match at {
        Some(offset) => format!(
            "{} bytes differing from the expected {} at offset {offset}",
            observed.len(),
            expected.len()
        ),
        None => format!(
            "{} bytes against the expected {}, agreeing as far as the shorter runs",
            observed.len(),
            expected.len()
        ),
    }
}

fn mac(address: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = address;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

fn ipv4(address: [u8; 4]) -> String {
    let [a, b, c, d] = address;
    format!("{a}.{b}.{c}.{d}")
}

/// The packets one boot injects into `topology`'s bench, and what each of them
/// proves.
///
/// Two must be routed, in opposite directions, and four must be refused: a
/// packet that cannot survive a hop, one not addressed to the ingress port,
/// one for a destination no interface prefix covers, and the broadcast frame
/// the retired L2 contract required to be forwarded byte-identical.
///
/// The probes are named by port rather than by endpoint, because the endpoints
/// are the document's and a document names them what it likes; a port is the
/// build's own fact and reads the same under every bench.
///
/// # Errors
/// A bench on which one of the two refusals would be the appliance's to make
/// differently — the appliance has a route for [`UNROUTED_DESTINATION`], or
/// something on the bench carries [`FOREIGN_MAC`]. Injecting either anyway
/// would make the probe assert a rule the document does not impose.
fn probes(topology: &Topology) -> Result<Vec<Probe>, String> {
    if topology.covers(UNROUTED_DESTINATION) {
        return Err(format!(
            "the configuration document gives the appliance a route for {}, so the no-route \
             probe would be asserting a refusal the appliance is right not to make",
            ipv4(UNROUTED_DESTINATION)
        ));
    }
    if topology.carries_mac(FOREIGN_MAC) {
        return Err(format!(
            "the configuration document puts {} on the bench, so the not-our-mac probe would be \
             addressed to something the appliance is",
            mac(FOREIGN_MAC)
        ));
    }

    let [a, b] = topology.endpoints();
    let a_to_b = datagram(a, b, INJECTED_TTL, b"LFW-PROBE/routed-0-to-1");
    Ok(vec![
        routed(
            "routed-0-to-1",
            b"LFW-PROBE/routed-0-to-1",
            a,
            b,
            a_to_b.clone(),
        ),
        routed(
            "routed-1-to-0",
            b"LFW-PROBE/routed-1-to-0",
            b,
            a,
            datagram(b, a, INJECTED_TTL, b"LFW-PROBE/routed-1-to-0"),
        ),
        dropped(
            "ttl-one-0-to-1",
            b"LFW-PROBE/ttl-one-0-to-1",
            a,
            "a TTL of 1 cannot survive a hop",
            UdpPacket {
                ttl: 1,
                payload: b"LFW-PROBE/ttl-one-0-to-1".to_vec(),
                ..a_to_b.clone()
            },
        ),
        dropped(
            "not-our-mac",
            b"LFW-PROBE/not-our-mac",
            a,
            "its destination MAC is another station's, so it is not addressed to the appliance",
            UdpPacket {
                destination_mac: FOREIGN_MAC,
                payload: b"LFW-PROBE/not-our-mac".to_vec(),
                ..a_to_b.clone()
            },
        ),
        dropped(
            "no-route",
            b"LFW-PROBE/no-route",
            a,
            "no interface prefix covers the destination",
            UdpPacket {
                destination: UNROUTED_DESTINATION,
                payload: b"LFW-PROBE/no-route".to_vec(),
                ..a_to_b
            },
        ),
        Probe {
            name: "legacy-l2-broadcast",
            marker: b"LFW-PROBE/legacy-l2-broadcast",
            from: a,
            frame: legacy_broadcast_frame(b"LFW-PROBE/legacy-l2-broadcast"),
            expectation: Expectation::Dropped {
                because: "it is neither IPv4 nor addressed to the port's own MAC",
            },
        },
    ])
}

/// The datagram `from` sends `to`: addressed at L2 to the appliance interface
/// it is attached to, and at L3 to the far endpoint.
fn datagram(from: Endpoint, to: Endpoint, ttl: u8, marker: &[u8]) -> UdpPacket {
    UdpPacket {
        destination_mac: from.gateway_mac,
        source_mac: from.mac,
        source: from.address,
        destination: to.address,
        source_port: SOURCE_PORT,
        destination_port: DESTINATION_PORT,
        ttl,
        payload: marker.to_vec(),
    }
}

/// A probe the appliance must route, and the delivery it must produce: the
/// packet as injected with exactly the three changes a hop makes — the far
/// endpoint's MAC, the far interface's MAC, and one less TTL. Deriving the
/// expectation from the injection rather than writing it out is what makes
/// "every other byte unchanged" the default the contract has to break.
fn routed(
    name: &'static str,
    marker: &'static [u8],
    from: Endpoint,
    to: Endpoint,
    sent: UdpPacket,
) -> Probe {
    let delivered = UdpPacket {
        destination_mac: to.mac,
        source_mac: to.gateway_mac,
        ttl: sent.ttl - 1,
        ..sent.clone()
    };
    Probe {
        name,
        marker,
        from,
        frame: sent.build(),
        expectation: Expectation::Routed {
            to,
            sent,
            delivered,
        },
    }
}

fn dropped(
    name: &'static str,
    marker: &'static [u8],
    from: Endpoint,
    because: &'static str,
    sent: UdpPacket,
) -> Probe {
    Probe {
        name,
        marker,
        from,
        frame: sent.build(),
        expectation: Expectation::Dropped { because },
    }
}

/// The frame the retired L2 contract required to be forwarded byte-identical: a
/// broadcast frame under the local-experimental EtherType 0x88B5. It is kept
/// precisely because it must now be refused — a router carries what is
/// addressed to it and carries IPv4, and this is neither — so the change of
/// contract is a test rather than a note.
fn legacy_broadcast_frame(marker: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(MIN_ETHERNET_FRAME);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&LOCAL_EXPERIMENTAL_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(marker);
    if frame.len() < MIN_ETHERNET_FRAME {
        frame.resize(MIN_ETHERNET_FRAME, 0);
    }
    frame
}

/// What a boot must prove. Both variants inject the same packets into the same
/// ports; they differ in which observation is success.
pub enum BootContract<'a> {
    /// Both routed packets must arrive on the far port rewritten exactly for
    /// their next hop, and no refused packet may arrive at all.
    Routed,
    /// No injected packet may come back in any form (nothing bootable may have
    /// started) and the guest must emit `marker` on the serial channel. Used
    /// for the boot manager's halt path, where the absence of a dataplane is
    /// the point.
    Halted {
        /// The structured record whose presence proves the halt path was
        /// reached. It is matched as an exact byte substring, never as prose.
        marker: &'a str,
    },
}

/// The non-QEMU inputs of one boot test: what it must prove and where its run
/// log goes.
pub struct BootTest<'a> {
    /// The contract the boot is judged against.
    pub contract: BootContract<'a>,
    /// Path of the run log, whose parent directories are created.
    pub log_path: &'a Path,
    /// Harness-generated header written ahead of the captured serial output,
    /// recording how QEMU was configured. Reading a failure log must never
    /// require guessing whether the run was accelerated.
    pub log_header: &'a str,
    /// The bench, read out of the configuration document the image under test
    /// was built from. It decides every address the probes carry, so a boot can
    /// only ever be judged against the addressing the appliance in it was
    /// actually configured with.
    pub topology: &'a Topology,
}

/// How the management port is attached, which is the one thing that differs
/// between the frame-level scenarios and the one that points a real client at
/// the endpoint.
///
/// The two dataplane ports are socket-backed in both, so the routed contract is
/// asserted in the same boot either way: what changes is whether the harness
/// plays a *station* on the management wire or lets a host process open a TCP
/// connection to the appliance through QEMU's own stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementBacking {
    /// A host-controlled socket. The harness composes and decodes every frame,
    /// which is what makes the ARP, ICMP and TCP contracts field comparisons.
    Socket,
    /// QEMU's user-mode (SLIRP) stack with a host port forward to the
    /// endpoint's own address and port, so `curl` — a client nothing in this
    /// repository wrote — can be pointed at it. Nothing at frame level is
    /// asserted on this wire: the harness never sees one.
    UserNetwork {
        /// The loopback port on the host side of the forward, reserved by
        /// [`reserve_host_port`] before QEMU is told about it.
        host_port: u16,
    },
}

impl ManagementBacking {
    /// Whether the harness holds a socket for the management port, and so
    /// whether there is a stream to accept and a station to play.
    const fn is_socket(self) -> bool {
        matches!(self, Self::Socket)
    }
}

/// The host side of every NIC port: one loopback listener per socket-backed
/// port that QEMU's `socket` netdevs dial into, so the port identity of each
/// accepted stream is unambiguous.
///
/// Indexed by [`GuestNic::slot`], so the dataplane ports come first and the
/// management port — where it is socket-backed at all — is the last, which is
/// what makes `MANAGEMENT_SLOT` a valid index into every array in this file
/// that is keyed by it.
pub struct NicBackends {
    listeners: Vec<TcpListener>,
    management: ManagementBacking,
}

/// Where the management port sits in every slot-keyed array here: one past the
/// dataplane ports, exactly as `GuestNic::Management` sits one past them in the
/// PCI slots and the ECAM grants.
const MANAGEMENT_SLOT: usize = PORTS;

impl NicBackends {
    /// Bind one listener per socket-backed port.
    ///
    /// # Errors
    /// A listener that could not be bound, or a host port that could not be
    /// reserved for the forward.
    pub fn new(management: ManagementBacking) -> Result<Self, String> {
        let ports = if management.is_socket() {
            MANAGEMENT_SLOT + 1
        } else {
            MANAGEMENT_SLOT
        };
        let mut listeners = Vec::with_capacity(ports);
        for _ in 0..ports {
            listeners.push(bind_listener()?);
        }
        Ok(Self {
            listeners,
            management,
        })
    }

    /// Append every socket-backed virtio NIC to a QEMU invocation. Each port's
    /// `socket` netdev dials the corresponding host listener; the `-device`
    /// string (PCI address, MAC, no option ROM) is the single definition shared
    /// with interactive runs via [`crate::qemu::nic_device`], which takes a
    /// dataplane port's MAC from `topology`'s interface on it and the management
    /// port's from `crate::qemu::MANAGEMENT_MAC`.
    pub fn apply(&self, command: &mut Command, topology: &Topology) -> Result<(), String> {
        for nic in every_guest_nic() {
            let netdev = match (nic, self.management) {
                (GuestNic::Management, ManagementBacking::UserNetwork { host_port }) => {
                    user_netdev(&nic.netdev_id(), &topology.management(), host_port)
                }
                _ => {
                    let listener = self
                        .listeners
                        .get(nic.slot())
                        .ok_or_else(|| format!("no listener bound for {nic:?}"))?;
                    let tcp = listener
                        .local_addr()
                        .map_err(|error| format!("read listener port: {error}"))?
                        .port();
                    format!("socket,id={},connect=127.0.0.1:{tcp}", nic.netdev_id())
                }
            };
            command
                .arg("-netdev")
                .arg(netdev)
                .arg("-device")
                .arg(crate::qemu::nic_device(topology, nic)?);
        }
        Ok(())
    }
}

/// QEMU's user-mode stack on the management port's own network, with one host
/// port forwarded to the endpoint.
///
/// Every address in it is the configuration document's: the network the port
/// sits on, the station address the appliance answers (the SLIRP gateway speaks
/// from it, and the endpoint refuses an off-link sender), and the endpoint's own
/// address as the forward's target. A literal here would be a bench stated
/// against an address the appliance might not have.
fn user_netdev(id: &str, management: &ManagementPort, host_port: u16) -> String {
    format!(
        "user,id={id},net={}/{},host={},hostfwd=tcp:127.0.0.1:{host_port}-{}:{MANAGEMENT_TCP_PORT}",
        ipv4(management.network()),
        management.prefix_length,
        ipv4(management.station),
        ipv4(management.address),
    )
}

/// Take a loopback port nothing else holds, and let it go again.
///
/// The same trick the NIC listeners use, for the same reason: a fixed port would
/// collide with whatever else is running on a shared runner. There is a window
/// between releasing it and QEMU binding it, and it is accepted — the
/// alternative is handing QEMU a listening socket, which its `hostfwd` does not
/// take.
///
/// # Errors
/// A port that could not be bound.
pub fn reserve_host_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("reserve a host port for the management forward: {error}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("read the reserved host port: {error}"))
}

/// One opaque frame for the management port: addressed at L2 to the port's own
/// MAC from the harness's station, carrying the marker and padded to `len`.
///
/// It is deliberately not a protocol the endpoint answers. Its whole purpose is
/// to be *counted*, so the EtherType is the local-experimental one
/// [`legacy_broadcast_frame`] uses — it names no protocol anything will one day
/// route by accident — and the appliance must take it, count it, and say nothing
/// back. A frame the endpoint answered would make the console's byte total and
/// the reply contract two views of the same event.
fn management_frame(management: &ManagementPort, len: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(len);
    frame.extend_from_slice(&management.mac);
    frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
    frame.extend_from_slice(&LOCAL_EXPERIMENTAL_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(MANAGEMENT_MARKER);
    frame.resize(len, 0);
    frame
}

/// The ARP request the harness asks the management address with: broadcast at
/// L2, from the station's own pair, unpadded at 42 bytes.
///
/// Unpadded on purpose. A real endpoint sees both shapes, and 42 bytes is the one
/// that catches a parser reading a fixed 60-byte payload.
fn management_arp_request(management: &ManagementPort) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
    frame.extend_from_slice(&ARP_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&ARP_REQUEST.to_be_bytes());
    frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
    frame.extend_from_slice(&management.station);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&management.address);
    frame
}

/// The ICMP echo request the harness pings the management address with, from the
/// station's own pair at both layers.
fn management_echo_request(management: &ManagementPort) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(ICMP_HEADER_LEN + ECHO_PAYLOAD.len());
    icmp.push(ICMP_ECHO_REQUEST);
    icmp.push(0);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&ECHO_IDENTIFIER.to_be_bytes());
    icmp.extend_from_slice(&ECHO_SEQUENCE.to_be_bytes());
    icmp.extend_from_slice(ECHO_PAYLOAD);
    let checksum = message_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + icmp.len());
    frame.extend_from_slice(&management.mac);
    frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
    frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    let mut ip = [0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + icmp.len()) as u16).to_be_bytes());
    ip[8] = INJECTED_TTL;
    ip[9] = ICMP_PROTOCOL;
    ip[12..16].copy_from_slice(&management.station);
    ip[16..20].copy_from_slice(&management.address);
    let checksum = header_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&icmp);
    frame
}

/// A TCP segment as fields, read back by this harness's own reader.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TcpFrame {
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    window: u16,
    payload: Vec<u8>,
}

impl TcpFrame {
    /// Whether every flag in `wanted` is set and none in `forbidden` is.
    fn carries(&self, wanted: u8, forbidden: u8) -> bool {
        self.flags & wanted == wanted && self.flags & forbidden == 0
    }
}

/// Read a TCP-over-IPv4 frame, refusing anything that is not one and verifying
/// the pseudo-header checksum the way the station that receives one does.
///
/// # Errors
/// The verdict, naming the value that refused it. The checksum is verified here
/// rather than trusted, because it is the one field of the appliance's own
/// composition that no other assertion below would notice being wrong.
fn decode_tcp(frame: &[u8], management: &ManagementPort) -> Result<TcpFrame, String> {
    let Some(header) = frame.get(..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN) else {
        return Err(format!(
            "{} bytes is short of the {} an IPv4 frame needs",
            frame.len(),
            ETHERNET_HEADER_LEN + IPV4_HEADER_LEN
        ));
    };
    if header[ETHERNET_HEADER_LEN + 9] != TCP_PROTOCOL {
        return Err(format!(
            "the datagram names IP protocol {} rather than TCP",
            header[ETHERNET_HEADER_LEN + 9]
        ));
    }
    let total_length = usize::from(u16::from_be_bytes([
        header[ETHERNET_HEADER_LEN + 2],
        header[ETHERNET_HEADER_LEN + 3],
    ]));
    let Some(segment) = frame.get(
        ETHERNET_HEADER_LEN + IPV4_HEADER_LEN
            ..ETHERNET_HEADER_LEN + total_length.max(IPV4_HEADER_LEN),
    ) else {
        return Err(format!(
            "the datagram claims {total_length} bytes and the frame carries {}",
            frame.len() - ETHERNET_HEADER_LEN
        ));
    };
    let Some(fixed) = segment.get(..TCP_HEADER_LEN) else {
        return Err(format!(
            "{} bytes is short of the {TCP_HEADER_LEN} a TCP header needs",
            segment.len()
        ));
    };
    let data_offset = usize::from(fixed[12] >> 4) * 4;
    if data_offset < TCP_HEADER_LEN || data_offset > segment.len() {
        return Err(format!(
            "the segment names a {data_offset}-byte header inside {} bytes",
            segment.len()
        ));
    }
    let computed = tcp_checksum(&management.address, &management.station, segment);
    if computed != 0 {
        return Err(format!(
            "the segment's checksum does not verify: the ones' complement total over the \
             pseudo-header and the segment is {computed:#06x} rather than zero"
        ));
    }
    Ok(TcpFrame {
        source_port: u16::from_be_bytes([fixed[0], fixed[1]]),
        destination_port: u16::from_be_bytes([fixed[2], fixed[3]]),
        sequence: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
        acknowledgement: u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]),
        flags: fixed[13],
        window: u16::from_be_bytes([fixed[14], fixed[15]]),
        payload: segment.get(data_offset..).unwrap_or_default().to_vec(),
    })
}

/// One TCP segment from this harness's client, as a whole frame on the wire.
///
/// The client's own composition, written from RFC 793 rather than reused from the
/// appliance's builder: a segment built by the code under test and compared
/// against that code's own expectation would agree with itself.
fn tcp_frame(
    management: &ManagementPort,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = Vec::with_capacity(TCP_HEADER_LEN + payload.len());
    segment.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    segment.extend_from_slice(&MANAGEMENT_TCP_PORT.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&acknowledgement.to_be_bytes());
    // Five words of header and no options: the client offers no maximum segment
    // size, so the appliance must fall back on RFC 1122's default rather than on
    // whatever the option would have said.
    segment.push(5 << 4);
    segment.push(flags);
    segment.extend_from_slice(&CLIENT_WINDOW.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    let checksum = tcp_checksum(&management.station, &management.address, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + segment.len());
    frame.extend_from_slice(&management.mac);
    frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
    frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    let mut ip = [0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + segment.len()) as u16).to_be_bytes());
    ip[8] = INJECTED_TTL;
    ip[9] = TCP_PROTOCOL;
    ip[12..16].copy_from_slice(&management.station);
    ip[16..20].copy_from_slice(&management.address);
    let header_checksum = header_checksum(&ip);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&segment);
    frame
}

/// The RFC 793 §3.1 checksum over the pseudo-header and the segment.
///
/// Answers zero for a segment whose own field is consistent, which is what makes
/// one call serve both directions: composing (with the field zero) yields the
/// value to write, and verifying (with the field filled) yields zero.
fn tcp_checksum(source: &[u8; 4], destination: &[u8; 4], segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |pair: [u8; 2]| sum += u32::from(u16::from_be_bytes(pair));
    add([source[0], source[1]]);
    add([source[2], source[3]]);
    add([destination[0], destination[1]]);
    add([destination[2], destination[3]]);
    add([0, TCP_PROTOCOL]);
    add((segment.len() as u16).to_be_bytes());
    for index in 0..segment.len().div_ceil(2) {
        let high = segment[index * 2];
        let low = segment.get(index * 2 + 1).copied().unwrap_or(0);
        add([high, low]);
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    // Lossless: the fold above leaves at most sixteen significant bits.
    !(sum as u16)
}

/// The RFC 1071 ones' complement sum over a whole block whose checksum field is
/// treated as zero, for a message this harness composes.
///
/// [`header_checksum`] is the same arithmetic over a fixed-size IPv4 header; this
/// is the variable-length case, and both are written independently of the
/// appliance's own routine — the value of the check is that the two were arrived
/// at separately.
fn message_checksum(message: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for index in 0..message.len().div_ceil(2) {
        let high = message[index * 2];
        let low = message.get(index * 2 + 1).copied().unwrap_or(0);
        let pair = u16::from_be_bytes([high, low]);
        // The field is part of its own input, so it is summed as zero.
        if index != 1 {
            sum += u32::from(pair);
        }
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

/// What one boot puts on the management wire: the frames, and what the appliance
/// owes in return.
struct ManagementProbe {
    /// In injection order: the opaque frames, then the ARP request, then the
    /// echo request.
    frames: Vec<Vec<u8>>,
    /// The bench the expectations are stated against.
    port: ManagementPort,
}

/// Which of the replies a frame off the management wire was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagementReply {
    Arp,
    Echo,
    /// One step of the TCP exchange, named by the step it completed.
    Tcp(TcpStep),
}

/// Where the client's connection has got to.
///
/// The exchange is a *sequence*, and that is the point: a stack can answer every
/// segment shape correctly and still be unable to carry a connection. Each step
/// below both asserts what came back and composes what goes out next, so the
/// contract is met only by walking the whole of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpStep {
    /// Nothing sent yet: the client waits until the ARP and echo replies have
    /// been accepted, so a failure in either is reported as itself.
    Unopened,
    /// `SYN` sent; the appliance owes a `SYN-ACK`.
    AwaitSynAck,
    /// The request is out; the appliance owes a response and then its own `FIN`,
    /// `Connection: close` obliging it to close first.
    AwaitResponse,
    /// The appliance closed and the client answered with its own `FIN`; the
    /// appliance owes the acknowledgement of it.
    AwaitLastAck,
    /// Both halves are closed.
    Closed,
}

impl TcpStep {
    /// What the appliance still owes, as a clause for a verdict.
    fn outstanding(self) -> &'static str {
        match self {
            Self::Unopened => "the TCP exchange has not been started",
            Self::AwaitSynAck => "the TCP SYN-ACK",
            Self::AwaitResponse => "the rest of the HTTP response, and the FIN after it",
            Self::AwaitLastAck => "the acknowledgement of the client's own FIN",
            Self::Closed => "none",
        }
    }
}

/// The client's own end of the connection.
///
/// It is deliberately not a TCP stack: the wire between the harness and QEMU is a
/// host socket, so it is lossless and in-order, and a client with a
/// retransmission timer or a congestion window would be testing itself. What it
/// does have is the whole of the sequence-number arithmetic, because that is the
/// half the appliance's answers are checked against.
#[derive(Clone, Debug)]
struct TcpClient {
    step: TcpStep,
    /// The next sequence number this client will send.
    sequence: u32,
    /// What it expects to receive next, learned from the appliance's own numbers.
    expect: u32,
    /// The appliance's initial sequence number, kept so a caller can compare it
    /// across boots: a constant one would be an off-path injection primitive
    /// (RFC 6528), and one boot's number alone cannot show that it is not.
    peer_isn: Option<u32>,
    /// The response as it arrives, segment by segment. Accumulated rather than
    /// judged per segment because a response *is* a stream: what must be right
    /// is the bytes in order, and a per-segment check could not tell a correct
    /// stream from one whose segments each look plausible.
    response: Vec<u8>,
    /// Set by the appliance's own `FIN`, which `Connection: close` obliges.
    peer_closed: bool,
    /// Segments accepted, and what the last one was. Kept for the verdict alone:
    /// a run that times out mid-exchange is otherwise indistinguishable from one
    /// that never opened, and "it stopped after 47 segments holding 25048 bytes"
    /// is the difference between a close defect and a stream defect.
    segments: usize,
    last_segment: Option<(u8, u32, u32, usize)>,
}

impl TcpClient {
    fn new() -> Self {
        Self {
            step: TcpStep::Unopened,
            sequence: CLIENT_ISN,
            expect: 0,
            peer_isn: None,
            response: Vec::new(),
            peer_closed: false,
            segments: 0,
            last_segment: None,
        }
    }

    /// What this client has seen, as a clause for a verdict.
    fn seen(&self) -> String {
        match self.last_segment {
            None => String::from("no segment has come back at all"),
            Some((flags, sequence, acknowledgement, payload)) => format!(
                "{} segments came back holding {} response bytes, the last with flags {flags:#04x} \
                 sequence {sequence} acknowledgement {acknowledgement} and {payload} payload \
                 bytes; this client's next sequence is {} and it expects {}",
                self.segments,
                self.response.len(),
                self.sequence,
                self.expect
            ),
        }
    }

    /// The sequence number one past everything this client has sent but its own
    /// `FIN`: the `SYN` and the request.
    fn sent_through_request() -> u32 {
        CLIENT_ISN
            .wrapping_add(1)
            .wrapping_add(TCP_REQUEST.len() as u32)
    }

    /// The head and body of the response, split at the blank line.
    fn split_response(&self) -> Option<(&[u8], &[u8])> {
        let at = self
            .response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")?;
        Some((&self.response[..at + 4], &self.response[at + 4..]))
    }

    /// The `Content-Length` the response states, if its head has arrived whole.
    fn content_length(&self) -> Option<usize> {
        let (head, _) = self.split_response()?;
        let text = core::str::from_utf8(head).ok()?;
        text.lines().skip(1).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
    }
}

impl ManagementProbe {
    /// The two stateless replies as evidence, in the voice of the routed-traffic
    /// lines: a reader sees *that* the port answered and with which values. Every
    /// field printed is one `judge` refused the frame for not carrying, so this is
    /// a rendering of what was proved rather than a second reading of the wire.
    ///
    /// The TCP exchange has a line of its own ([`opened`](Self::opened)), because
    /// it is one connection rather than one reply and the values worth printing
    /// are the ones a whole exchange establishes.
    fn answered(&self, reply: ManagementReply) -> String {
        let port = &self.port;
        match reply {
            // Unreachable: the caller renders a TCP step through `opened`. A line
            // rather than a panic, because a rendering is not a place to fail a
            // run that has otherwise met its contract.
            ManagementReply::Tcp(step) => format!("  answered   tcp-step {step:?}"),
            ManagementReply::Arp => format!(
                "  answered   arp-request           station->mgmt  who-has {} tell {}  \
                 is-at {}",
                ipv4(port.address),
                ipv4(port.station),
                mac(port.mac)
            ),
            ManagementReply::Echo => format!(
                "  answered   icmp-echo-request     station->mgmt  {} -> {}  id {ECHO_IDENTIFIER:#06x} \
                 seq {ECHO_SEQUENCE:#06x}  ttl {ECHO_REPLY_TTL}",
                ipv4(port.station),
                ipv4(port.address)
            ),
        }
    }

    /// Every frame one boot injects, and what it obliges the console to report.
    ///
    /// The count and the byte total are derived from the frames themselves, so the
    /// console contract cannot come to be stated against a second copy of them.
    fn new(management: ManagementPort) -> (Self, ManagementInjection) {
        let mut frames: Vec<Vec<u8>> = MANAGEMENT_FRAMES
            .iter()
            .map(|len| management_frame(&management, *len))
            .collect();
        frames.push(management_arp_request(&management));
        frames.push(management_echo_request(&management));
        let injection = ManagementInjection {
            frames: frames.len(),
            bytes: frames.iter().map(|frame| frame.len() as u64).sum(),
        };
        (
            Self {
                frames,
                port: management,
            },
            injection,
        )
    }

    /// Judge one frame that came back on the management wire.
    ///
    /// # Errors
    /// The verdict. Every frame on this wire is either one of the two replies the
    /// endpoint owes or a frame the port must never have put there — a dataplane
    /// probe that leaked across the isolation boundary, or something the
    /// appliance originated that nothing asked for.
    fn judge(
        &self,
        frame: &[u8],
        probes: &[Probe],
        client: &mut TcpClient,
    ) -> Result<ManagementReply, String> {
        for probe in probes {
            if contains(frame, probe.marker) {
                return Err(format!(
                    "probe {} came back on the management port. CONCEPT §9.1 isolates that port \
                     from the dataplane, and no domain is granted a region on both sides of it, so \
                     a dataplane frame reaching it means one of those grants has changed",
                    probe.name
                ));
            }
        }
        if contains(frame, MANAGEMENT_MARKER) {
            return Err(format!(
                "an opaque management frame of {} bytes came back. Those frames carry a protocol \
                 the endpoint answers nothing for: it must count them and say nothing",
                frame.len()
            ));
        }
        let ether_type = frame
            .get(MAC_PAIR_LEN..ETHERNET_HEADER_LEN)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
        match ether_type {
            Some(ARP_ETHERTYPE) => self.judge_arp(frame).map(|()| ManagementReply::Arp),
            // An IPv4 datagram is one of two things on this wire, and the
            // protocol number is what separates them: the echo reply the ICMP
            // request obliges, or a segment of the one TCP connection the client
            // opens.
            Some(IPV4_ETHERTYPE) if is_tcp(frame) => {
                self.judge_tcp(frame, client).map(ManagementReply::Tcp)
            }
            Some(IPV4_ETHERTYPE) => self.judge_echo(frame).map(|()| ManagementReply::Echo),
            other => Err(format!(
                "a {} byte frame with EtherType {} came back on the management port, and the \
                 endpoint answers ARP and ICMP echo alone",
                frame.len(),
                match other {
                    Some(value) => format!("0x{value:04x}"),
                    None => String::from("(too short to have one)"),
                }
            )),
        }
    }

    /// Judge one segment of the client's connection against the step it is at, and
    /// advance the client over it.
    ///
    /// Every assertion is a **field comparison**: the flags that must be set and
    /// the flags that must not, the acknowledgement number against what the client
    /// actually sent, the payload against the bytes it actually sent. Nothing here
    /// matches a substring or a rendered line (TEST-13).
    ///
    /// # Errors
    /// The verdict, naming the field and the two values. A segment that arrives at
    /// a step it does not belong to is refused rather than tolerated: the whole
    /// value of asserting a sequence is that its order is part of the contract.
    fn judge_tcp(&self, frame: &[u8], client: &mut TcpClient) -> Result<TcpStep, String> {
        let segment = decode_tcp(frame, &self.port)?;
        if segment.source_port != MANAGEMENT_TCP_PORT || segment.destination_port != CLIENT_PORT {
            return Err(format!(
                "a segment came back from port {} to port {}, and the client opened {CLIENT_PORT} \
                 to {MANAGEMENT_TCP_PORT}",
                segment.source_port, segment.destination_port
            ));
        }
        if segment.carries(TCP_RST, 0) {
            return Err(format!(
                "the appliance reset the connection at the {:?} step (sequence {}, \
                 acknowledgement {})",
                client.step, segment.sequence, segment.acknowledgement
            ));
        }
        client.segments += 1;
        client.last_segment = Some((
            segment.flags,
            segment.sequence,
            segment.acknowledgement,
            segment.payload.len(),
        ));
        match client.step {
            TcpStep::Unopened => Err(format!(
                "a segment came back on the management port before the client opened a \
                 connection: flags {:#04x}, sequence {}",
                segment.flags, segment.sequence
            )),
            TcpStep::AwaitSynAck => {
                if !segment.carries(TCP_SYN | TCP_ACK, TCP_FIN) {
                    return Err(format!(
                        "the appliance answered a SYN with flags {:#04x}, and a passive open owes \
                         SYN and ACK together and no FIN",
                        segment.flags
                    ));
                }
                // The `SYN` occupies one sequence number, so this is the whole of
                // what the appliance may acknowledge.
                let owed = CLIENT_ISN.wrapping_add(1);
                if segment.acknowledgement != owed {
                    return Err(format!(
                        "the SYN-ACK acknowledges {} and the client's SYN occupied {owed}",
                        segment.acknowledgement
                    ));
                }
                client.peer_isn = Some(segment.sequence);
                client.expect = segment.sequence.wrapping_add(1);
                client.sequence = owed;
                Ok(TcpStep::AwaitSynAck)
            }
            TcpStep::AwaitResponse => {
                if !segment.carries(TCP_ACK, TCP_SYN) {
                    return Err(format!(
                        "the appliance answered with flags {:#04x}, and an established connection \
                         owes an ACK with no SYN",
                        segment.flags
                    ));
                }
                // The client has sent its `SYN` and its request and nothing
                // else, so every segment of the response acknowledges exactly
                // that much.
                let owed = TcpClient::sent_through_request();
                if segment.acknowledgement != owed {
                    return Err(format!(
                        "a response segment acknowledges {} and the client had sent up to {owed}",
                        segment.acknowledgement
                    ));
                }
                // Everything this client has sent is acknowledged, so its next
                // byte is `owed`. Set here rather than in `advance` because the
                // acknowledgements it composes from now on carry it, and a stale
                // one would re-send the request's sequence space and be refused
                // as out of window — which the appliance would answer by
                // retransmitting the range it thought was lost.
                client.sequence = owed;
                // In order and with no gap: a stream is what is under test, so a
                // segment out of place is refused rather than reassembled.
                if segment.sequence != client.expect {
                    return Err(format!(
                        "a response segment begins at sequence {} and the client expected {}; \
                         {} response bytes had arrived",
                        segment.sequence,
                        client.expect,
                        client.response.len()
                    ));
                }
                if client.response.len().saturating_add(segment.payload.len()) > MAX_RESPONSE_BYTES
                {
                    return Err(format!(
                        "the appliance has sent more than {MAX_RESPONSE_BYTES} response bytes; \
                         its Content-Length said {:?}",
                        client.content_length()
                    ));
                }
                client.response.extend_from_slice(&segment.payload);
                client.expect = segment.sequence.wrapping_add(segment.payload.len() as u32);
                if segment.carries(TCP_FIN, 0) {
                    // The `FIN` occupies one sequence number past the data.
                    client.expect = client.expect.wrapping_add(1);
                    client.peer_closed = true;
                    return judge_response(client).map(|()| TcpStep::AwaitResponse);
                }
                Ok(TcpStep::AwaitResponse)
            }
            TcpStep::AwaitLastAck => {
                if !segment.carries(TCP_ACK, TCP_SYN | TCP_FIN) {
                    return Err(format!(
                        "the appliance answered the client's FIN with flags {:#04x}, and a peer \
                         that has already closed owes a bare ACK",
                        segment.flags
                    ));
                }
                // The client's `FIN` occupied one number past its request.
                let owed = TcpClient::sent_through_request().wrapping_add(1);
                if segment.acknowledgement != owed {
                    return Err(format!(
                        "the final acknowledgement covers {} and the client's FIN occupied {owed}",
                        segment.acknowledgement
                    ));
                }
                client.sequence = owed;
                Ok(TcpStep::Closed)
            }
            TcpStep::Closed => Err(format!(
                "a segment came back after the connection closed: flags {:#04x}, sequence {}",
                segment.flags, segment.sequence
            )),
        }
    }

    /// What the client sends to reach the next step, given the one it has just
    /// completed. `None` where it owes nothing right now.
    fn advance(&self, client: &mut TcpClient) -> Option<Vec<u8>> {
        let (next, frame) = match client.step {
            TcpStep::Unopened => (
                TcpStep::AwaitSynAck,
                tcp_frame(&self.port, CLIENT_ISN, 0, TCP_SYN, &[]),
            ),
            // The handshake's third segment and the request in one, which is what
            // a client with something to say does: the acknowledgement rides on
            // the data rather than costing a segment of its own.
            TcpStep::AwaitSynAck => (
                TcpStep::AwaitResponse,
                tcp_frame(
                    &self.port,
                    client.sequence,
                    client.expect,
                    TCP_ACK | TCP_PSH,
                    TCP_REQUEST,
                ),
            ),
            // Every response segment is acknowledged, which is what opens the
            // window again and clocks the next one out; the appliance's own
            // `FIN` is answered with this end's.
            TcpStep::AwaitResponse if client.peer_closed => (
                TcpStep::AwaitLastAck,
                tcp_frame(
                    &self.port,
                    client.sequence,
                    client.expect,
                    TCP_FIN | TCP_ACK,
                    &[],
                ),
            ),
            TcpStep::AwaitResponse => (
                TcpStep::AwaitResponse,
                tcp_frame(&self.port, client.sequence, client.expect, TCP_ACK, &[]),
            ),
            // The client's `FIN` is already out; what remains is the appliance's
            // acknowledgement of it, which `judge_tcp` closes the exchange on.
            TcpStep::AwaitLastAck | TcpStep::Closed => return None,
        };
        client.step = next;
        Some(frame)
    }

    /// The exchange as evidence, in the voice of the routed-traffic lines.
    fn opened(&self, client: &TcpClient) -> String {
        let status = client
            .split_response()
            .and_then(|(head, _)| core::str::from_utf8(head).ok())
            .and_then(|head| head.lines().next())
            .unwrap_or("(no status line)")
            .to_owned();
        format!(
            "  answered   http-scrape           station->mgmt  {}:{CLIENT_PORT} -> \
             {}:{MANAGEMENT_TCP_PORT}  isn {}  {status}  {} response bytes  closed cleanly",
            ipv4(self.port.station),
            ipv4(self.port.address),
            client
                .peer_isn
                .map_or_else(|| String::from("(none)"), |isn| isn.to_string()),
            client.response.len()
        )
    }

    /// The ARP reply the request obliges: our request's sender as the target, and
    /// the management port's own pair as the sender.
    fn judge_arp(&self, frame: &[u8]) -> Result<(), String> {
        let reply = decode_arp(frame)?;
        let expected = ArpFrame {
            destination_mac: MANAGEMENT_STATION_MAC,
            source_mac: self.port.mac,
            operation: ARP_REPLY,
            sender_mac: self.port.mac,
            sender_address: self.port.address,
            target_mac: MANAGEMENT_STATION_MAC,
            target_address: self.port.station,
        };
        if reply == expected {
            return Ok(());
        }
        Err(format!(
            "the ARP reply on the management port departs from the contract in {}",
            arp_differences(&expected, &reply).join("; ")
        ))
    }

    /// The echo reply the request obliges: the addresses reversed, and the echo
    /// repeated to the byte.
    fn judge_echo(&self, frame: &[u8]) -> Result<(), String> {
        let reply = decode_echo(frame)?;
        let expected = EchoFrame {
            destination_mac: MANAGEMENT_STATION_MAC,
            source_mac: self.port.mac,
            source: self.port.address,
            destination: self.port.station,
            ttl: ECHO_REPLY_TTL,
            message_type: ICMP_ECHO_REPLY,
            code: 0,
            identifier: ECHO_IDENTIFIER,
            sequence: ECHO_SEQUENCE,
            payload: ECHO_PAYLOAD.to_vec(),
        };
        if reply == expected {
            return Ok(());
        }
        Err(format!(
            "the ICMP echo reply on the management port departs from the contract in {}",
            echo_differences(&expected, &reply).join("; ")
        ))
    }
}

/// Judge the whole response the appliance sent before closing.
///
/// The stream is what a client actually has: the head parsed back into a status
/// line and a `Content-Length`, and the body compared against the length it
/// declared. Contents are deliberately not judged here — the exposition is
/// judged where it can be cross-checked against traffic the harness observed
/// itself (`crate::metrics_contract`), and a body compared against a second copy
/// of the appliance's own renderer would agree with itself.
///
/// # Errors
/// The verdict, naming the field and the two values.
fn judge_response(client: &TcpClient) -> Result<(), String> {
    let Some((head, body)) = client.split_response() else {
        return Err(format!(
            "the appliance closed after {} response bytes with no blank line in them, so it sent \
             no complete HTTP head",
            client.response.len()
        ));
    };
    if !head.starts_with(HTTP_OK) {
        return Err(format!(
            "the appliance answered {:?} and a scrape is owed {:?}",
            String::from_utf8_lossy(head.get(..head.len().min(64)).unwrap_or_default()),
            String::from_utf8_lossy(HTTP_OK)
        ));
    }
    let Some(stated) = client.content_length() else {
        return Err(format!(
            "the response head carries no readable Content-Length: {:?}",
            String::from_utf8_lossy(head)
        ));
    };
    if stated != body.len() {
        return Err(format!(
            "the response states a Content-Length of {stated} and closed after {} body bytes",
            body.len()
        ));
    }
    if body.is_empty() {
        return Err(String::from(
            "the appliance answered 200 with an empty body, so nothing about the exposition was \
             carried by the stream",
        ));
    }
    Ok(())
}

/// An ARP frame as fields, read back by this harness's own reader.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ArpFrame {
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    operation: u16,
    sender_mac: [u8; 6],
    sender_address: [u8; 4],
    target_mac: [u8; 6],
    target_address: [u8; 4],
}

/// Read an ARP-over-Ethernet frame, refusing anything that is not IPv4 over
/// Ethernet.
///
/// # Errors
/// The verdict, naming the value that refused it. Padding past the 28-byte
/// payload is ignored, as an endpoint must ignore it.
fn decode_arp(frame: &[u8]) -> Result<ArpFrame, String> {
    let Some(bytes) = frame.get(..ARP_FRAME_LEN) else {
        return Err(format!(
            "{} bytes is short of the {ARP_FRAME_LEN} an ARP frame needs",
            frame.len()
        ));
    };
    let hardware = u16::from_be_bytes([bytes[14], bytes[15]]);
    let protocol = u16::from_be_bytes([bytes[16], bytes[17]]);
    if hardware != 1 || protocol != IPV4_ETHERTYPE || bytes[18] != 6 || bytes[19] != 4 {
        return Err(format!(
            "the ARP reply names hardware type {hardware}, protocol type 0x{protocol:04x} and              address lengths {}/{}, which is not IPv4 over Ethernet",
            bytes[18], bytes[19]
        ));
    }
    let six = |at: usize| -> [u8; 6] {
        let mut out = [0u8; 6];
        out.copy_from_slice(&bytes[at..at + 6]);
        out
    };
    let four = |at: usize| -> [u8; 4] {
        let mut out = [0u8; 4];
        out.copy_from_slice(&bytes[at..at + 4]);
        out
    };
    Ok(ArpFrame {
        destination_mac: six(0),
        source_mac: six(6),
        operation: u16::from_be_bytes([bytes[20], bytes[21]]),
        sender_mac: six(22),
        sender_address: four(28),
        target_mac: six(32),
        target_address: four(38),
    })
}

/// An ICMP echo frame as fields, read back by this harness's own reader.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EchoFrame {
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source: [u8; 4],
    destination: [u8; 4],
    ttl: u8,
    message_type: u8,
    code: u8,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

/// Read an ICMP-over-IPv4 frame, validating both checksums and every length the
/// field view rests on.
///
/// # Errors
/// The verdict, naming the value that refused it.
fn decode_echo(frame: &[u8]) -> Result<EchoFrame, String> {
    let Some((ethernet, after_ethernet)) = frame.split_first_chunk::<ETHERNET_HEADER_LEN>() else {
        return Err(format!(
            "{} bytes is short of an Ethernet header",
            frame.len()
        ));
    };
    let Some((ip, after_ip)) = after_ethernet.split_first_chunk::<IPV4_HEADER_LEN>() else {
        return Err(format!(
            "{} bytes leave no room for an IPv4 header",
            after_ethernet.len()
        ));
    };
    if ip[0] != 0x45 {
        return Err(format!(
            "the reply's version/IHL byte is 0x{:02x} rather than 0x45",
            ip[0]
        ));
    }
    let found = u16::from_be_bytes([ip[10], ip[11]]);
    let computed = header_checksum(ip);
    if found != computed {
        return Err(format!(
            "the reply's IPv4 checksum is 0x{found:04x} where 0x{computed:04x} was required"
        ));
    }
    if ip[9] != ICMP_PROTOCOL {
        return Err(format!("IP protocol {} is not ICMP", ip[9]));
    }
    let total_length = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let Some(message_len) = total_length.checked_sub(IPV4_HEADER_LEN) else {
        return Err(format!(
            "total length {total_length} is below the IPv4 header"
        ));
    };
    let Some(message) = after_ip.get(..message_len) else {
        return Err(format!(
            "total length {total_length} exceeds the {}-byte frame",
            frame.len()
        ));
    };
    let Some((icmp, payload)) = message.split_first_chunk::<ICMP_HEADER_LEN>() else {
        return Err(format!(
            "{message_len} bytes leave no room for an ICMP echo header"
        ));
    };
    let found = u16::from_be_bytes([icmp[2], icmp[3]]);
    let computed = message_checksum(message);
    if found != computed {
        return Err(format!(
            "the reply's ICMP checksum is 0x{found:04x} where 0x{computed:04x} was required"
        ));
    }
    let mut destination_mac = [0u8; 6];
    destination_mac.copy_from_slice(&ethernet[..6]);
    let mut source_mac = [0u8; 6];
    source_mac.copy_from_slice(&ethernet[6..12]);
    let mut source = [0u8; 4];
    source.copy_from_slice(&ip[12..16]);
    let mut destination = [0u8; 4];
    destination.copy_from_slice(&ip[16..20]);
    Ok(EchoFrame {
        destination_mac,
        source_mac,
        source,
        destination,
        ttl: ip[8],
        message_type: icmp[0],
        code: icmp[1],
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
        payload: payload.to_vec(),
    })
}

/// Name every field in which an ARP reply departs from its contract, so a
/// verdict says which one the endpoint got wrong rather than that a frame was
/// wrong.
fn arp_differences(expected: &ArpFrame, observed: &ArpFrame) -> Vec<String> {
    let mut found = Vec::new();
    let mut note = |name: &str, left: String, right: String| {
        if left != right {
            found.push(format!("{name} {right} (expected {left})"));
        }
    };
    note(
        "destination MAC",
        mac(expected.destination_mac),
        mac(observed.destination_mac),
    );
    note(
        "source MAC",
        mac(expected.source_mac),
        mac(observed.source_mac),
    );
    note(
        "operation",
        expected.operation.to_string(),
        observed.operation.to_string(),
    );
    note(
        "sender MAC",
        mac(expected.sender_mac),
        mac(observed.sender_mac),
    );
    note(
        "sender address",
        ipv4(expected.sender_address),
        ipv4(observed.sender_address),
    );
    note(
        "target MAC",
        mac(expected.target_mac),
        mac(observed.target_mac),
    );
    note(
        "target address",
        ipv4(expected.target_address),
        ipv4(observed.target_address),
    );
    found
}

/// As [`arp_differences`], for an echo reply.
fn echo_differences(expected: &EchoFrame, observed: &EchoFrame) -> Vec<String> {
    let mut found = Vec::new();
    let mut note = |name: &str, left: String, right: String| {
        if left != right {
            found.push(format!("{name} {right} (expected {left})"));
        }
    };
    note(
        "destination MAC",
        mac(expected.destination_mac),
        mac(observed.destination_mac),
    );
    note(
        "source MAC",
        mac(expected.source_mac),
        mac(observed.source_mac),
    );
    note(
        "source address",
        ipv4(expected.source),
        ipv4(observed.source),
    );
    note(
        "destination address",
        ipv4(expected.destination),
        ipv4(observed.destination),
    );
    note("TTL", expected.ttl.to_string(), observed.ttl.to_string());
    note(
        "ICMP type",
        expected.message_type.to_string(),
        observed.message_type.to_string(),
    );
    note(
        "ICMP code",
        expected.code.to_string(),
        observed.code.to_string(),
    );
    note(
        "identifier",
        format!("0x{:04x}", expected.identifier),
        format!("0x{:04x}", observed.identifier),
    );
    note(
        "sequence",
        format!("0x{:04x}", expected.sequence),
        format!("0x{:04x}", observed.sequence),
    );
    if expected.payload != observed.payload {
        found.push(format!(
            "payload: {}",
            byte_difference(&expected.payload, &observed.payload)
        ));
    }
    found
}

/// Whether an IPv4 frame on the management wire carries a TCP segment.
fn is_tcp(frame: &[u8]) -> bool {
    frame
        .get(ETHERNET_HEADER_LEN + 9)
        .is_some_and(|protocol| *protocol == TCP_PROTOCOL)
}

/// Whether a frame carries anything only the management wire's traffic does: the
/// port's own MAC, or the harness's station on it.
///
/// Both belong to nothing else on either bench (`crate::qemu`'s and
/// `crate::topology`'s tests hold them to it), so either appearing in a frame on
/// a dataplane port is the isolation CONCEPT §9.1 requires having stopped being
/// true — in the direction no console record would ever show.
fn carries_management_traffic(frame: &[u8], management: &ManagementPort) -> bool {
    contains(frame, MANAGEMENT_MARKER)
        || contains(frame, &management.mac)
        || contains(frame, &MANAGEMENT_STATION_MAC)
}

/// An [`Endpoint`] joined to the QEMU socket that carries its port's traffic.
struct AttachedEndpoint {
    endpoint: Endpoint,
    wire: TcpStream,
    /// Why injection into this endpoint stopped, if it ever did.
    injection_failure: Option<io::Error>,
}

impl AttachedEndpoint {
    /// Put one frame on the wire in QEMU's `net_socket` STREAM framing.
    ///
    /// Losing one port's socket says nothing about the other direction, so a
    /// failure retires this endpoint and keeps its reason: it is reported with
    /// whatever verdict the exit and timeout checks eventually reach.
    fn inject(&mut self, frame: &[u8]) {
        if self.injection_failure.is_some() {
            return;
        }
        if let Err(error) = self.wire.write_all(&encode_wire(frame)) {
            self.injection_failure = Some(error);
        }
    }
}

/// The harness's end of the management wire.
///
/// Not an [`AttachedEndpoint`]: that carries an [`Endpoint`] read out of the
/// configuration document, and the management port has no interface and no
/// neighbour in one. What is left is a socket and the reason injection stopped,
/// if it ever did.
struct ManagementWire {
    wire: TcpStream,
    injection_failure: Option<io::Error>,
    /// Which of the two replies has arrived and been accepted. Both must, and
    /// each exactly once: the endpoint answers a request, and a second answer to
    /// one request is a frame nothing asked for.
    arp_reply: bool,
    echo_reply: bool,
    /// The client's end of the one TCP connection this harness opens.
    client: TcpClient,
    /// Every frame this harness has put on the wire, accumulated as it goes.
    ///
    /// Accumulated rather than precomputed because the TCP exchange's frames are
    /// decided by the appliance's own answers: the console's count is an equality
    /// (`crate::management_contract`), so it must be stated against what was
    /// actually sent and not against a tally written in advance.
    injected: ManagementInjection,
}

impl ManagementWire {
    /// Whether the port has answered everything it owes: both stateless replies
    /// and a whole TCP exchange.
    fn answered(&self) -> bool {
        self.arp_reply && self.echo_reply && self.client.step == TcpStep::Closed
    }

    /// Whether the two stateless replies are in, which is what the TCP exchange
    /// waits for: a failure in either is then reported as itself rather than as a
    /// connection that never opened.
    fn stateless_replies_in(&self) -> bool {
        self.arp_reply && self.echo_reply
    }

    /// Which replies are still outstanding, as a clause for a verdict.
    fn outstanding(&self) -> String {
        let mut owed: Vec<&str> = Vec::new();
        if !self.arp_reply {
            owed.push("the ARP reply");
        }
        if !self.echo_reply {
            owed.push("the ICMP echo reply");
        }
        if self.client.step != TcpStep::Closed {
            owed.push(self.client.step.outstanding());
        }
        if owed.is_empty() {
            return String::from("none");
        }
        owed.join(" and ")
    }

    /// Record one accepted reply, refusing a second of the same kind.
    ///
    /// A TCP step is not one of those: the connection's own state machine is what
    /// orders its segments, and it already refuses one that arrives out of turn.
    fn accept(&mut self, reply: ManagementReply) -> Result<(), String> {
        let seen = match reply {
            ManagementReply::Arp => &mut self.arp_reply,
            ManagementReply::Echo => &mut self.echo_reply,
            ManagementReply::Tcp(_) => return Ok(()),
        };
        if *seen {
            return Err(format!(
                "a second {reply:?} reply came back on the management port. One request is one \
                 reply, and the harness injects each exactly once"
            ));
        }
        *seen = true;
        Ok(())
    }
}

impl ManagementWire {
    /// Put one frame on the wire, on [`AttachedEndpoint::inject`]'s terms: a
    /// failure retires the wire and keeps its reason for whichever verdict the
    /// exit and timeout checks eventually reach.
    fn inject(&mut self, frame: &[u8]) {
        if self.injection_failure.is_some() {
            return;
        }
        match self.wire.write_all(&encode_wire(frame)) {
            Ok(()) => {
                self.injected.frames += 1;
                self.injected.bytes += frame.len() as u64;
            }
            Err(error) => self.injection_failure = Some(error),
        }
    }
}

/// Why the management half of a timed-out run had not finished, as a clause to
/// append to the verdict. A run that timed out with the management frames never
/// sent failed for a different reason from one that sent them and heard nothing,
/// and the two must not read alike.
fn describe_management(
    output: &[u8],
    injected: &ManagementInjection,
    wire: Option<&ManagementWire>,
) -> String {
    let Some(wire) = wire else {
        return String::from(
            "the management port is on QEMU's user-mode stack, so the harness put no frame on it \
             and the scrape had not been taken",
        );
    };
    if let Some(error) = &wire.injection_failure {
        return format!("management injection stopped: {error}");
    }
    if injected.is_empty() {
        return format!(
            "the management frames were never injected: the capture does not yet show every port \
             up (ports_are_ready is {})",
            management_contract::ports_are_ready(output)
        );
    }
    format!(
        "{} management frames of {} bytes were injected, and the port still owes {}; {}",
        injected.frames,
        injected.bytes,
        wire.outstanding(),
        wire.client.seen()
    )
}

/// Inject every probe the `wanted` predicate selects, from the endpoint whose
/// port it enters on.
fn inject_probes(
    endpoints: &mut [AttachedEndpoint],
    probes: &[Probe],
    wanted: impl Fn(&Probe) -> bool,
) {
    for attached in endpoints.iter_mut() {
        let port = attached.endpoint.port;
        for probe in probes
            .iter()
            .filter(|probe| probe.from.port == port && wanted(probe))
        {
            attached.inject(&probe.frame);
        }
    }
}

/// What one boot yielded: the guest's serial output, what the probes injected
/// into it were observed to do, and what reached the management port.
#[derive(Debug)]
pub struct Booted {
    pub serial: Vec<u8>,
    pub traffic: TrafficReport,
    /// What was put on the management wire, which is what the console's own
    /// count is judged against. Empty on a boot that never reached the point
    /// where injecting an exact number was possible — a halted slot, or a routed
    /// contract that failed first — and `management_contract::judge` refuses an
    /// empty one rather than reading two zeroes as agreement.
    pub management: ManagementInjection,
    /// The appliance's own initial sequence number for the one connection this
    /// boot opened, or `None` on a boot that never opened one.
    ///
    /// Returned so a caller can compare it *across boots*: RFC 6528 makes an
    /// unpredictable one a security property, and one boot's number alone cannot
    /// show that it is not a constant.
    pub management_tcp_isn: Option<u32>,
    /// One line per reply the management port owed and gave, in the order they
    /// were accepted. Empty exactly when the run had no routed contract to meet:
    /// a routed run that reached its verdict answered both, the wait for them
    /// being what ends it.
    pub management_replies: Vec<String>,
    /// What `curl` got out of the management endpoint, on the one scenario that
    /// points it at one: two consecutive scrapes, because a scrape cannot carry
    /// the response it is (`crate::metrics_contract`). Empty on every
    /// socket-backed boot.
    pub scrapes: Vec<Scrape>,
    /// Frames the harness itself observed coming back on the two dataplane
    /// ports.
    ///
    /// It is the independent half of the cross-check the scrape scenario makes:
    /// every frame on a dataplane egress is one the appliance forwarded, and
    /// nothing else originates on those ports, so this number is what the
    /// appliance's own `librefirewall_forwarded_frames_total` must equal. The
    /// harness counts frames rather than *deliveries* deliberately — a probe
    /// re-injected before its first delivery was observed is forwarded twice,
    /// and both counters see both.
    pub dataplane_frames: u64,
}

/// Spawn the prepared QEMU `command` (which must carry this harness's NIC
/// backends and serial on stdio) and judge the boot against `test`'s contract.
///
/// The captured serial output is always written to the run log, whether the
/// test passes or fails, and is returned on success; QEMU is always killed and
/// reaped on every exit path. A failed run prints its traffic report before
/// returning, so the table and the verdict it explains cannot reach a terminal
/// in the other order.
pub fn run_boot_test(
    command: Command,
    backends: NicBackends,
    test: BootTest,
) -> Result<Booted, String> {
    run_boot(command, backends, test, ACCEPT_TIMEOUT, BOOT_TEST_TIMEOUT)
}

/// The boot-test engine with the two timeout budgets injected, so the timeout
/// and early-exit paths can be exercised in tests without the production
/// 20 s / 180 s waits.
fn run_boot(
    mut command: Command,
    backends: NicBackends,
    test: BootTest,
    accept_timeout: Duration,
    total_timeout: Duration,
) -> Result<Booted, String> {
    let log_path = test.log_path;
    // Built before QEMU is spawned: a bench this harness cannot play is the
    // caller's mistake and must be reported as one, not as a process nobody
    // reaped.
    let stations = test.topology.endpoints();
    let probes = probes(test.topology)?;

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start QEMU: {error}"))?;

    // Serial output arrives on both pipes; reader threads funnel it into a
    // single channel the timeout loop drains.
    let (serial_sender, serial_receiver) = mpsc::channel();
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate(&mut child, "stdout capture failure")?;
            return Err("capture QEMU stdout".to_owned());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate(&mut child, "stderr capture failure")?;
            return Err("capture QEMU stderr".to_owned());
        }
    };
    let stdout_reader = spawn_reader(stdout, serial_sender.clone());
    let stderr_reader = spawn_reader(stderr, serial_sender);

    let start = Instant::now();
    let mut output: Vec<u8> = Vec::new();
    // Kept alive across finalisation so they can be joined after QEMU dies.
    let mut frame_readers: Vec<JoinHandle<io::Result<()>>> = Vec::new();

    // What the run observed, held outside the block that fills it so the report
    // can be built on every exit path rather than only where the run succeeded.
    let mut deliveries: Vec<Option<Delivery>> = vec![None; probes.len()];
    let mut broke: Option<usize> = None;
    // What reached the management wire, which stays empty on every path that
    // never got as far as sending it.
    let (management_probe, _) = ManagementProbe::new(test.topology.management());
    let mut injected = ManagementInjection::default();
    let mut answered: Vec<String> = Vec::new();
    // Held outside the run block so it survives every exit path, as the traffic
    // report does: a boot that opened a connection and then failed later still
    // observed the number.
    let mut tcp_isn: Option<u32> = None;
    let mut observed_isn: Option<u32> = None;
    // What the harness saw come back on the two dataplane ports, and what a real
    // client got out of the management endpoint. Both live outside the run block
    // so they survive every exit path.
    let mut dataplane_frames: u64 = 0;
    let mut scrapes: Vec<Scrape> = Vec::new();

    let outcome: Result<(), String> = 'run: {
        // Phase 1: accept every one of QEMU's socket dial-ins.
        let sockets = backends.listeners.len();
        let mut streams: Vec<Option<TcpStream>> = (0..sockets).map(|_| None).collect();
        while streams.iter().any(Option::is_none) {
            drain(&serial_receiver, &mut output);
            for (slot, listener) in backends.listeners.iter().enumerate() {
                if streams.get(slot).is_some_and(Option::is_some) {
                    continue;
                }
                match listener.accept() {
                    Ok((stream, _peer)) => streams[slot] = Some(stream),
                    Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => break 'run Err(format!("accept QEMU NIC socket: {error}")),
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    break 'run Err(format!(
                        "QEMU exited before connecting its NIC sockets ({status})"
                    ));
                }
                Ok(None) => {}
                Err(error) => break 'run Err(format!("poll QEMU: {error}")),
            }
            if start.elapsed() >= accept_timeout {
                break 'run Err(format!(
                    "QEMU did not connect all {sockets} NIC sockets within {}s",
                    accept_timeout.as_secs()
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
        let mut accepted: Vec<TcpStream> = Vec::with_capacity(streams.len());
        for stream in streams {
            match stream {
                Some(stream) => accepted.push(stream),
                // Unreachable: the loop above only leaves when none is `None`.
                None => break 'run Err("a NIC socket was never accepted".to_owned()),
            }
        }
        // Socket-backed, the management stream is the last one accepted; under
        // the user-mode backing there is none at all and the harness sees no
        // frame of that port's traffic.
        let management_stream = if backends.management.is_socket() {
            accepted.pop()
        } else {
            None
        };
        let streams = accepted;

        // Each stream carries QEMU's `net_socket` STREAM framing in both
        // directions: a 4-byte big-endian length header followed by the raw L2
        // bytes (no FCS). A decoder thread per port parses the guest's egress
        // frames into one channel; draining continuously also keeps QEMU's TX
        // path from blocking on a full host socket buffer.
        let (frame_sender, frame_receiver) = mpsc::channel();
        // The management wire, drained like the others so QEMU's TX path cannot
        // block on a full host buffer, and watched for the one thing that must
        // never arrive on it.
        let mut management: Option<ManagementWire> = match management_stream {
            Some(stream) => {
                if let Err(error) = stream.set_nonblocking(false) {
                    break 'run Err(format!("set the management NIC socket blocking: {error}"));
                }
                let management_read = match stream.try_clone() {
                    Ok(handle) => handle,
                    Err(error) => {
                        break 'run Err(format!("clone the management NIC socket: {error}"));
                    }
                };
                frame_readers.push(spawn_frame_decoder(
                    MANAGEMENT_SLOT,
                    management_read,
                    frame_sender.clone(),
                ));
                Some(ManagementWire {
                    wire: stream,
                    injection_failure: None,
                    arp_reply: false,
                    echo_reply: false,
                    client: TcpClient::new(),
                    injected: ManagementInjection::default(),
                })
            }
            None => None,
        };

        let mut endpoints: Vec<AttachedEndpoint> = Vec::new();
        for (endpoint, stream) in stations.into_iter().zip(streams) {
            if let Err(error) = stream.set_nonblocking(false) {
                break 'run Err(format!("set NIC socket blocking: {error}"));
            }
            let read_half = match stream.try_clone() {
                Ok(handle) => handle,
                Err(error) => break 'run Err(format!("clone NIC socket: {error}")),
            };
            frame_readers.push(spawn_frame_decoder(
                endpoint.port,
                read_half,
                frame_sender.clone(),
            ));
            endpoints.push(AttachedEndpoint {
                endpoint,
                wire: stream,
                injection_failure: None,
            });
        }
        drop(frame_sender);

        // Inject immediately: a station does not wait to be told its peer is
        // ready, and a packet sent into an unbooted appliance is lost rather
        // than queued. That is why sending continues on a cadence below. The
        // management frames are the exception and wait, for the reason given at
        // the point they are sent.
        let mut last_injection = Instant::now();
        inject_probes(&mut endpoints, &probes, |_| true);

        // Phase 2: watch both ports and the serial channel, re-injecting
        // periodically, until the contract is decided.
        //
        // Set once both routed packets have arrived, starting the window in
        // which a refused packet would still have time to come back.
        let mut settling_since: Option<Instant> = None;
        loop {
            drain(&serial_receiver, &mut output);
            while let Ok((egress, frame)) = frame_receiver.try_recv() {
                // The management port is judged before any dataplane probe is
                // matched, because what may come back on it is a contract of its
                // own: the two replies the endpoint owes, and nothing else. Under
                // the halted contract nothing may come back at all — no slot
                // booted, so no endpoint answered.
                if egress == MANAGEMENT_SLOT {
                    // Unreachable under the user-mode backing: there is no
                    // decoder on that port, so no frame of it ever arrives here.
                    let Some(management) = management.as_mut() else {
                        break 'run Err(format!(
                            "{} bytes arrived from the management port on a boot with no socket \
                             on it; see {}",
                            frame.len(),
                            log_path.display()
                        ));
                    };
                    match &test.contract {
                        BootContract::Routed => {
                            match management_probe.judge(&frame, &probes, &mut management.client) {
                                Ok(reply) => {
                                    if let Err(verdict) = management.accept(reply) {
                                        break 'run Err(format!(
                                            "{verdict}; see {}",
                                            log_path.display()
                                        ));
                                    }
                                    // A TCP step both asserts what came back and
                                    // decides what goes out next, so the client is
                                    // advanced here rather than on a timer: the
                                    // exchange is driven by the appliance's own
                                    // answers.
                                    //
                                    // The judged step is recorded before the
                                    // client is advanced, because the last step of
                                    // the exchange sends nothing: the final
                                    // acknowledgement is *only* observed, and a
                                    // client that learned its step from what it
                                    // next transmits could never notice it and
                                    // would wait out the whole timeout on a
                                    // connection the appliance had already closed
                                    // correctly.
                                    if let ManagementReply::Tcp(step) = reply {
                                        management.client.step = step;
                                    }
                                    if matches!(reply, ManagementReply::Tcp(_)) {
                                        observed_isn = management.client.peer_isn;
                                        if let Some(next) =
                                            management_probe.advance(&mut management.client)
                                        {
                                            management.inject(&next);
                                            injected = management.injected;
                                        }
                                        if management.client.step == TcpStep::Closed {
                                            answered
                                                .push(management_probe.opened(&management.client));
                                            // Restart the settle window from the
                                            // last frame this harness sent, so the
                                            // appliance has a whole one to report
                                            // the count including its final
                                            // segment: the console's total is an
                                            // equality, and breaking out at the
                                            // instant the exchange closed would
                                            // race that record.
                                            settling_since = Some(Instant::now());
                                        }
                                    } else {
                                        answered.push(management_probe.answered(reply));
                                    }
                                }
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            }
                        }
                        BootContract::Halted { .. } => {
                            break 'run Err(format!(
                                "{} bytes came back on the management port, so a slot booted \
                                 where none may be bootable; see {}",
                                frame.len(),
                                log_path.display()
                            ));
                        }
                    }
                    continue;
                }
                // Every frame on a dataplane egress is one the appliance
                // forwarded, and nothing else originates on those ports — which
                // is what makes this an *independent* measurement of the number
                // `librefirewall_forwarded_frames_total` reports.
                dataplane_frames = dataplane_frames.saturating_add(1);
                // And the other direction of that isolation, which no console
                // record would ever show: a frame the harness put on the
                // management wire, or one the endpoint answered with, reaching a
                // dataplane port.
                if carries_management_traffic(&frame, &test.topology.management()) {
                    break 'run Err(format!(
                        "{} bytes carrying management traffic came back on port{egress}. CONCEPT \
                         §9.1 isolates the management port from the dataplane, and no domain is \
                         granted a region on both sides of it, so a frame crossing means one of \
                         those grants has changed; see {}",
                        frame.len(),
                        log_path.display()
                    ));
                }
                for (index, (probe, seen)) in probes.iter().zip(deliveries.iter_mut()).enumerate() {
                    if !contains(&frame, probe.marker) {
                        continue;
                    }
                    match &test.contract {
                        BootContract::Routed => match probe.judge(egress, &frame) {
                            Ok(delivery) => *seen = Some(delivery),
                            Err(verdict) => {
                                broke = Some(index);
                                break 'run Err(format!("{verdict}; see {}", log_path.display()));
                            }
                        },
                        // Any frame at all means something booted and is moving
                        // traffic, which is precisely what must not happen. No
                        // amount of further draining can undo that, so fail now.
                        BootContract::Halted { .. } => {
                            break 'run Err(format!(
                                "probe {} came back on port{egress}, so a slot booted where none \
                                 may be bootable; see {}",
                                probe.name,
                                log_path.display()
                            ));
                        }
                    }
                }
            }
            match &test.contract {
                BootContract::Routed => match settling_since {
                    // Both directions have completed AND the capture says every
                    // port is up. The first says a refused packet injected now is
                    // one that reached a driver; the second is what makes an
                    // *exact* management count possible, a frame put on a wire
                    // before its port has posted a receive buffer being lost
                    // rather than queued. Neither implies the other: the
                    // management port takes no part in forwarding.
                    None if all_routed(&probes, &deliveries)
                        && management_contract::ports_are_ready(&output) =>
                    {
                        inject_probes(&mut endpoints, &probes, |probe| {
                            matches!(probe.expectation, Expectation::Dropped { .. })
                        });
                        // Once, and never retransmitted: a retransmission is a
                        // second frame, and both halves of this contract are
                        // equalities — the console's count, and one reply per
                        // request.
                        if let Some(management) = management.as_mut() {
                            for frame in &management_probe.frames {
                                management.inject(frame);
                            }
                            injected = management.injected;
                        }
                        settling_since = Some(Instant::now());
                    }
                    // The window is what a refusal needs to have come back in;
                    // the replies are what the management port owes. A run that
                    // waited out the window without both has not met the
                    // contract, and says which one is missing when it times out.
                    // The two stateless replies are in, so a failure in either has
                    // already been reported as itself: the connection may be
                    // opened. Once, and never retransmitted — the wire to QEMU is
                    // a host socket, so a client that re-sent would be testing
                    // itself rather than the appliance.
                    Some(_)
                        if management.as_ref().is_some_and(|wire| {
                            wire.stateless_replies_in() && wire.client.step == TcpStep::Unopened
                        }) =>
                    {
                        if let Some(wire) = management.as_mut()
                            && let Some(syn) = management_probe.advance(&mut wire.client)
                        {
                            wire.inject(&syn);
                        }
                    }
                    Some(since)
                        if since.elapsed() >= SETTLE_WINDOW
                            && management.as_ref().is_some_and(ManagementWire::answered) =>
                    {
                        break 'run Ok(());
                    }
                    // The scrape scenario: nothing more is injected anywhere, so
                    // the dataplane is quiet and the count the harness has
                    // observed is final. Take it, run a real client against the
                    // endpoint, and take it again — a number that moved across
                    // the scrape would make the cross-check meaningless rather
                    // than merely wrong, and is reported as its own failure.
                    Some(since)
                        if since.elapsed() >= SETTLE_WINDOW
                            && management.is_none()
                            && scrapes.is_empty() =>
                    {
                        let ManagementBacking::UserNetwork { host_port } = backends.management
                        else {
                            break 'run Err(String::from(
                                "a boot with no management socket must be on the user-mode \
                                 backing",
                            ));
                        };
                        while let Ok((egress, frame)) = frame_receiver.try_recv() {
                            if egress != MANAGEMENT_SLOT {
                                dataplane_frames = dataplane_frames.saturating_add(1);
                            }
                            let _ = frame;
                        }
                        let before = dataplane_frames;
                        // Two, back to back: the second is what carries the
                        // first's request and response, and answering it at all
                        // is what proves the one staging buffer was released
                        // rather than held through the first connection's
                        // `TIME_WAIT` (`crate::metrics_contract`).
                        let mut fetched = Vec::new();
                        for _ in 0..SCRAPES {
                            match metrics_contract::fetch(host_port) {
                                Ok(one) => fetched.push(one),
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            }
                        }
                        while let Ok((egress, frame)) = frame_receiver.try_recv() {
                            if egress != MANAGEMENT_SLOT {
                                dataplane_frames = dataplane_frames.saturating_add(1);
                            }
                            let _ = frame;
                        }
                        if dataplane_frames != before {
                            break 'run Err(format!(
                                "{before} frames had come back on the dataplane ports when the \
                                 scrape began and {dataplane_frames} by the time it finished, so \
                                 the count the exposition is compared against is not the count \
                                 the appliance had when it rendered it; see {}",
                                log_path.display()
                            ));
                        }
                        scrapes = fetched;
                        break 'run Ok(());
                    }
                    _ => {}
                },
                BootContract::Halted { marker } => {
                    if contains(&output, marker.as_bytes()) {
                        break 'run Ok(());
                    }
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => match &test.contract {
                    BootContract::Routed => {
                        break 'run Err(format!(
                            "QEMU exited before the routed contract was met ({status}); {}{}; \
                             see {}",
                            describe_pending(&probes, &deliveries),
                            describe_injection_failures(&endpoints),
                            log_path.display()
                        ));
                    }
                    // Halting the guest powers the machine off, so an exit is
                    // the expected end of this contract — but serial bytes may
                    // still be in flight. Leave the verdict to the post-drain
                    // check below, which sees every byte QEMU wrote.
                    BootContract::Halted { .. } => break 'run Ok(()),
                },
                Ok(None) => {}
                Err(error) => break 'run Err(format!("poll QEMU: {error}")),
            }
            if start.elapsed() >= total_timeout {
                break 'run Err(match &test.contract {
                    BootContract::Routed => format!(
                        "timed out after {}s waiting for the routed contract; {}; {}{}; see {}",
                        total_timeout.as_secs(),
                        describe_pending(&probes, &deliveries),
                        describe_management(&output, &injected, management.as_ref()),
                        describe_injection_failures(&endpoints),
                        log_path.display()
                    ),
                    BootContract::Halted { marker } => format!(
                        "timed out after {}s waiting for {marker:?} on the serial channel{}; \
                         see {}",
                        total_timeout.as_secs(),
                        describe_injection_failures(&endpoints),
                        log_path.display()
                    ),
                });
            }
            if settling_since.is_none() && last_injection.elapsed() >= REINJECT_INTERVAL {
                last_injection = Instant::now();
                inject_probes(&mut endpoints, &probes, |probe| {
                    !is_delivered(&probes, &deliveries, probe)
                });
            }
            thread::sleep(Duration::from_millis(25));
        }
        // `endpoints` drop here, closing our write sides of the NIC sockets.
    };

    // Reliable shutdown: kill and reap QEMU on every path before joining the
    // reader threads (which unblock once the pipes and sockets close).
    tcp_isn = tcp_isn.or(observed_isn);
    let terminate_result = terminate(&mut child, "boot test finished");
    let stdout_result = join_reader(stdout_reader, "stdout");
    let stderr_result = join_reader(stderr_reader, "stderr");
    let mut frame_reader_result = Ok(());
    for handle in frame_readers {
        frame_reader_result = frame_reader_result.and(join_reader(handle, "NIC socket"));
    }
    // Killing QEMU does not discard what it already wrote: the pipes still hold
    // every byte, the reader threads have now read them to EOF, and this drain
    // moves the last of them into `output`. Any assertion on the capture is
    // therefore made against the complete serial record, not a snapshot taken
    // at whatever instant the contract happened to be decided.
    drain(&serial_receiver, &mut output);

    let outcome = decide(outcome, &test.contract, &output, log_path);
    let traffic = TrafficReport::new(stations, &probes, &deliveries, broke);

    // Persisting the log must never destroy the verdict that produced it, so
    // the two are reported together rather than one replacing the other.
    let capture_result = write_capture(log_path, test.log_header, &output);
    let verdict = match (outcome, capture_result) {
        (Err(verdict), Err(capture)) => Err(format!("{verdict}; additionally, {capture}")),
        (Err(verdict), Ok(())) => Err(verdict),
        (Ok(()), Err(capture)) => Err(capture),
        (Ok(()), Ok(())) => Ok(()),
    };
    if let Err(verdict) = verdict {
        // Ahead of the verdict, and flushed: the verdict travels back as an
        // error and reaches the terminal on stderr, which orders itself against
        // a block-buffered stdout only if this is pushed out first.
        print!("{}", traffic.render());
        return Err(match io::stdout().flush() {
            Ok(()) => verdict,
            Err(error) => format!(
                "{verdict}; additionally, the traffic report above may be \
                 truncated: flushing stdout failed: {error}"
            ),
        });
    }

    terminate_result?;
    stdout_result?;
    stderr_result?;
    frame_reader_result?;
    Ok(Booted {
        serial: output,
        traffic,
        management: injected,
        management_tcp_isn: tcp_isn,
        management_replies: answered,
        scrapes,
        dataplane_frames,
    })
}

/// Whether every probe that must be routed has arrived and been accepted.
fn all_routed(probes: &[Probe], deliveries: &[Option<Delivery>]) -> bool {
    probes
        .iter()
        .zip(deliveries)
        .filter(|(probe, _)| matches!(probe.expectation, Expectation::Routed { .. }))
        .all(|(_, seen)| seen.is_some())
}

/// Whether this probe has already been accepted, so re-injecting it would only
/// add traffic the contract no longer needs.
fn is_delivered(probes: &[Probe], deliveries: &[Option<Delivery>], probe: &Probe) -> bool {
    probes
        .iter()
        .zip(deliveries)
        .any(|(candidate, seen)| candidate.name == probe.name && seen.is_some())
}

/// Name which routed probes arrived and which never did. A run that timed out
/// has to say which direction failed, not that something did.
fn describe_pending(probes: &[Probe], deliveries: &[Option<Delivery>]) -> String {
    let mut arrived = Vec::new();
    let mut missing = Vec::new();
    for (probe, seen) in probes.iter().zip(deliveries) {
        if !matches!(probe.expectation, Expectation::Routed { .. }) {
            continue;
        }
        if seen.is_some() {
            arrived.push(probe.name);
        } else {
            missing.push(probe.name);
        }
    }
    format!(
        "routed: [{}], never arrived: [{}]",
        arrived.join(", "),
        missing.join(", ")
    )
}

/// Apply the parts of a contract that can only be judged once the serial
/// capture is complete. [`BootContract::Routed`] is decided entirely by frames
/// on the sockets, so its loop verdict already stands; a halt is decided by a
/// record the guest may have emitted in the same breath as powering off.
fn decide(
    loop_outcome: Result<(), String>,
    contract: &BootContract,
    output: &[u8],
    log_path: &Path,
) -> Result<(), String> {
    match (contract, loop_outcome) {
        (BootContract::Halted { marker }, Ok(())) if !contains(output, marker.as_bytes()) => {
            Err(format!(
                "QEMU exited without emitting {marker:?}, so the boot manager's halt path was \
                 never reached; see {}",
                log_path.display()
            ))
        }
        (_, outcome) => outcome,
    }
}

/// Whether `haystack` contains `needle` as a byte substring.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Render the per-endpoint injection failures as a clause to append to a
/// verdict, or the empty string when injection ran cleanly. A test that timed
/// out because it silently stopped feeding one port must say so.
fn describe_injection_failures(endpoints: &[AttachedEndpoint]) -> String {
    let reasons: Vec<String> = endpoints
        .iter()
        .filter_map(|attached| {
            attached.injection_failure.as_ref().map(|error| {
                format!(
                    "endpoint {} on port{}: {error}",
                    attached.endpoint.name(),
                    attached.endpoint.port
                )
            })
        })
        .collect();
    if reasons.is_empty() {
        String::new()
    } else {
        format!("; frame injection stopped for {}", reasons.join(", "))
    }
}

fn bind_listener() -> Result<TcpListener, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("bind harness listener: {error}"))?;
    // Non-blocking accept lets the timeout loop keep draining serial output
    // while it waits for QEMU to connect.
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set listener non-blocking: {error}"))?;
    Ok(listener)
}

/// Encode a frame for QEMU's `net_socket` STREAM backend: a 4-byte big-endian
/// (network order) length header followed by the raw frame bytes.
fn encode_wire(frame: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(4 + frame.len());
    wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    wire.extend_from_slice(frame);
    wire
}

/// Move every currently buffered serial chunk into `output`.
fn drain(receiver: &mpsc::Receiver<Vec<u8>>, output: &mut Vec<u8>) {
    while let Ok(chunk) = receiver.try_recv() {
        output.extend_from_slice(&chunk);
    }
}

/// Decode the guest's egress frames from one NIC socket (QEMU's length-framed
/// STREAM encoding) and send each as `(port, frame)` until the stream closes.
fn spawn_frame_decoder(
    port: usize,
    mut stream: TcpStream,
    sender: mpsc::Sender<(usize, Vec<u8>)>,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        loop {
            let mut header = [0u8; 4];
            match stream.read_exact(&mut header) {
                Ok(()) => {}
                // A closed or reset socket is QEMU exiting: a normal end.
                Err(ref error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            let length = u32::from_be_bytes(header) as usize;
            if length > MAX_WIRE_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("NIC socket announced an implausible frame length {length}"),
                ));
            }
            let mut frame = vec![0u8; length];
            match stream.read_exact(&mut frame) {
                Ok(()) => {}
                Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            }
            if sender.send((port, frame)).is_err() {
                return Ok(());
            }
        }
    })
}

/// Stream a piped child output into `sender` until EOF.
fn spawn_reader<R>(mut reader: R, sender: mpsc::Sender<Vec<u8>>) -> JoinHandle<io::Result<()>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            if sender.send(buffer[..count].to_vec()).is_err() {
                return Ok(());
            }
        }
    })
}

/// Join a reader thread, flattening a panic and an I/O error into a message.
fn join_reader(handle: JoinHandle<io::Result<()>>, name: &str) -> Result<(), String> {
    handle
        .join()
        .map_err(|_| format!("QEMU {name} reader panicked"))?
        .map_err(|error| format!("read QEMU {name}: {error}"))
}

/// Kill and reap the QEMU child, tolerating a process that has already exited.
fn terminate(child: &mut Child, reason: &str) -> Result<(), String> {
    match child.kill() {
        Ok(()) => {}
        Err(_error) if child.try_wait().ok().flatten().is_some() => {}
        Err(error) => return Err(format!("kill QEMU after {reason}: {error}")),
    }
    child
        .wait()
        .map_err(|error| format!("reap QEMU after {reason}: {error}"))?;
    Ok(())
}

/// Write the run log — the harness `header` followed by the captured serial
/// output — to `path`, creating parent directories.
fn write_capture(path: &Path, header: &str, output: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let mut bytes = Vec::with_capacity(header.len() + output.len());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(output);
    fs::write(path, &bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qemu::GuestNic;
    use std::collections::BTreeSet;

    const HEADER: &str = "# test header\n";

    /// The bench the appliance's own document describes — the same one
    /// scenario 1 boots against, so a probe built here is the probe the gate
    /// injects.
    fn bench() -> Topology {
        Topology::from_document(include_bytes!(
            "../../../systems/qemu-x86_64/configuration.xml"
        ))
        .expect("the shipped document describes the bench")
    }

    fn endpoints() -> [Endpoint; PORTS] {
        bench().endpoints()
    }

    /// The second bench scenario 3 plays, whose every address differs.
    fn alternate() -> Topology {
        Topology::from_document(include_bytes!("../scenarios/alternate-addressing.xml"))
            .expect("the alternate document describes a bench")
    }

    fn routed_test<'a>(log: &'a Path, topology: &'a Topology) -> BootTest<'a> {
        BootTest {
            contract: BootContract::Routed,
            log_path: log,
            log_header: HEADER,
            topology,
        }
    }

    /// The port-0-to-port-1 packet as injected, and the delivery it must
    /// produce.
    fn a_to_b() -> (UdpPacket, UdpPacket) {
        let [a, b] = endpoints();
        let sent = datagram(a, b, INJECTED_TTL, b"marker-0-to-1");
        let delivered = UdpPacket {
            destination_mac: b.mac,
            source_mac: b.gateway_mac,
            ttl: INJECTED_TTL - 1,
            ..sent.clone()
        };
        (sent, delivered)
    }

    #[test]
    fn the_bench_names_the_gateway_macs_qemu_puts_on_the_ports() {
        // The contract expects the appliance to answer to these, and QEMU is
        // what actually assigns them: a harness that expected a MAC no port
        // carries would fail with every frame refused and no reason visible.
        // Both sides now read the same document, so this is a check that the
        // derivation on each side lands on the same value rather than a check
        // between two literals.
        let topology = bench();
        for endpoint in topology.endpoints() {
            assert!(
                crate::qemu::nic_device(&topology, GuestNic::Dataplane(endpoint.port))
                    .unwrap()
                    .contains(&mac(endpoint.gateway_mac)),
                "endpoint {} expects a gateway MAC port{} does not carry",
                endpoint.name(),
                endpoint.port
            );
            assert_ne!(endpoint.mac, endpoint.gateway_mac);
        }
        let [a, b] = topology.endpoints();
        assert_ne!(a.mac, b.mac);
        assert_ne!(a.address, b.address);
    }

    /// A bench the appliance has a route into, or one carrying the MAC a
    /// refused probe is addressed to, would make two of the negatives assert a
    /// rule the document does not impose. Both are refused rather than
    /// injected.
    #[test]
    fn a_bench_that_would_make_a_refusal_wrong_is_refused_before_qemu_starts() {
        let covering = Topology::from_document(
            concat!(
                "<configuration><interfaces>",
                "<interface id=\"one\" port=\"0\" enabled=\"true\" mac=\"52:54:00:12:34:50\" ",
                "address=\"192.0.2.1\" prefix-length=\"24\"/>",
                "<interface id=\"two\" port=\"1\" enabled=\"true\" mac=\"52:54:00:12:34:51\" ",
                "address=\"10.0.1.1\" prefix-length=\"24\"/>",
                "</interfaces><neighbours>",
                "<neighbour id=\"one-a\" interface=\"one\" address=\"192.0.2.2\" ",
                "mac=\"52:54:00:00:00:0a\"/>",
                "<neighbour id=\"two-b\" interface=\"two\" address=\"10.0.1.2\" ",
                "mac=\"52:54:00:00:00:0b\"/>",
                "</neighbours>",
                "<management mac=\"52:54:00:12:34:52\" address=\"10.0.2.15\" ",
                "prefix-length=\"24\" enabled=\"true\"/>",
                "</configuration>"
            )
            .as_bytes(),
        )
        .expect("a valid document");
        let verdict = probes(&covering).expect_err("the appliance has a route for 192.0.2.9");
        assert!(verdict.contains("192.0.2.9"), "{verdict}");

        let claiming = Topology::from_document(
            concat!(
                "<configuration><interfaces>",
                "<interface id=\"one\" port=\"0\" enabled=\"true\" mac=\"52:54:00:99:99:99\" ",
                "address=\"10.0.0.1\" prefix-length=\"24\"/>",
                "<interface id=\"two\" port=\"1\" enabled=\"true\" mac=\"52:54:00:12:34:51\" ",
                "address=\"10.0.1.1\" prefix-length=\"24\"/>",
                "</interfaces><neighbours>",
                "<neighbour id=\"one-a\" interface=\"one\" address=\"10.0.0.2\" ",
                "mac=\"52:54:00:00:00:0a\"/>",
                "<neighbour id=\"two-b\" interface=\"two\" address=\"10.0.1.2\" ",
                "mac=\"52:54:00:00:00:0b\"/>",
                "</neighbours>",
                "<management mac=\"52:54:00:12:34:52\" address=\"10.0.2.15\" ",
                "prefix-length=\"24\" enabled=\"true\"/>",
                "</configuration>"
            )
            .as_bytes(),
        )
        .expect("a valid document");
        let verdict = probes(&claiming).expect_err("a port carries the foreign MAC");
        assert!(verdict.contains("52:54:00:99:99:99"), "{verdict}");
    }

    /// The bench the alternate scenario plays: every probe on it must carry
    /// that document's addresses and none of the shipped one's, or scenario 3
    /// would prove nothing.
    #[test]
    fn a_probe_carries_the_addresses_of_the_document_it_was_built_from() {
        let shipped_probes = probes(&bench()).expect("the shipped bench");
        let alternate_probes = probes(&alternate()).expect("the alternate bench");

        assert_eq!(shipped_probes.len(), alternate_probes.len());
        for (shipped, other) in shipped_probes.iter().zip(&alternate_probes) {
            assert_eq!(shipped.name, other.name);
            // The legacy L2 frame carries no address of either bench, so it is
            // the one probe the two documents agree on.
            if shipped.name == "legacy-l2-broadcast" {
                assert_eq!(shipped.frame, other.frame);
                continue;
            }
            assert_ne!(
                shipped.frame, other.frame,
                "probe {} is the same on both benches",
                shipped.name
            );
        }
    }

    #[test]
    fn a_built_datagram_decodes_back_to_the_fields_it_was_built_from() {
        // Round trip over payloads either side of the 60-byte Ethernet
        // minimum, so the padding path is covered by the identity it must not
        // break: padding is bytes L3 disclaims and may not become payload.
        for length in [0usize, 1, 17, 18, 19, 64, 512] {
            let (sent, delivered) = a_to_b();
            for packet in [
                UdpPacket {
                    payload: vec![0xa5; length],
                    ..sent.clone()
                },
                UdpPacket {
                    payload: vec![0x5a; length],
                    ..delivered.clone()
                },
            ] {
                let frame = packet.build();
                assert!(frame.len() >= MIN_ETHERNET_FRAME, "{length}");
                assert_eq!(UdpPacket::decode(&frame), Ok(packet), "payload of {length}");
            }
        }
    }

    #[test]
    fn a_built_header_carries_the_checksum_an_independent_sum_computes() {
        // The decoder validates the checksum with the same routine that wrote
        // it, so the value itself is pinned here against a differently written
        // sum over the wire bytes.
        let (sent, _) = a_to_b();
        let frame = sent.build();
        let header = &frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN];

        let mut total: u32 = 0;
        for index in 0..IPV4_HEADER_LEN / 2 {
            total += u32::from(u16::from_be_bytes([
                header[index * 2],
                header[index * 2 + 1],
            ]));
        }
        while total > 0xffff {
            total = (total & 0xffff) + (total >> 16);
        }
        assert_eq!(
            total, 0xffff,
            "a header carrying its own checksum sums to all ones"
        );
    }

    #[test]
    fn the_matcher_accepts_only_the_packet_the_route_produces() {
        let (sent, delivered) = a_to_b();
        let probe = routed(
            "under-test",
            b"marker-0-to-1",
            endpoints()[0],
            endpoints()[1],
            sent,
        );

        probe
            .judge(endpoints()[1].port, &delivered.build())
            .expect("the delivery the route produces is the one the matcher accepts");

        // One mutation per field the contract names; each must be refused, and
        // the verdict must name the field rather than merely the frame.
        let mutations: [(&str, UdpPacket); 7] = [
            (
                "destination MAC",
                UdpPacket {
                    destination_mac: [0x52, 0x54, 0x00, 0x00, 0x00, 0x0c],
                    ..delivered.clone()
                },
            ),
            (
                "source MAC",
                UdpPacket {
                    source_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x50],
                    ..delivered.clone()
                },
            ),
            (
                "TTL",
                UdpPacket {
                    ttl: INJECTED_TTL,
                    ..delivered.clone()
                },
            ),
            (
                "source address",
                UdpPacket {
                    source: [10, 0, 0, 3],
                    ..delivered.clone()
                },
            ),
            (
                "destination address",
                UdpPacket {
                    destination: [10, 0, 1, 3],
                    ..delivered.clone()
                },
            ),
            (
                "source port",
                UdpPacket {
                    source_port: SOURCE_PORT + 1,
                    ..delivered.clone()
                },
            ),
            (
                "destination port",
                UdpPacket {
                    destination_port: DESTINATION_PORT + 1,
                    ..delivered.clone()
                },
            ),
        ];
        for (field, mutated) in mutations {
            let verdict = probe
                .judge(endpoints()[1].port, &mutated.build())
                .expect_err("a mutated field must be refused");
            assert!(verdict.contains(field), "{field} unnamed in: {verdict}");
        }

        // The payload is compared as bytes, so an altered marker is refused as
        // a payload difference rather than as an unattributable frame.
        let altered = UdpPacket {
            payload: b"marker-0-to-C".to_vec(),
            ..delivered.clone()
        };
        let verdict = probe
            .judge(endpoints()[1].port, &altered.build())
            .expect_err("an altered payload must be refused");
        assert!(verdict.contains("payload"), "{verdict}");

        // A stale checksum never reaches the field comparison: it is refused
        // with the value it should have carried.
        let mut stale = delivered.build();
        stale[ETHERNET_HEADER_LEN + 10] ^= 0xff;
        let verdict = probe
            .judge(endpoints()[1].port, &stale)
            .expect_err("a stale checksum must be refused");
        assert!(
            verdict.contains("header checksum") && verdict.contains("not a well-formed"),
            "{verdict}"
        );

        // A trailing byte changes nothing the field view models, so it must be
        // caught by the whole-frame comparison behind it.
        let mut padded = delivered.build();
        padded.push(0x99);
        let verdict = probe
            .judge(endpoints()[1].port, &padded)
            .expect_err("a frame longer than the contract must be refused");
        assert!(verdict.contains("differs outside them"), "{verdict}");

        // The right packet on the wrong port is not a delivery.
        let verdict = probe
            .judge(endpoints()[0].port, &delivered.build())
            .expect_err("the far port is part of the contract");
        assert!(
            verdict.contains("port0") && verdict.contains("port1"),
            "{verdict}"
        );
    }

    #[test]
    fn every_defect_renders_as_the_values_that_caused_it() {
        // A delivery refused before the field comparison has only this line to
        // explain itself, so each rendering must be distinct and carry numbers.
        let renderings = [
            format!("{}", FrameDefect::TooShort { needed: 42, got: 9 }),
            format!("{}", FrameDefect::NotIpv4 { ether_type: 0x88b5 }),
            format!("{}", FrameDefect::VersionNotFour { version: 6 }),
            format!("{}", FrameDefect::OptionsPresent { ihl: 6 }),
            format!(
                "{}",
                FrameDefect::HeaderChecksumInvalid {
                    found: 0x1234,
                    computed: 0x5678,
                }
            ),
            format!("{}", FrameDefect::NotUdp { protocol: 6 }),
            format!(
                "{}",
                FrameDefect::TotalLengthBelowHeaders { total_length: 8 }
            ),
            format!(
                "{}",
                FrameDefect::TotalLengthBeyondFrame {
                    total_length: 9000,
                    frame_len: 60,
                }
            ),
            format!(
                "{}",
                FrameDefect::UdpLengthDisagrees {
                    udp_length: 1000,
                    total_length: 48,
                }
            ),
            format!(
                "{}",
                FrameDefect::UdpChecksumAdded {
                    udp_checksum: 0xbeef,
                }
            ),
        ];
        assert!(renderings[0].contains("42") && renderings[0].contains('9'));
        assert!(renderings[4].contains("0x1234") && renderings[4].contains("0x5678"));

        let mut distinct: Vec<&str> = renderings.iter().map(String::as_str).collect();
        distinct.sort_unstable();
        let count = distinct.len();
        distinct.dedup();
        assert_eq!(distinct.len(), count, "two defects read alike");
    }

    #[test]
    fn a_malformed_frame_is_refused_by_the_defect_it_carries() {
        let (_, delivered) = a_to_b();

        assert_eq!(
            UdpPacket::decode(&[0u8; 8]),
            Err(FrameDefect::TooShort {
                needed: MIN_UDP_FRAME,
                got: 8,
            })
        );
        assert_eq!(
            UdpPacket::decode(&legacy_broadcast_frame(b"legacy")),
            Err(FrameDefect::NotIpv4 {
                ether_type: LOCAL_EXPERIMENTAL_ETHERTYPE,
            })
        );

        // Each remaining defect is one edited byte, resealed where the edit is
        // not itself the checksum, so the checksum is never what refuses it.
        let ip = ETHERNET_HEADER_LEN;
        let mut version = delivered.build();
        version[ip] = 0x65;
        reseal(&mut version);
        assert_eq!(
            UdpPacket::decode(&version),
            Err(FrameDefect::VersionNotFour { version: 6 })
        );

        let mut options = delivered.build();
        options[ip] = 0x46;
        reseal(&mut options);
        assert_eq!(
            UdpPacket::decode(&options),
            Err(FrameDefect::OptionsPresent { ihl: 6 })
        );

        let mut protocol = delivered.build();
        protocol[ip + 9] = 6;
        reseal(&mut protocol);
        assert_eq!(
            UdpPacket::decode(&protocol),
            Err(FrameDefect::NotUdp { protocol: 6 })
        );

        let mut short = delivered.build();
        short[ip + 2..ip + 4].copy_from_slice(&8u16.to_be_bytes());
        reseal(&mut short);
        assert_eq!(
            UdpPacket::decode(&short),
            Err(FrameDefect::TotalLengthBelowHeaders { total_length: 8 })
        );

        let mut beyond = delivered.build();
        let frame_len = beyond.len();
        beyond[ip + 2..ip + 4].copy_from_slice(&9000u16.to_be_bytes());
        beyond[ip + IPV4_HEADER_LEN + 4..ip + IPV4_HEADER_LEN + 6]
            .copy_from_slice(&8980u16.to_be_bytes());
        reseal(&mut beyond);
        assert_eq!(
            UdpPacket::decode(&beyond),
            Err(FrameDefect::TotalLengthBeyondFrame {
                total_length: 9000,
                frame_len,
            })
        );

        let mut udp_length = delivered.build();
        let udp = ip + IPV4_HEADER_LEN;
        udp_length[udp + 4..udp + 6].copy_from_slice(&1000u16.to_be_bytes());
        assert!(matches!(
            UdpPacket::decode(&udp_length),
            Err(FrameDefect::UdpLengthDisagrees {
                udp_length: 1000,
                ..
            })
        ));

        let mut udp_checksum = delivered.build();
        udp_checksum[udp + 6..udp + 8].copy_from_slice(&0xbeefu16.to_be_bytes());
        assert_eq!(
            UdpPacket::decode(&udp_checksum),
            Err(FrameDefect::UdpChecksumAdded {
                udp_checksum: 0xbeef,
            })
        );
    }

    /// Rebuild the header checksum after an edit, so a rejection that only
    /// fired because the checksum went stale proves nothing about the field the
    /// case is aimed at.
    fn reseal(frame: &mut [u8]) {
        let header: &mut [u8; IPV4_HEADER_LEN] = (&mut frame
            [ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN])
            .try_into()
            .expect("a 20-byte window");
        let checksum = header_checksum(header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
    fn every_probe_is_attributable_to_itself_alone() {
        let probes = probes(&bench()).expect("the shipped bench");
        assert_eq!(probes.len(), 6);
        for probe in &probes {
            assert!(
                contains(&probe.frame, probe.marker),
                "probe {} does not carry its own marker",
                probe.name
            );
            for other in &probes {
                if other.name == probe.name {
                    continue;
                }
                assert!(
                    !contains(&other.frame, probe.marker),
                    "probe {}'s marker also appears in {}",
                    probe.name,
                    other.name
                );
                assert_ne!(other.name, probe.name);
            }
        }
    }

    #[test]
    fn the_two_routed_probes_cross_the_appliance_in_opposite_directions() {
        let probes = probes(&bench()).expect("the shipped bench");
        let routes: Vec<(usize, usize)> = probes
            .iter()
            .filter_map(|probe| match &probe.expectation {
                Expectation::Routed { to, .. } => Some((probe.from.port, to.port)),
                Expectation::Dropped { .. } => None,
            })
            .collect();
        assert_eq!(routes, [(0, 1), (1, 0)]);
    }

    #[test]
    fn every_refused_probe_is_refused_wherever_it_surfaces() {
        // The negatives carry no egress port, so a delivery on either port is a
        // failure — and the verdict has to name the rule that was broken.
        for probe in probes(&bench()).expect("the shipped bench") {
            let Expectation::Dropped { because } = probe.expectation else {
                continue;
            };
            for port in 0..PORTS {
                let verdict = probe
                    .judge(port, &probe.frame)
                    .expect_err("a refused probe must never be accepted");
                assert!(
                    verdict.contains(probe.name) && verdict.contains(because),
                    "{verdict}"
                );
            }
        }
    }

    #[test]
    fn the_retired_l2_frame_is_the_one_the_old_contract_required_to_be_forwarded() {
        // Kept as a negative precisely because it used to be the positive: if
        // it ever became routable again the change would be silent otherwise.
        let frame = legacy_broadcast_frame(b"legacy");
        assert_eq!(frame.len(), MIN_ETHERNET_FRAME);
        assert_eq!(&frame[0..6], [0xff_u8; 6].as_slice());
        assert_eq!(
            &frame[12..14],
            LOCAL_EXPERIMENTAL_ETHERTYPE.to_be_bytes().as_slice()
        );
        assert!(frame[14..].starts_with(b"legacy"));
    }

    #[test]
    fn the_routed_contract_is_only_met_once_both_directions_have_arrived() {
        let probes = probes(&bench()).expect("the shipped bench");
        let at = |name: &str| {
            probes
                .iter()
                .position(|probe| probe.name == name)
                .expect("the probe set names this probe")
        };

        // Marking every refused probe cannot satisfy the contract: only the two
        // routed ones count towards it.
        let arrived = arrival(&probes[at("routed-0-to-1")]);
        let mut deliveries: Vec<Option<Delivery>> = probes
            .iter()
            .map(|probe| match probe.expectation {
                Expectation::Dropped { .. } => Some(arrived.clone()),
                Expectation::Routed { .. } => None,
            })
            .collect();
        assert!(!all_routed(&probes, &deliveries));

        deliveries = vec![None; probes.len()];
        deliveries[at("routed-0-to-1")] = Some(arrived);
        assert!(!all_routed(&probes, &deliveries));
        let pending = describe_pending(&probes, &deliveries);
        assert!(
            pending.contains("routed: [routed-0-to-1]")
                && pending.contains("never arrived: [routed-1-to-0]"),
            "{pending}"
        );

        // Re-injection stops for what has arrived and continues for the rest,
        // so a delivered direction is not re-sent while the other is waited on.
        assert!(is_delivered(
            &probes,
            &deliveries,
            &probes[at("routed-0-to-1")]
        ));
        assert!(!is_delivered(
            &probes,
            &deliveries,
            &probes[at("routed-1-to-0")]
        ));
        assert!(!is_delivered(&probes, &deliveries, &probes[at("no-route")]));

        deliveries[at("routed-1-to-0")] = Some(arrival(&probes[at("routed-1-to-0")]));
        assert!(all_routed(&probes, &deliveries));
    }

    /// The delivery a routed probe's own contract produces, taken by judging
    /// the frame that contract describes — so a test's notion of an arrival is
    /// the harness's own, never a hand-built stand-in that could agree with
    /// nothing the run would accept.
    fn arrival(probe: &Probe) -> Delivery {
        let Expectation::Routed { to, delivered, .. } = &probe.expectation else {
            panic!("probe {} is not one that routes", probe.name);
        };
        probe
            .judge(to.port, &delivered.build())
            .expect("the delivery a route produces is the one the matcher accepts")
    }

    #[test]
    fn a_delivered_row_reports_the_frame_that_arrived_and_not_the_contract() {
        // The whole value of the report: a row must be readable off the wire.
        // Every number below is checked against the frame, so a row rendered
        // from the expectation instead would still read plausibly and would
        // stop proving anything.
        let probes = probes(&bench()).expect("the shipped bench");
        let deliveries: Vec<Option<Delivery>> = probes
            .iter()
            .map(|probe| match probe.expectation {
                Expectation::Routed { .. } => Some(arrival(probe)),
                Expectation::Dropped { .. } => None,
            })
            .collect();
        let report = TrafficReport::new(endpoints(), &probes, &deliveries, None);
        let rendered = report.render();

        assert_eq!(report.summary(), "2 routed, 4 dropped");
        assert!(
            !rendered.contains("unfinished"),
            "every probe reached an end state: {rendered}"
        );
        for probe in &probes {
            assert!(rendered.contains(probe.name), "{}\n{rendered}", probe.name);
        }
        // A->B: the far endpoint's address and MAC, the far interface as the
        // new source MAC, one TTL gone, and the length the frame arrived at.
        let [a, b] = endpoints();
        let delivered = "delivered  routed-0-to-1";
        let line = rendered
            .lines()
            .find(|line| line.contains(delivered))
            .unwrap_or_else(|| panic!("no delivered row for routed-0-to-1:\n{rendered}"));
        assert!(
            line.contains(&format!("{}->{}", a.name(), b.name())),
            "{line}"
        );
        assert!(
            line.contains(&format!("{}:{SOURCE_PORT} -> ", ipv4(a.address)))
                && line.contains(&format!("{}:{DESTINATION_PORT}", ipv4(b.address))),
            "{line}"
        );
        assert!(
            line.contains(&format!("ttl {INJECTED_TTL}->{}", INJECTED_TTL - 1)),
            "{line}"
        );
        assert!(
            line.contains(&format!("mac {}->{}", mac(b.gateway_mac), mac(b.mac))),
            "{line}"
        );
        let frame_len = MIN_ETHERNET_FRAME.max(MIN_UDP_FRAME + b"LFW-PROBE/routed-0-to-1".len());
        assert!(line.contains(&format!("{frame_len} bytes")), "{line}");

        // Every refused probe reports the rule it demonstrates, and none of
        // them claims a far end.
        for probe in &probes {
            let Expectation::Dropped { because } = probe.expectation else {
                continue;
            };
            let line = rendered
                .lines()
                .find(|line| line.contains(probe.name))
                .unwrap_or_else(|| panic!("no row for {}:\n{rendered}", probe.name));
            assert!(line.contains("dropped") && line.contains(because), "{line}");
            assert!(
                line.contains(&format!("{}->.", probe.from.name())),
                "a refused probe reached no far end: {line}"
            );
        }

        // The topology the rows are read against, so the MACs in them can be
        // attributed to an endpoint or to an appliance port.
        for endpoint in endpoints() {
            assert!(
                rendered.contains(&format!(
                    "endpoint {}  {}  {}",
                    endpoint.name(),
                    ipv4(endpoint.address),
                    mac(endpoint.mac)
                )) && rendered.contains(&mac(endpoint.gateway_mac)),
                "{rendered}"
            );
        }
    }

    #[test]
    fn a_failed_run_marks_the_probe_that_failed_and_the_ones_that_never_came() {
        // The report is also the failure's first line of explanation, so the
        // three states a failed run distinguishes must be visible in it: the
        // probe that broke the contract, the one still outstanding, and the
        // refusals that behaved.
        let probes = probes(&bench()).expect("the shipped bench");
        let at = |name: &str| {
            probes
                .iter()
                .position(|probe| probe.name == name)
                .expect("the probe set names this probe")
        };
        let mut deliveries: Vec<Option<Delivery>> = vec![None; probes.len()];
        deliveries[at("routed-0-to-1")] = Some(arrival(&probes[at("routed-0-to-1")]));

        let report =
            TrafficReport::new(endpoints(), &probes, &deliveries, Some(at("routed-1-to-0")));
        let rendered = report.render();
        let row = |name: &str| {
            rendered
                .lines()
                .find(|line| line.contains(name))
                .unwrap_or_else(|| panic!("no row for {name}:\n{rendered}"))
                .to_owned()
        };

        assert!(row("routed-1-to-0").contains("failed"), "{rendered}");
        assert!(
            rendered.contains("unfinished"),
            "a run that ended early must not present its refusals as judged: {rendered}"
        );
        assert!(row("routed-0-to-1").contains("delivered"), "{rendered}");
        assert!(row("no-route").contains("dropped"), "{rendered}");
        // One direction delivered is not two, and the failure must not be
        // countable as either outcome.
        assert_eq!(report.summary(), "1 routed, 4 dropped");

        // A routed probe that simply never arrived is neither a failure of its
        // own nor a delivery: it is outstanding, and says so.
        let nothing: Vec<Option<Delivery>> = vec![None; probes.len()];
        let outstanding = TrafficReport::new(endpoints(), &probes, &nothing, None);
        assert!(
            outstanding.render().contains("missing"),
            "{}",
            outstanding.render()
        );
        assert_eq!(outstanding.summary(), "0 routed, 4 dropped");
    }

    #[test]
    fn a_refused_probe_that_came_back_is_never_reported_as_a_refusal() {
        // The run fails the instant a refusal is delivered, so this state is
        // only reachable where a delivery was recorded against a probe that
        // must never produce one. Reporting it as "dropped" would render the
        // one case the contract exists to catch as a pass.
        let probes = probes(&bench()).expect("the shipped bench");
        let refused = probes
            .iter()
            .position(|probe| matches!(probe.expectation, Expectation::Dropped { .. }))
            .expect("the probe set refuses something");
        let mut deliveries: Vec<Option<Delivery>> = vec![None; probes.len()];
        deliveries[refused] = Some(arrival(&probes[0]));

        let report = TrafficReport::new(endpoints(), &probes, &deliveries, None);
        let line = report
            .render()
            .lines()
            .find(|line| line.contains(probes[refused].name))
            .expect("the refused probe has a row")
            .to_owned();
        assert!(
            line.contains("failed") && line.contains("came back"),
            "{line}"
        );
        assert_eq!(report.summary(), "0 routed, 3 dropped");
    }

    #[test]
    fn nic_backends_produce_per_port_socket_and_device_arguments() {
        let backends = NicBackends::new(ManagementBacking::Socket).unwrap();
        let mut command = Command::new("qemu-system-x86_64");
        backends.apply(&mut command, &bench()).unwrap();

        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let devices: Vec<&String> = args
            .iter()
            .filter(|arg| arg.starts_with("virtio-net-pci"))
            .collect();
        // Every port the image expects a device on, the management one included:
        // a driver instance with no device at its ECAM page parks on a refusal,
        // which is a boot no shipped image performs.
        assert_eq!(devices.len(), MANAGEMENT_SLOT + 1);
        assert!(devices[0].contains("addr=02.0") && devices[0].contains("romfile="));
        assert!(devices[1].contains("addr=03.0") && devices[1].contains("romfile="));
        assert!(
            devices[MANAGEMENT_SLOT].contains("addr=04.0")
                && devices[MANAGEMENT_SLOT].contains(&mac(bench().management().mac))
        );
        let netdevs: Vec<&String> = args
            .iter()
            .filter(|arg| arg.starts_with("socket,id="))
            .collect();
        assert_eq!(netdevs.len(), MANAGEMENT_SLOT + 1);
        let distinct: BTreeSet<&&String> = netdevs.iter().collect();
        assert_eq!(
            distinct.len(),
            netdevs.len(),
            "each port needs its own listener"
        );
    }

    /// The management frames are what the console's count is judged against, so
    /// the two must be derived from one place. This is that derivation: the four
    /// opaque frames, none of them padded and none a multiple of another — which
    /// is what stops a domain that summed a constant from reproducing the total —
    /// followed by the two the endpoint must answer.
    #[test]
    fn the_management_probe_reports_exactly_the_frames_it_built() {
        let management = bench().management();
        let (probe, injection) = ManagementProbe::new(management);
        assert_eq!(probe.frames.len(), MANAGEMENT_FRAMES.len() + 2);
        assert_eq!(injection.frames, probe.frames.len());
        assert_eq!(
            injection.bytes,
            probe
                .frames
                .iter()
                .map(|frame| frame.len() as u64)
                .sum::<u64>()
        );
        assert!(!injection.is_empty());

        let mut lengths = Vec::new();
        for (frame, len) in probe.frames.iter().zip(MANAGEMENT_FRAMES) {
            // Nothing pads: every length is at or above the Ethernet minimum,
            // so the length QEMU delivers is the length written and the byte
            // total is the sum of these and not of something wider.
            assert_eq!(frame.len(), len);
            assert!(len >= MIN_ETHERNET_FRAME);
            assert!(contains(frame, MANAGEMENT_MARKER));
            // Addressed to the management port from the harness's station, so a
            // frame on that wire is attributable in a capture.
            assert!(frame.starts_with(&management.mac));
            assert!(frame[6..12] == MANAGEMENT_STATION_MAC);
            lengths.push(len);
        }
        for pair in lengths.windows(2) {
            if let [shorter, longer] = pair {
                assert!(longer > shorter, "the lengths must be distinct and ordered");
                assert!(
                    !longer.is_multiple_of(*shorter),
                    "a length that is a multiple of another lets a constant sum agree"
                );
            }
        }

        // The two protocol frames are the last two, and neither carries the
        // opaque marker: they are answered rather than merely counted, so a
        // reply reaching the wire must not read as one of them coming back.
        let arp = &probe.frames[MANAGEMENT_FRAMES.len()];
        let echo = &probe.frames[MANAGEMENT_FRAMES.len() + 1];
        assert_eq!(
            arp.len(),
            ARP_FRAME_LEN,
            "an ARP request is 42 bytes unpadded"
        );
        assert!(!contains(arp, MANAGEMENT_MARKER));
        assert!(!contains(echo, MANAGEMENT_MARKER));
        assert!(contains(echo, ECHO_PAYLOAD));
    }

    /// Both requests must be exactly what the endpoint expects to see, or the
    /// contract tests something the appliance was right to refuse. Each is
    /// decoded by the harness's own reader, which is what the replies are judged
    /// with too.
    #[test]
    fn the_two_requests_the_management_port_is_asked_carry_the_benchs_addresses() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let arp = decode_arp(&probe.frames[MANAGEMENT_FRAMES.len()]).expect("a well-formed ARP");
        assert_eq!(
            arp,
            ArpFrame {
                destination_mac: [0xff; 6],
                source_mac: MANAGEMENT_STATION_MAC,
                operation: ARP_REQUEST,
                sender_mac: MANAGEMENT_STATION_MAC,
                sender_address: management.station,
                target_mac: [0; 6],
                target_address: management.address,
            }
        );

        let echo =
            decode_echo(&probe.frames[MANAGEMENT_FRAMES.len() + 1]).expect("a well-formed echo");
        assert_eq!(
            echo,
            EchoFrame {
                destination_mac: management.mac,
                source_mac: MANAGEMENT_STATION_MAC,
                source: management.station,
                destination: management.address,
                ttl: INJECTED_TTL,
                message_type: ICMP_ECHO_REQUEST,
                code: 0,
                identifier: ECHO_IDENTIFIER,
                sequence: ECHO_SEQUENCE,
                payload: ECHO_PAYLOAD.to_vec(),
            }
        );
    }

    /// The reply each request obliges, built here as the appliance must build it
    /// — and then the same reply with one field moved at a time, every one of
    /// which must be refused by name.
    #[test]
    fn only_the_reply_the_endpoint_owes_is_accepted_and_a_moved_field_is_named() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let probes = probes(&bench()).expect("the shipped bench");

        assert_eq!(
            probe.judge(
                &arp_reply(&management, |_| {}),
                &probes,
                &mut TcpClient::new()
            ),
            Ok(ManagementReply::Arp)
        );
        assert_eq!(
            probe.judge(
                &echo_reply(&management, |_| {}),
                &probes,
                &mut TcpClient::new()
            ),
            Ok(ManagementReply::Echo)
        );

        let arp_mutations: [ArpMutation; 5] = [
            ("destination MAC", |reply| reply.destination_mac = [1; 6]),
            ("source MAC", |reply| reply.source_mac = [2; 6]),
            ("operation", |reply| reply.operation = ARP_REQUEST),
            ("sender address", |reply| {
                reply.sender_address = [9, 9, 9, 9]
            }),
            ("target address", |reply| {
                reply.target_address = [8, 8, 8, 8]
            }),
        ];
        for (field, mutate) in arp_mutations {
            let verdict = probe
                .judge(
                    &arp_reply(&management, mutate),
                    &probes,
                    &mut TcpClient::new(),
                )
                .expect_err("a moved field must be refused");
            assert!(verdict.contains(field), "{field} unnamed in: {verdict}");
        }

        let echo_mutations: [EchoMutation; 6] = [
            ("source address", |reply| reply.source = [9, 9, 9, 9]),
            ("destination address", |reply| {
                reply.destination = [8, 8, 8, 8]
            }),
            ("ICMP type", |reply| reply.message_type = ICMP_ECHO_REQUEST),
            ("identifier", |reply| reply.identifier = 1),
            ("sequence", |reply| reply.sequence = 1),
            ("payload", |reply| {
                reply.payload = b"something else".to_vec()
            }),
        ];
        for (field, mutate) in echo_mutations {
            let verdict = probe
                .judge(
                    &echo_reply(&management, mutate),
                    &probes,
                    &mut TcpClient::new(),
                )
                .expect_err("a moved field must be refused");
            assert!(verdict.contains(field), "{field} unnamed in: {verdict}");
        }
    }

    /// Everything else that can arrive on that wire, and the reason each is a
    /// failure rather than noise.
    #[test]
    fn a_frame_the_endpoint_never_owed_is_refused_wherever_it_came_from() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let probes = probes(&bench()).expect("the shipped bench");

        // A dataplane probe: the isolation CONCEPT §9.1 requires, in the
        // direction a leak would be silent.
        let leaked = &probes[0].frame;
        let verdict = probe
            .judge(leaked, &probes, &mut TcpClient::new())
            .expect_err("a dataplane probe on the management wire");
        assert!(verdict.contains(probes[0].name), "{verdict}");
        assert!(verdict.contains("isolates that port"), "{verdict}");

        // One of the opaque frames coming back: the endpoint answers nothing for
        // that EtherType, so it must count it and stay silent.
        let verdict = probe
            .judge(&probe.frames[0], &probes, &mut TcpClient::new())
            .expect_err("an opaque frame must never be answered");
        assert!(verdict.contains("say nothing"), "{verdict}");

        // A protocol the endpoint does not speak, and a frame too short to name
        // one at all.
        for frame in [legacy_broadcast_frame(b"unrelated"), vec![0u8; 4]] {
            let verdict = probe
                .judge(&frame, &probes, &mut TcpClient::new())
                .expect_err("nothing else may come back");
            assert!(
                verdict.contains("answers ARP and ICMP echo alone"),
                "{verdict}"
            );
        }

        // A malformed reply of the right EtherType is refused by the field that
        // refused it, rather than read as a different reply.
        let mut corrupt = echo_reply(&management, |_| {});
        corrupt[ETHERNET_HEADER_LEN + 10] ^= 0xff;
        let verdict = probe
            .judge(&corrupt, &probes, &mut TcpClient::new())
            .expect_err("a stale checksum");
        assert!(verdict.contains("IPv4 checksum"), "{verdict}");

        let mut short_arp = arp_reply(&management, |_| {});
        short_arp.truncate(ARP_FRAME_LEN - 1);
        let verdict = probe
            .judge(&short_arp, &probes, &mut TcpClient::new())
            .expect_err("a truncated ARP");
        assert!(verdict.contains("short of the"), "{verdict}");
    }

    /// The evidence a passing run prints names the values `judge` refused a
    /// frame for not carrying, so the two cannot drift apart.
    #[test]
    fn each_answer_is_reported_with_the_values_it_was_judged_against() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let arp = probe.answered(ManagementReply::Arp);
        assert!(arp.contains(&ipv4(management.address)), "{arp}");
        assert!(arp.contains(&ipv4(management.station)), "{arp}");
        assert!(arp.contains(&mac(management.mac)), "{arp}");

        let echo = probe.answered(ManagementReply::Echo);
        assert!(echo.contains(&ipv4(management.address)), "{echo}");
        assert!(echo.contains(&ipv4(management.station)), "{echo}");
        assert!(echo.contains(&format!("{ECHO_IDENTIFIER:#06x}")), "{echo}");
        assert!(echo.contains(&format!("{ECHO_SEQUENCE:#06x}")), "{echo}");
        assert!(echo.contains(&ECHO_REPLY_TTL.to_string()), "{echo}");
    }

    /// Each reply is owed exactly once, and the port must answer both before a
    /// boot has met the contract.
    #[test]
    fn both_replies_are_owed_and_neither_may_arrive_twice() {
        let mut wire = ManagementWire {
            wire: TcpStream::connect(
                TcpListener::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap(),
            )
            .unwrap(),
            injection_failure: None,
            arp_reply: false,
            echo_reply: false,
            client: TcpClient::new(),
            injected: ManagementInjection::default(),
        };
        assert!(!wire.answered());
        assert!(!wire.stateless_replies_in());
        assert!(wire.outstanding().contains("ARP") && wire.outstanding().contains("echo"));

        wire.accept(ManagementReply::Arp).expect("the first");
        assert!(!wire.answered());
        assert!(wire.outstanding().contains("ICMP echo reply"));
        let verdict = wire
            .accept(ManagementReply::Arp)
            .expect_err("one request is one reply");
        assert!(verdict.contains("a second"), "{verdict}");

        wire.accept(ManagementReply::Echo).expect("the second");
        // Both stateless replies are in, and the connection is still owed: that is
        // the point at which the client opens one.
        assert!(wire.stateless_replies_in());
        assert!(!wire.answered());
        assert_eq!(wire.outstanding(), "the TCP exchange has not been started");

        // A TCP step is not a reply that may arrive twice: the connection's own
        // state machine orders its segments, so `accept` has nothing to refuse.
        wire.accept(ManagementReply::Tcp(TcpStep::AwaitSynAck))
            .expect("a step is not a reply");
        wire.client.step = TcpStep::Closed;
        assert!(wire.answered());
        assert_eq!(wire.outstanding(), "none");
    }

    /// The reply the appliance owes, as this harness builds it for its own
    /// negative tests: `mutate` moves one field so a refusal can be attributed.
    /// One named field of a reply fixture, and the edit that moves it.
    type ArpMutation = (&'static str, fn(&mut ArpFrame));
    type EchoMutation = (&'static str, fn(&mut EchoFrame));

    fn arp_reply(management: &ManagementPort, mutate: impl Fn(&mut ArpFrame)) -> Vec<u8> {
        let mut fields = ArpFrame {
            destination_mac: MANAGEMENT_STATION_MAC,
            source_mac: management.mac,
            operation: ARP_REPLY,
            sender_mac: management.mac,
            sender_address: management.address,
            target_mac: MANAGEMENT_STATION_MAC,
            target_address: management.station,
        };
        mutate(&mut fields);
        let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
        frame.extend_from_slice(&fields.destination_mac);
        frame.extend_from_slice(&fields.source_mac);
        frame.extend_from_slice(&ARP_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&fields.operation.to_be_bytes());
        frame.extend_from_slice(&fields.sender_mac);
        frame.extend_from_slice(&fields.sender_address);
        frame.extend_from_slice(&fields.target_mac);
        frame.extend_from_slice(&fields.target_address);
        frame
    }

    /// As [`arp_reply`], for the echo reply.
    fn echo_reply(management: &ManagementPort, mutate: impl Fn(&mut EchoFrame)) -> Vec<u8> {
        let mut fields = EchoFrame {
            destination_mac: MANAGEMENT_STATION_MAC,
            source_mac: management.mac,
            source: management.address,
            destination: management.station,
            ttl: ECHO_REPLY_TTL,
            message_type: ICMP_ECHO_REPLY,
            code: 0,
            identifier: ECHO_IDENTIFIER,
            sequence: ECHO_SEQUENCE,
            payload: ECHO_PAYLOAD.to_vec(),
        };
        mutate(&mut fields);

        let mut icmp = Vec::new();
        icmp.push(fields.message_type);
        icmp.push(fields.code);
        icmp.extend_from_slice(&[0, 0]);
        icmp.extend_from_slice(&fields.identifier.to_be_bytes());
        icmp.extend_from_slice(&fields.sequence.to_be_bytes());
        icmp.extend_from_slice(&fields.payload);
        let checksum = message_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = Vec::new();
        frame.extend_from_slice(&fields.destination_mac);
        frame.extend_from_slice(&fields.source_mac);
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + icmp.len()) as u16).to_be_bytes());
        ip[8] = fields.ttl;
        ip[9] = ICMP_PROTOCOL;
        ip[12..16].copy_from_slice(&fields.source);
        ip[16..20].copy_from_slice(&fields.destination);
        let checksum = header_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&icmp);
        frame
    }

    /// No dataplane probe may carry anything the management wire's traffic does,
    /// and no management frame a probe's marker: the two directions of the
    /// isolation check rest on exactly that.
    #[test]
    fn nothing_on_one_wire_is_mistakable_for_traffic_on_the_other() {
        for topology in [bench(), alternate()] {
            let management = topology.management();
            let (probe, _) = ManagementProbe::new(management);
            for dataplane in probes(&topology).expect("a bench") {
                assert!(
                    !carries_management_traffic(&dataplane.frame, &management),
                    "{}",
                    dataplane.name
                );
                for frame in &probe.frames {
                    assert!(!contains(frame, dataplane.marker), "{}", dataplane.name);
                }
            }
            // And every frame the harness puts on the management wire is
            // recognisable as management traffic, which is what makes the
            // dataplane-side check able to see a leak at all.
            for frame in &probe.frames {
                assert!(carries_management_traffic(frame, &management));
            }
            assert!(carries_management_traffic(
                &arp_reply(&management, |_| {}),
                &management
            ));
            assert!(carries_management_traffic(
                &echo_reply(&management, |_| {}),
                &management
            ));
        }
    }

    #[test]
    fn frame_decoder_reassembles_length_framed_frames() {
        // A local socket pair carrying two frames in QEMU's framing, the
        // second arriving byte-dribbled, must decode into exactly those
        // frames tagged with the decoder's port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut writer = TcpStream::connect(address).unwrap();
        let (stream, _peer) = listener.accept().unwrap();

        let (sender, receiver) = mpsc::channel();
        let decoder = spawn_frame_decoder(1, stream, sender);

        let first = legacy_broadcast_frame(b"FIRST");
        let second = legacy_broadcast_frame(b"SECOND");
        writer.write_all(&encode_wire(&first)).unwrap();
        for byte in encode_wire(&second) {
            writer.write_all(&[byte]).unwrap();
        }
        drop(writer);

        assert_eq!(receiver.recv().unwrap(), (1, first));
        assert_eq!(receiver.recv().unwrap(), (1, second));
        assert!(receiver.recv().is_err(), "decoder must close after EOF");
        decoder.join().unwrap().unwrap();
    }

    #[test]
    fn frame_decoder_rejects_an_implausible_length() {
        // A length header beyond MAX_WIRE_FRAME is a corrupt stream, not a
        // jumbo frame: the decoder must fail with InvalidData and emit nothing.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut writer = TcpStream::connect(address).unwrap();
        let (stream, _peer) = listener.accept().unwrap();

        let (sender, receiver) = mpsc::channel();
        let decoder = spawn_frame_decoder(0, stream, sender);

        writer
            .write_all(&((MAX_WIRE_FRAME as u32) + 1).to_be_bytes())
            .unwrap();

        let error = decoder.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(receiver.recv().is_err(), "no frame may be emitted");
        drop(writer);
    }

    #[test]
    fn frame_decoder_decodes_a_zero_length_frame_as_empty() {
        // A zero-length frame is accepted (not rejected) and surfaces as an
        // empty vec; it carries no marker, so it is attributed to no probe.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut writer = TcpStream::connect(address).unwrap();
        let (stream, _peer) = listener.accept().unwrap();

        let (sender, receiver) = mpsc::channel();
        let decoder = spawn_frame_decoder(0, stream, sender);

        writer.write_all(&0u32.to_be_bytes()).unwrap();
        drop(writer);

        assert_eq!(receiver.recv().unwrap(), (0, Vec::new()));
        assert!(receiver.recv().is_err(), "decoder closes after EOF");
        decoder.join().unwrap().unwrap();
        for probe in probes(&bench()).expect("the shipped bench") {
            assert!(!contains(&[], probe.marker));
        }
    }

    #[test]
    fn marker_search_matches_only_an_exact_byte_substring() {
        let capture = b"noise\r\nLFW-BOOT slot=none state=halted\r\nmore".as_slice();
        assert!(contains(capture, b"LFW-BOOT slot=none state=halted"));
        assert!(!contains(capture, b"LFW-BOOT slot=A state=halted"));
        // A marker longer than the capture, and an empty marker, must never
        // read as a match: an empty needle would make every halt test pass.
        assert!(!contains(b"short", b"a much longer needle"));
        assert!(!contains(capture, b""));
    }

    #[test]
    fn injection_failures_are_named_per_endpoint_in_a_verdict() {
        assert_eq!(describe_injection_failures(&[]), "");

        let described = describe_injection_failures(&[
            attached(endpoints()[0], None),
            attached(
                endpoints()[1],
                Some(io::Error::new(io::ErrorKind::BrokenPipe, "gone")),
            ),
        ]);
        assert!(described.contains("port1"), "unexpected: {described}");
        assert!(!described.contains("port0"), "unexpected: {described}");
        assert!(described.contains("gone"), "the cause must survive");
        assert!(
            described.contains(endpoints()[1].name()),
            "the endpoint must be named by the id the document gave it: {described}"
        );

        let described = describe_injection_failures(&[
            attached(
                endpoints()[0],
                Some(io::Error::new(io::ErrorKind::BrokenPipe, "left")),
            ),
            attached(
                endpoints()[1],
                Some(io::Error::new(io::ErrorKind::BrokenPipe, "right")),
            ),
        ]);
        assert!(described.contains("port0") && described.contains("port1"));
    }

    /// An [`AttachedEndpoint`] over a connected loopback socket, so the failure
    /// reporting can be exercised without QEMU.
    fn attached(endpoint: Endpoint, injection_failure: Option<io::Error>) -> AttachedEndpoint {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let wire = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        AttachedEndpoint {
            endpoint,
            wire,
            injection_failure,
        }
    }

    #[test]
    fn a_retired_endpoint_is_never_written_to_again() {
        // A broken socket must not be retried on every cadence tick, and the
        // first reason must be the one reported rather than the last.
        let mut endpoint = attached(
            endpoints()[0],
            Some(io::Error::new(io::ErrorKind::BrokenPipe, "first")),
        );
        endpoint.inject(b"anything");
        assert_eq!(
            endpoint.injection_failure.as_ref().unwrap().to_string(),
            "first"
        );
    }

    #[test]
    fn a_halt_contract_is_only_satisfied_by_the_marker_after_the_final_drain() {
        let log = Path::new("/nonexistent/never-written.log");
        let contract = BootContract::Halted {
            marker: "LFW-BOOT slot=none state=halted",
        };

        // QEMU exiting is not on its own proof of a halt: without the record
        // the verdict must flip to a failure naming what was missing.
        let error = decide(Ok(()), &contract, b"booting...", log).unwrap_err();
        assert!(error.contains("halt path was never reached"), "{error}");

        // The same exit with the record present is the success it claims to be.
        decide(
            Ok(()),
            &contract,
            b"x\r\nLFW-BOOT slot=none state=halted\r\n",
            log,
        )
        .unwrap();

        // A verdict the loop already reached is never overridden.
        let error = decide(Err("real failure".to_owned()), &contract, b"", log).unwrap_err();
        assert_eq!(error, "real failure");

        // The routed contract is decided by frames alone, so serial text must
        // not enter into it either way.
        decide(Ok(()), &BootContract::Routed, b"", log).unwrap();
    }

    #[test]
    fn the_run_log_carries_the_harness_header_ahead_of_the_guest_output() {
        let log = temp_log("capture-header");
        let _ = fs::remove_file(&log);

        write_capture(&log, "# accel=tcg\n", b"guest says hello").unwrap();

        let written = fs::read_to_string(&log).unwrap();
        assert_eq!(written, "# accel=tcg\nguest says hello");
        let _ = fs::remove_file(&log);
    }

    fn temp_log(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("lf-fwd-{}-{name}.log", std::process::id()))
    }

    #[test]
    fn run_boot_reports_a_child_that_exits_before_connecting() {
        // `true` exits immediately without ever dialing the NIC listeners, so
        // the accept phase must fail fast — and still persist the run log.
        let log = temp_log("early-exit");
        let _ = fs::remove_file(&log);
        let backends = NicBackends::new(ManagementBacking::Socket).unwrap();

        let error = run_boot(
            Command::new("true"),
            backends,
            routed_test(&log, &bench()),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap_err();

        assert!(
            error.contains("exited before connecting"),
            "unexpected error: {error}"
        );
        assert!(log.is_file(), "the run log must be written on failure");
        let _ = fs::remove_file(&log);
    }

    #[test]
    fn run_boot_times_out_when_the_child_never_connects() {
        // A live child that never dials the listeners must trip the accept
        // timeout rather than hang, and the child must be reaped.
        let log = temp_log("accept-timeout");
        let _ = fs::remove_file(&log);
        let backends = NicBackends::new(ManagementBacking::Socket).unwrap();
        let mut child = Command::new("sleep");
        child.arg("30");

        let error = run_boot(
            child,
            backends,
            routed_test(&log, &bench()),
            Duration::from_millis(300),
            Duration::from_millis(600),
        )
        .unwrap_err();

        assert!(
            error.contains("did not connect all"),
            "unexpected error: {error}"
        );
        assert!(log.is_file(), "the run log must be written on failure");
        let _ = fs::remove_file(&log);
    }

    #[test]
    fn a_failure_to_persist_the_run_log_never_replaces_the_run_verdict() {
        // An unwritable log path must not swallow the real diagnostic: both
        // the verdict and the persistence failure have to reach the caller.
        let log = Path::new("/proc/self/librefirewall-unwritable/qemu.log");
        let backends = NicBackends::new(ManagementBacking::Socket).unwrap();

        let error = run_boot(
            Command::new("true"),
            backends,
            routed_test(log, &bench()),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap_err();

        assert!(
            error.contains("exited before connecting"),
            "the run verdict must survive: {error}"
        );
        assert!(
            error.contains("additionally"),
            "the persistence failure must be reported too: {error}"
        );
    }
}

#[cfg(test)]
mod tcp_client_tests {
    use super::*;
    use crate::topology::Topology;

    fn bench() -> Topology {
        Topology::from_document(include_bytes!(
            "../../../systems/qemu-x86_64/configuration.xml"
        ))
        .expect("the shipped document")
    }

    /// A segment the appliance would send, built here as it must build one, so a
    /// negative test can move one field at a time.
    fn appliance_segment(
        management: &ManagementPort,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&MANAGEMENT_TCP_PORT.to_be_bytes());
        segment.extend_from_slice(&CLIENT_PORT.to_be_bytes());
        segment.extend_from_slice(&sequence.to_be_bytes());
        segment.extend_from_slice(&acknowledgement.to_be_bytes());
        segment.push(5 << 4);
        segment.push(flags);
        segment.extend_from_slice(&8192u16.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        segment.extend_from_slice(payload);
        let checksum = tcp_checksum(&management.address, &management.station, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = Vec::new();
        frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
        frame.extend_from_slice(&management.mac);
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + segment.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = TCP_PROTOCOL;
        ip[12..16].copy_from_slice(&management.address);
        ip[16..20].copy_from_slice(&management.station);
        let sum = header_checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&segment);
        frame
    }

    /// A response head and body of `body_len` bytes, as the appliance composes
    /// one. Not the real renderer's output: what is under test here is the
    /// stream, and a body compared against a second copy of the appliance's own
    /// renderer would agree with itself.
    fn response_of(body_len: usize) -> Vec<u8> {
        let mut bytes = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {body_len}\r\n\
             Connection: close\r\n\r\n",
            lfw_http::METRICS_CONTENT_TYPE
        )
        .into_bytes();
        bytes.extend((0..body_len).map(|index| b'a'.wrapping_add((index % 26) as u8)));
        bytes
    }

    /// The whole exchange, driven the way the boot loop drives it: each answer
    /// both asserts what came back and decides what goes out next, and the
    /// response arrives over several segments as a real one does.
    #[test]
    fn the_whole_exchange_is_walked_and_every_step_asserted() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut client = TcpClient::new();

        // The client opens.
        let syn = probe.advance(&mut client).expect("a SYN");
        assert_eq!(client.step, TcpStep::AwaitSynAck);
        let sent = decode_tcp(&syn, &management).expect("the client's own SYN re-parses");
        assert!(sent.carries(TCP_SYN, TCP_ACK | TCP_FIN));
        assert_eq!(sent.sequence, CLIENT_ISN);
        assert_eq!(sent.destination_port, MANAGEMENT_TCP_PORT);

        // The appliance answers with a SYN-ACK, and the client acknowledges it
        // with the request.
        let peer_isn = 0x9e37_79b9;
        let syn_ack = appliance_segment(
            &management,
            peer_isn,
            CLIENT_ISN.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            &[],
        );
        assert_eq!(
            probe.judge_tcp(&syn_ack, &mut client),
            Ok(TcpStep::AwaitSynAck)
        );
        assert_eq!(client.peer_isn, Some(peer_isn));
        let data = probe.advance(&mut client).expect("the request");
        assert_eq!(client.step, TcpStep::AwaitResponse);
        let sent = decode_tcp(&data, &management).expect("the request re-parses");
        assert_eq!(sent.payload, TCP_REQUEST);
        assert_eq!(sent.acknowledgement, peer_isn.wrapping_add(1));

        // The response, in three segments and a FIN on the last, each
        // acknowledged as it arrives.
        let response = response_of(200);
        let owed = TcpClient::sent_through_request();
        let mut sequence = peer_isn.wrapping_add(1);
        let mut chunks = response.chunks(response.len().div_ceil(3)).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let flags = if last {
                TCP_ACK | TCP_PSH | TCP_FIN
            } else {
                TCP_ACK | TCP_PSH
            };
            let segment = appliance_segment(&management, sequence, owed, flags, chunk);
            assert_eq!(
                probe.judge_tcp(&segment, &mut client),
                Ok(TcpStep::AwaitResponse),
                "chunk at {sequence}"
            );
            sequence = sequence.wrapping_add(chunk.len() as u32);
            let answer = probe.advance(&mut client).expect("an acknowledgement");
            let sent = decode_tcp(&answer, &management).expect("it re-parses");
            if last {
                assert!(sent.carries(TCP_FIN | TCP_ACK, TCP_SYN));
                assert_eq!(client.step, TcpStep::AwaitLastAck);
            } else {
                assert!(sent.carries(TCP_ACK, TCP_SYN | TCP_FIN));
                assert!(sent.payload.is_empty());
                assert_eq!(client.step, TcpStep::AwaitResponse);
            }
        }
        assert_eq!(client.response, response, "the stream did not arrive whole");

        // The appliance acknowledges the client's own FIN and the exchange is
        // over.
        let last_ack = appliance_segment(
            &management,
            sequence.wrapping_add(1),
            owed.wrapping_add(1),
            TCP_ACK,
            &[],
        );
        // Recorded from the judged step, exactly as the run loop does it. This
        // line used to assign `Closed` by hand, and that is what let the run
        // loop go without the assignment for as long as it did: the final
        // acknowledgement is the one step that sends nothing, so a client
        // advanced only by what it transmits never leaves `AwaitLastAck`.
        let step = probe
            .judge_tcp(&last_ack, &mut client)
            .expect("the final acknowledgement");
        assert_eq!(step, TcpStep::Closed);
        client.step = step;
        assert_eq!(probe.advance(&mut client), None);
        assert_eq!(
            client.step,
            TcpStep::Closed,
            "the client did not settle closed, so the run loop would wait out its timeout"
        );
        let evidence = probe.opened(&client);
        assert!(evidence.contains(&peer_isn.to_string()), "{evidence}");
        assert!(evidence.contains("HTTP/1.1 200 OK"), "{evidence}");
    }

    /// Every field of every step, moved one at a time. This is what makes the
    /// exchange a contract rather than a sequence of shapes: each mutation is a
    /// segment a broken stack would plausibly send.
    #[test]
    fn one_moved_field_at_any_step_is_refused_by_name() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let peer_isn = 0x1234_5678;
        let acked = CLIENT_ISN.wrapping_add(1);
        let owed = TcpClient::sent_through_request();

        // A client at each step, and a segment that is wrong for it.
        let cases: [(TcpStep, Vec<u8>, &str); 8] = [
            (
                TcpStep::AwaitSynAck,
                appliance_segment(&management, peer_isn, acked, TCP_ACK, &[]),
                "SYN and ACK together",
            ),
            (
                TcpStep::AwaitSynAck,
                appliance_segment(
                    &management,
                    peer_isn,
                    acked.wrapping_add(7),
                    TCP_SYN | TCP_ACK,
                    &[],
                ),
                "acknowledges",
            ),
            (
                TcpStep::AwaitSynAck,
                appliance_segment(&management, peer_isn, acked, TCP_RST | TCP_ACK, &[]),
                "reset the connection",
            ),
            (
                TcpStep::AwaitResponse,
                appliance_segment(&management, peer_isn + 1, owed, TCP_SYN | TCP_ACK, &[]),
                "no SYN",
            ),
            (
                TcpStep::AwaitResponse,
                appliance_segment(
                    &management,
                    peer_isn + 1,
                    owed.wrapping_add(9),
                    TCP_ACK,
                    b"x",
                ),
                "acknowledges",
            ),
            (
                TcpStep::AwaitResponse,
                appliance_segment(&management, peer_isn + 99, owed, TCP_ACK, b"x"),
                "begins at sequence",
            ),
            (
                TcpStep::Unopened,
                appliance_segment(&management, peer_isn, 0, TCP_ACK, &[]),
                "before the client opened",
            ),
            (
                TcpStep::Closed,
                appliance_segment(&management, peer_isn, 0, TCP_ACK, &[]),
                "after the connection closed",
            ),
        ];
        for (step, frame, expected) in cases {
            let mut client = TcpClient::new();
            client.step = step;
            client.expect = peer_isn.wrapping_add(1);
            client.sequence = acked;
            let verdict = probe
                .judge_tcp(&frame, &mut client)
                .expect_err(&format!("{step:?} must refuse this segment"));
            assert!(
                verdict.contains(expected),
                "at {step:?}, expected {expected:?} in: {verdict}"
            );
        }
    }

    /// The response is judged when the appliance closes, and a stream that does
    /// not add up is refused by the field that does not.
    #[test]
    fn a_response_that_does_not_add_up_is_refused_when_the_appliance_closes() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let owed = TcpClient::sent_through_request();
        let cases: [(Vec<u8>, &str); 4] = [
            (response_of(64)[..40].to_vec(), "no complete HTTP head"),
            (
                {
                    let mut short = response_of(64);
                    short.truncate(short.len() - 10);
                    short
                },
                "Content-Length of 64",
            ),
            (response_of(0), "empty body"),
            (
                {
                    let mut refused = response_of(8);
                    refused.splice(9..12, b"503".iter().copied());
                    refused
                },
                "is owed",
            ),
        ];
        for (body, expected) in cases {
            let mut client = TcpClient::new();
            client.step = TcpStep::AwaitResponse;
            client.expect = 0x2000;
            client.sequence = owed;
            let segment = appliance_segment(
                &management,
                0x2000,
                owed,
                TCP_ACK | TCP_PSH | TCP_FIN,
                &body,
            );
            let verdict = probe
                .judge_tcp(&segment, &mut client)
                .expect_err("a stream that does not add up");
            assert!(
                verdict.contains(expected),
                "expected {expected:?}: {verdict}"
            );
        }
    }

    /// A bare acknowledgement inside the response is legitimate TCP — a window
    /// update, or a pure acknowledgement of the request — so the client
    /// acknowledges and waits rather than refusing.
    #[test]
    fn a_bare_acknowledgement_during_the_response_is_tolerated() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut client = TcpClient::new();
        client.step = TcpStep::AwaitResponse;
        client.expect = 0x1000;
        let ack = appliance_segment(
            &management,
            0x1000,
            TcpClient::sent_through_request(),
            TCP_ACK,
            &[],
        );
        assert_eq!(
            probe.judge_tcp(&ack, &mut client),
            Ok(TcpStep::AwaitResponse)
        );
        assert!(client.response.is_empty());
        assert_eq!(client.expect, 0x1000, "an empty segment moved the stream");
    }

    /// The checksum is verified rather than trusted: it is the one field of the
    /// appliance's own composition no other assertion here would notice.
    #[test]
    fn a_segment_whose_checksum_does_not_verify_is_refused() {
        let management = bench().management();
        let mut frame = appliance_segment(&management, 1, 2, TCP_ACK, b"body");
        assert!(decode_tcp(&frame, &management).is_ok());
        let at = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 16;
        frame[at] ^= 0xff;
        let verdict = decode_tcp(&frame, &management).expect_err("a bad checksum");
        assert!(verdict.contains("does not verify"), "{verdict}");
    }

    /// Everything a frame can be that is not a segment this client reads.
    #[test]
    fn a_frame_that_is_not_a_tcp_segment_is_refused_by_the_field_that_says_so() {
        let management = bench().management();
        assert!(decode_tcp(&[0u8; 10], &management).is_err());

        let mut wrong_protocol = appliance_segment(&management, 1, 2, TCP_ACK, &[]);
        wrong_protocol[ETHERNET_HEADER_LEN + 9] = ICMP_PROTOCOL;
        assert!(
            decode_tcp(&wrong_protocol, &management)
                .expect_err("not TCP")
                .contains("IP protocol")
        );
        assert!(!is_tcp(&wrong_protocol));

        // A data offset naming more header than the segment carries.
        let mut short_header = appliance_segment(&management, 1, 2, TCP_ACK, &[]);
        let offset_at = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 12;
        short_header[offset_at] = 15 << 4;
        assert!(
            decode_tcp(&short_header, &management)
                .expect_err("an impossible header length")
                .contains("byte header")
        );

        // And one below the twenty a header occupies.
        let mut tiny_header = appliance_segment(&management, 1, 2, TCP_ACK, &[]);
        tiny_header[offset_at] = 4 << 4;
        assert!(decode_tcp(&tiny_header, &management).is_err());

        // A datagram claiming more than the frame carries.
        let mut overlong = appliance_segment(&management, 1, 2, TCP_ACK, &[]);
        overlong[ETHERNET_HEADER_LEN + 2..ETHERNET_HEADER_LEN + 4]
            .copy_from_slice(&9000u16.to_be_bytes());
        assert!(decode_tcp(&overlong, &management).is_err());
    }

    /// A segment addressed to the wrong port pair is not this connection's,
    /// whatever else it carries.
    #[test]
    fn a_segment_on_another_port_pair_is_refused() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut client = TcpClient::new();
        client.step = TcpStep::AwaitSynAck;
        let mut frame = appliance_segment(
            &management,
            1,
            CLIENT_ISN.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            &[],
        );
        // Move the source port and re-seal, so the refusal is the port rather than
        // the checksum.
        let at = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
        frame[at..at + 2].copy_from_slice(&8080u16.to_be_bytes());
        frame[at + 16..at + 18].copy_from_slice(&[0, 0]);
        let checksum = tcp_checksum(&management.address, &management.station, &frame[at..]);
        frame[at + 16..at + 18].copy_from_slice(&checksum.to_be_bytes());
        let verdict = probe
            .judge_tcp(&frame, &mut client)
            .expect_err("not this connection");
        assert!(verdict.contains("came back from port 8080"), "{verdict}");
    }

    /// The two halves of one checksum routine: composing and verifying.
    #[test]
    fn the_checksum_routine_serves_both_directions() {
        let source = [10, 0, 2, 2];
        let destination = [10, 0, 2, 15];
        let mut segment = std::vec![0u8; 24];
        segment[12] = 5 << 4;
        segment[13] = TCP_ACK;
        let value = tcp_checksum(&source, &destination, &segment);
        segment[16..18].copy_from_slice(&value.to_be_bytes());
        assert_eq!(tcp_checksum(&source, &destination, &segment), 0);

        // An odd-length segment is padded with a zero byte, as RFC 1071 says.
        let mut odd = std::vec![0u8; 21];
        odd[12] = 5 << 4;
        let value = tcp_checksum(&source, &destination, &odd);
        odd[16..18].copy_from_slice(&value.to_be_bytes());
        assert_eq!(tcp_checksum(&source, &destination, &odd), 0);
    }

    /// Three boots' numbers, and the one thing they must not be.
    #[test]
    fn equal_sequence_numbers_across_boots_are_refused() {
        assert!(crate::qemu::judge_sequence_numbers(&[]).is_err());
        let distinct = crate::qemu::judge_sequence_numbers(&[("a", 1), ("b", 2), ("c", 3)])
            .expect("three distinct numbers");
        assert!(distinct.contains('3'), "{distinct}");
        let verdict = crate::qemu::judge_sequence_numbers(&[("a", 7), ("b", 7)])
            .expect_err("two equal numbers");
        assert!(verdict.contains("both answered with"), "{verdict}");
        assert!(verdict.contains("off-path"), "{verdict}");
    }
}
