//! QEMU two-port virtio-net routing harness.
//!
//! Attaches two `virtio-net-pci` NICs whose backends are host-controlled TCP
//! sockets to a caller-built QEMU invocation (the OVMF/GRUB boot of the
//! deployable disk), plays one host endpoint on each port, and judges the boot
//! against a [`BootContract`].
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

use crate::topology::{Endpoint, PORTS, Topology};

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

/// The host side of the two NIC ports: one loopback listener per port that
/// QEMU's `socket` netdevs dial into, so the port identity of each accepted
/// stream is unambiguous.
pub struct NicBackends {
    listeners: [TcpListener; PORTS],
}

impl NicBackends {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            listeners: [bind_listener()?, bind_listener()?],
        })
    }

    /// Append the two socket-backed virtio NICs to a QEMU invocation. Each
    /// port's `socket` netdev dials the corresponding host listener; the
    /// `-device` string (PCI address, MAC, no option ROM) is the single
    /// definition shared with interactive runs via [`crate::qemu::nic_device`],
    /// which takes the MAC from `topology`'s interface on that port.
    pub fn apply(&self, command: &mut Command, topology: &Topology) -> Result<(), String> {
        for (port, listener) in self.listeners.iter().enumerate() {
            let tcp = listener
                .local_addr()
                .map_err(|error| format!("read listener port: {error}"))?
                .port();
            command
                .arg("-netdev")
                .arg(format!("socket,id=n{port},connect=127.0.0.1:{tcp}"))
                .arg("-device")
                .arg(crate::qemu::nic_device(topology, port)?);
        }
        Ok(())
    }
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

/// What one boot yielded: the guest's serial output, and what the probes
/// injected into it were observed to do.
#[derive(Debug)]
pub struct Booted {
    pub serial: Vec<u8>,
    pub traffic: TrafficReport,
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

    let outcome: Result<(), String> = 'run: {
        // Phase 1: accept both of QEMU's socket dial-ins.
        let mut streams: [Option<TcpStream>; PORTS] = [None, None];
        while streams.iter().any(Option::is_none) {
            drain(&serial_receiver, &mut output);
            for (port, listener) in backends.listeners.iter().enumerate() {
                if streams[port].is_some() {
                    continue;
                }
                match listener.accept() {
                    Ok((stream, _peer)) => streams[port] = Some(stream),
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
                    "QEMU did not connect both NIC sockets within {}s",
                    accept_timeout.as_secs()
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
        let streams = streams.map(|stream| stream.expect("both streams accepted"));

        // Each stream carries QEMU's `net_socket` STREAM framing in both
        // directions: a 4-byte big-endian length header followed by the raw L2
        // bytes (no FCS). A decoder thread per port parses the guest's egress
        // frames into one channel; draining continuously also keeps QEMU's TX
        // path from blocking on a full host socket buffer.
        let (frame_sender, frame_receiver) = mpsc::channel();
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
        // than queued. That is why sending continues on a cadence below.
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
                    None if all_routed(&probes, &deliveries) => {
                        // Both directions have completed, so the guest is
                        // demonstrably taking frames off both ports: a refused
                        // packet injected now is one that reached the driver.
                        // Send them once more and give a delivery the window it
                        // would need to come back.
                        inject_probes(&mut endpoints, &probes, |probe| {
                            matches!(probe.expectation, Expectation::Dropped { .. })
                        });
                        settling_since = Some(Instant::now());
                    }
                    Some(since) if since.elapsed() >= SETTLE_WINDOW => break 'run Ok(()),
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
                        "timed out after {}s waiting for the routed contract; {}{}; see {}",
                        total_timeout.as_secs(),
                        describe_pending(&probes, &deliveries),
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
                crate::qemu::nic_device(&topology, endpoint.port)
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
                "</neighbours></configuration>"
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
                "</neighbours></configuration>"
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
        let alternate =
            Topology::from_document(include_bytes!("../scenarios/alternate-addressing.xml"))
                .expect("the alternate document describes a bench");
        let shipped_probes = probes(&bench()).expect("the shipped bench");
        let alternate_probes = probes(&alternate).expect("the alternate bench");

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
        let backends = NicBackends::new().unwrap();
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
        assert_eq!(devices.len(), 2);
        assert!(devices[0].contains("addr=02.0") && devices[0].contains("romfile="));
        assert!(devices[1].contains("addr=03.0") && devices[1].contains("romfile="));
        let netdevs: Vec<&String> = args
            .iter()
            .filter(|arg| arg.starts_with("socket,id="))
            .collect();
        assert_eq!(netdevs.len(), 2);
        assert_ne!(netdevs[0], netdevs[1], "each port needs its own listener");
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
        let backends = NicBackends::new().unwrap();

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
        let backends = NicBackends::new().unwrap();
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
            error.contains("did not connect both NIC sockets"),
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
        let backends = NicBackends::new().unwrap();

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
