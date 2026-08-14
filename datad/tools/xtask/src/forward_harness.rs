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
//! the routed contract must never expect it to forward anything, because the
//! design gives it no forwarded traffic. What it gets instead is a contract
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
//! The management/dataplane mutual exclusion is two prohibitions, and a boot must satisfy
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
    collections::VecDeque,
    fmt, fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::dial_contract;
use crate::management_contract::{self, ManagementInjection};
use crate::metrics_contract::{self, Scrape};
use crate::onboard_contract;
use crate::onboard_install_contract;
use crate::onboard_request_contract;
use crate::onboard_tls_contract;
use crate::qemu::{GuestNic, every_guest_nic};
use crate::recording_contract::{self, Download};
use crate::surface_contract::Injected;
use crate::topology::{Endpoint, ManagementPort, PORTS, PortPolicy, Topology};

/// Total wall-clock budget from QEMU launch to the contract being decided. A
/// TCG (no KVM) walk through OVMF, GRUB signature verification, seL4 boot, and
/// two polling virtio drivers is slow, hence the generous ceiling.
const BOOT_TEST_TIMEOUT: Duration = Duration::from_secs(180);

/// The same budget for a boot whose station leaves the appliance's `SYN`
/// unanswered.
///
/// It is the appliance's own arithmetic rather than a guess about the machine.
/// The transport abandons a `SYN` nothing answers only once RFC 6298's backoff
/// is spent — one second doubling five times, so sixty-three seconds for one
/// attempt — and what a run waits for is the **first** attempt's report and the
/// settling after it. Six times one attempt is room enough over that for a slow
/// emulated boot to reach it, and nothing is asserted against this number: it is
/// the point past which a run stops waiting, and a boot that reaches it has
/// found a node whose first attempt never ended rather than a machine that was
/// slow.
const UNANSWERED_DIAL_BOOT_TIMEOUT: Duration = Duration::from_secs(360);

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

/// How long a run waits for the console to report the last frame the management
/// port received before giving up on it.
///
/// The console's total is an equality and the appliance writes it on the drain
/// that moved the frame, so the record can still be in the log ring when the
/// exchange closes. Waiting on the *observable* removes that race; this bounds the
/// wait, so a frame that really was lost is reported as the count verdict rather
/// than as a timeout. Generous against a settle window of two seconds: a report
/// that has not arrived by now is a report that is not coming.
const MANAGEMENT_REPORT_GRACE: Duration = Duration::from_secs(10);

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

/// The port the appliance dials out of its management port, the probe it
/// carries, and what the station answers with.
///
/// Written here rather than imported, on [`MANAGEMENT_TCP_PORT`]'s terms: a
/// station that took the port and the payload from the code under test could not
/// catch that code dialling somewhere else or saying something else.
/// The address the appliance dials, restated here as the appliance's own
/// constant rather than read from the bench: it is a first-party choice of the
/// code under test, and a station that took it from the document could not catch
/// that code dialling somewhere else. Where a document places it on the
/// management port's own prefix — as the shipped one does, it being that port's
/// stated gateway — it is the station's address too.
pub(crate) const DIAL_DESTINATION: [u8; 4] = [10, 0, 2, 2];
pub(crate) const DIAL_PORT: u16 = 4433;

/// The initial sequence number the station answers a dial with, and the window
/// it advertises.
///
/// Fixed and deliberately not round, for [`CLIENT_ISN`]'s reason. The window is
/// far above the probe, so nothing about this exchange turns on the station
/// re-opening one.
const STATION_ISN: u32 = 0x6d1f_0a53;
const STATION_WINDOW: u16 = 8192;

/// The station a misbehaving wire answers *for* when the appliance asked about
/// another: an on-link address of the management prefix that this port never
/// asked about, at a hardware address of its own.
///
/// On-link and internally consistent on purpose. The reply's Ethernet source is
/// the sender it claims, its sender address sits on the management prefix of the
/// document the one scenario that plays this station boots, and it is unicast —
/// so every check a frame can fail before the cache is consulted passes, and the
/// one thing wrong with it is that nothing asked. That is the property being
/// stated: this end learns what it asked for and nothing else.
///
/// Written here rather than derived from the bench, on [`DIAL_DESTINATION`]'s
/// terms: a station whose impostor came out of the document under test could not
/// catch that document's own addressing deciding the answer.
const IMPOSTOR_ADDRESS: [u8; 4] = [10, 0, 2, 9];
const IMPOSTOR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x63];

/// The acknowledgement a misbehaving station claims for a `SYN` it never
/// received.
///
/// Far from every number the appliance's own connection occupies, and chosen
/// rather than derived: a station that computed the wrong acknowledgement out of
/// the right one could be wrong in the same direction as the code under test.
const UNSENT_ACKNOWLEDGEMENT: u32 = 0x1234_5678;

/// The most attempts a **scheduled** channel can open inside one run, and so the
/// bound every station limit below is derived from.
///
/// The appliance no longer stops re-dialling: the channel is a persistent
/// connection and an attempt that fails is followed by another for as long as the
/// node is up. So what a station can still catch is not a node that retries —
/// that is the design — but a node that retries **without a schedule**, and the
/// schedule is what this number comes from. Each wait is drawn below a bound
/// that starts at a second, and the wakeup that reaches it arrives on a tenth of
/// a second, so no two attempts can be closer together than one tick. A run
/// stops within the settling window and the report grace of the first attempt's
/// record set — twelve seconds — so at most a hundred and twenty attempts fit
/// after it, plus the one that opened it.
///
/// A ceiling and never a count: the bound doubles, so a schedule that is working
/// spends a handful and not a hundred. What a hundred and twenty-second attempt
/// says is that the wait between them is not being taken at all.
const DIAL_ATTEMPTS_WHILE_FAILING: usize = 121;

/// How many times the station will answer a fresh resolution or a fresh
/// connection before it calls the appliance broken.
///
/// One of each per attempt at most, so the attempt ceiling is the whole of it.
/// It bounds the harness rather than the appliance: what it catches is a loop,
/// not a retry.
const DIAL_RESTART_LIMIT: usize = DIAL_ATTEMPTS_WHILE_FAILING;

/// The most a station that answers nothing will take off the channel across a
/// whole boot before it calls the appliance unbounded.
///
/// The appliance's own outbound window times the attempts a scheduled channel
/// can open in one run: a session whose peer never speaks composes one client
/// hello and then waits, so a boot's worth of them is one flight per attempt.
/// Derived from the two bounds rather than measured off a run, so a hello that
/// grew would still fit and a node emitting without end would still not.
const DIAL_OFFER_LIMIT: usize = 2048 * DIAL_RESTART_LIMIT;

/// The same bound for a station whose misbehaviour makes the appliance spend its
/// whole retransmission budget on every attempt.
///
/// Written as the arithmetic rather than as a number, because it *is* the claim:
/// the transport re-sends each unanswered `SYN` at most five times, so an
/// attempt puts at most six on this wire and the attempt ceiling bounds the
/// rest. One past it is one of those two bounds not holding, which is exactly
/// what this catches.
const DIAL_SYNS_WHILE_UNANSWERED: usize = DIAL_ATTEMPTS_WHILE_FAILING * (1 + 5);

/// How many resolutions a station that never answers for the next hop will
/// answer before it calls the appliance broken.
///
/// The same arithmetic on the other bound: the neighbour cache asks about one
/// address three times before it reports it unreachable, so an attempt spends at
/// most three requests and the attempt ceiling bounds the rest. A ceiling rather
/// than a count: fewer cross wherever an attempt ends before it reaches a
/// resolution at all.
const DIAL_REQUESTS_WHILE_UNRESOLVED: usize = DIAL_ATTEMPTS_WHILE_FAILING * 3;

/// The two ephemeral ports the onboarding station dials the appliance's second
/// listening port from.
///
/// Two rather than one because one scenario opens a second connection while the
/// first is established, and a 4-tuple is what tells them apart on this wire.
/// Neither collides with [`CLIENT_PORT`], the harness's own HTTP client running
/// on the same wire in the same boot.
const ONBOARD_STATION_PORT: u16 = 0xc351;
const ONBOARD_CROWD_PORT: u16 = 0xc352;

/// The initial sequence numbers those two connections open under.
///
/// Chosen and distinct, on [`STATION_ISN`]'s terms: the appliance's own
/// acknowledgements are compared against them, and two connections sharing one
/// would let a segment for either satisfy an assertion about the other.
const ONBOARD_STATION_ISN: u32 = 0x2b41_7f00;
const ONBOARD_CROWD_ISN: u32 = 0x5e02_c100;

/// The window the onboarding station advertises.
///
/// Larger than anything it sends, so nothing this station does is ever paced by
/// its own receive window: what the appliance answers a *half* record with is
/// nothing at all, and a window that could refuse a byte would make that fact
/// unreadable.
const ONBOARD_WINDOW: u16 = 8192;

/// What one onboarding session carries, in one segment.
///
/// **The opening of a TLS record and not the whole of one**, which is the one
/// shape that lets these three boots go on being about what they are about. A
/// TLS server now stands behind this port, so a payload that is not a record at
/// all is refused the moment it lands and the session ends by this appliance's
/// own decision — which would take the endings these boots exist to prove away
/// from them. A record whose header declares more than arrives is held instead,
/// unanswered and undecided, so the station keeps deciding how each session
/// ends. What each *failure* looks like is proved on a boot of its own
/// ([`crate::onboard_tls_contract`]), by real clients.
///
/// Nineteen bytes: the five-byte record header of a handshake record declaring
/// 1024 bytes, the four-byte header of a client hello inside it, and the first
/// ten of that hello. What is asserted about it is its **length**, at both ends
/// of the relay and in both domains' accounts, so the property it needs beyond
/// being incomplete is to be a length no bound of the path rounds off — it is
/// far inside [`pd_runtime::ONBOARD_INBOUND_CAPACITY`] and inside one relay
/// item, so a session that carried it carried all of it in one handover.
const ONBOARD_PAYLOAD: &[u8] = &[
    0x16, 0x03, 0x01, 0x04, 0x00, // handshake record, 1024 bytes declared
    0x01, 0x00, 0x03, 0xfc, // client hello, 1020 bytes declared
    0x03, 0x03, // the legacy version every TLS 1.3 hello still carries
    0x4c, 0x46, 0x57, 0x2d, 0x4f, 0x4e, 0x42, 0x44, // ten bytes of its random
];

/// Passes a boot spends *watching* for the appliance to finish reporting the
/// handshakes real clients drew out of it, and the gap between two of them.
///
/// It is a wait and not a prod, which is the whole difference from the station's
/// budget below: this boot has no station on the wire, and it used to spend
/// requests on the port's other surface to run the pass that writes the last
/// account. The clock domain's tick runs that pass now, so the requests bought
/// nothing — and they cost something, each one drawing a console record out of
/// the endpoint and pressing a log ring that a 115200-baud console drains far
/// more slowly than a domain can fill it. A dropped record is how the second half
/// of a session's account goes missing, which is a failure of this harness's own
/// making.
///
/// Far more polls than a healthy boot needs, because the cost of being wrong is
/// asymmetric: a few spare seconds against a run that reports a domain as silent
/// when it was one pass from speaking.
const ONBOARD_REPORT_POLLS: usize = 256;
const ONBOARD_REPORT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How many segments repeating sequence space it has already taken the client
/// will accept on its connection before it calls the appliance broken.
///
/// A retransmission is a peer working, not a peer misbehaving, so each one is
/// taken and answered rather than refused — but a peer that only ever repeats
/// itself never finishes the exchange, and a station that waited for it could
/// not tell that from a slow machine. The appliance's own transport abandons a
/// range after five re-sends, and an exchange has a handful of ranges in it: a
/// ceiling with room above that rather than a count, on
/// [`ONBOARD_SEGMENT_LIMIT`]'s terms and for its reason.
const CLIENT_REPEAT_LIMIT: usize = 16;

/// The same bound for the station on the far end of the appliance's dial, across
/// a whole boot.
///
/// [`CLIENT_REPEAT_LIMIT`]'s ceiling and its reason, spread over the sessions one
/// boot may open: the dial's numbers begin again with every `SYN` this station
/// answers, and this counts across all of them, so what a session is allowed is
/// the client's own ceiling and the product is what a boot is.
const DIAL_REPEAT_LIMIT: usize = CLIENT_REPEAT_LIMIT * DIAL_RESTART_LIMIT;

/// How many segments the onboarding station will accept on one connection before
/// it calls the appliance broken.
///
/// A session of this shape is a handshake, an acknowledgement of one payload and
/// a close — three segments this end must see, and a retransmission of any of
/// them is a fourth. A ceiling with room rather than a count: what it catches is
/// a port that answers without end, which is the one failure a station that
/// simply waits could not tell from a slow machine.
const ONBOARD_SEGMENT_LIMIT: usize = 32;

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

/// How many management frames go onto the wire at once.
///
/// An eighth of the buffers the management pipeline holds. The bound is the
/// pool's rather than a delay that happens to be long enough, and it is a small
/// fraction of it rather than half because what has to have room is not the pool
/// but the *receive descriptors the driver has posted at that instant*, which is
/// as many as it has been able to refill since the last chunk. An eighth leaves
/// that margin under any scheduling; the frames still go out exactly once each,
/// and what is chunked is *when*, not *whether*.
const MANAGEMENT_BURST: usize = pd_runtime::POOL_BUFFERS / 8;

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

/// A TCP-over-IPv4 Ethernet frame as fields, for the one probe that has to be a
/// TCP segment rather than a datagram: a packet from the middle of a conversation
/// the appliance never saw begin.
///
/// Written from RFC 793 here rather than reused from the appliance's own builder,
/// exactly as the management client's segment is: a frame composed by the code
/// under test and judged against that code's expectation would agree with itself.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TcpPacket {
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    /// The eight flag bits as they sit in the header. A bare `ACK` is 0x10, which
    /// is the shape a segment from mid-conversation has.
    flags: u8,
    /// Where in its own sequence space this segment sits. It decides nothing for
    /// a segment on an unknown five-tuple — refused for its flags before any
    /// window is consulted — and it decides everything for one on a flow the
    /// appliance holds: a tracker admits a segment only inside the window its
    /// peer authorised.
    sequence: u32,
    acknowledgement: u32,
    ttl: u8,
    payload: Vec<u8>,
}

impl TcpPacket {
    /// Serialize to the bytes an endpoint's NIC would put on the wire, padded to
    /// the Ethernet minimum on [`UdpPacket::build`]'s terms.
    fn build(&self) -> Vec<u8> {
        let mut segment = Vec::with_capacity(TCP_HEADER_LEN + self.payload.len());
        segment.extend_from_slice(&self.source_port.to_be_bytes());
        segment.extend_from_slice(&self.destination_port.to_be_bytes());
        segment.extend_from_slice(&self.sequence.to_be_bytes());
        segment.extend_from_slice(&self.acknowledgement.to_be_bytes());
        // Five words of header and no options.
        segment.push(5 << 4);
        segment.push(self.flags);
        segment.extend_from_slice(&0xffffu16.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        segment.extend_from_slice(&self.payload);
        let checksum = tcp_checksum(&self.source, &self.destination, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = Vec::with_capacity(MIN_UDP_FRAME + segment.len());
        frame.extend_from_slice(&self.destination_mac);
        frame.extend_from_slice(&self.source_mac);
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + segment.len()) as u16).to_be_bytes());
        ip[8] = self.ttl;
        ip[9] = TCP_PROTOCOL;
        ip[12..16].copy_from_slice(&self.source);
        ip[16..20].copy_from_slice(&self.destination);
        let header = header_checksum(&ip);
        ip[10..12].copy_from_slice(&header.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&segment);
        if frame.len() < MIN_UDP_FRAME {
            frame.resize(MIN_UDP_FRAME, 0);
        }
        frame
    }
}

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

/// The ones'-complement sum RFC 1071 defines, over an arbitrary run of bytes.
///
/// Separate from [`header_checksum`], which zeroes the IPv4 header's own field
/// before summing: an ICMP message carries its checksum inside the bytes it covers,
/// so the caller zeroes it and this sums what it is given.
fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in bytes.chunks(2) {
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
    /// It must arrive at endpoint `to` as exactly `delivered` — the frame it went
    /// in as, with exactly the three changes a hop makes.
    ///
    /// `datagram` holds the same two frames decoded, where the probe *is* a
    /// datagram this harness models field by field: a delivery that departs from
    /// the contract is then reported as the field it departs in rather than as an
    /// offset. It is `None` for a probe built as raw bytes — a TCP segment, whose
    /// fields this harness does not model — and such a delivery is judged and
    /// reported as bytes. Byte equality is the contract either way; the decoded
    /// view only decides how a failure reads.
    Routed {
        to: Endpoint,
        delivered: Vec<u8>,
        datagram: Option<Datagrams>,
    },
    /// It must never arrive anywhere; `because` names the rule that forbids it,
    /// so a wrongly delivered packet says which one the guest broke — and the
    /// report says which one each refusal demonstrates.
    Dropped { because: &'static str },
}

/// One probe as it went in and as it must come out, decoded.
#[derive(Debug)]
struct Datagrams {
    /// Kept so the report can put the TTL the appliance produced beside the one
    /// it was handed.
    sent: UdpPacket,
    delivered: UdpPacket,
}

impl Expectation {
    /// The endpoint this probe must reach, or `None` for one that must reach
    /// none.
    const fn destination(&self) -> Option<&Endpoint> {
        match self {
            Self::Routed { to, .. } => Some(to),
            Self::Dropped { .. } => None,
        }
    }

    /// Whether the appliance must put this probe on a wire.
    const fn is_routed(&self) -> bool {
        matches!(self, Self::Routed { .. })
    }
}

/// One injected packet and the single thing it proves.
#[derive(Debug)]
struct Probe {
    /// Names the probe in a verdict.
    ///
    /// Owned rather than borrowed, because a probe set decides how many probes
    /// its experiment needs: a flood puts one probe per five-tuple on the wire,
    /// and a name per tuple cannot be a literal written out beside the set.
    name: String,
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
    /// Whether the appliance's recording tap must have observed this frame,
    /// which is what [`crate::surface_contract`] holds the recordings to.
    ///
    /// Not every injected frame is one the recorder can be held to, and the
    /// line is not "was it forwarded" — a refused packet is observed, with its
    /// refusal. The tap is driven from the *routing decision*, so a frame the
    /// router's parser cannot read produces no decision and therefore no
    /// observation; `Routed::Discarded` and its `observed` in
    /// `crates/pd-runtime/src/lib.rs` are where that happens, and the comment
    /// there says so. Only [`legacy_broadcast_frame`] is such a frame here.
    observed: bool,
    /// Whether this probe may only be injected once every *immediate* probe that
    /// must be delivered has arrived.
    ///
    /// The one thing a stateful contract needs that a stateless one does not:
    /// order. A reply belongs to a flow, so it is only a reply if the request
    /// opened one first — injected alongside the request it would race it, be
    /// classified as a connection nothing permits, and be refused. Deferring it
    /// makes "the appliance carried this because it recognised the conversation"
    /// a statement about what was on the wire rather than about whichever frame
    /// QEMU happened to deliver first.
    deferred: bool,
    /// Whether this probe is injected exactly once and never retransmitted.
    ///
    /// The one thing a probe whose *refusal* depends on a flow's state needs.
    /// Retransmission is otherwise free — a refused probe is refused the same way
    /// however often it arrives — but a segment that is out of a flow's window
    /// while the flow is open is a segment for a flow that no longer exists once
    /// it has closed, and the second refusal is a different one. A probe like that
    /// goes out once, into the state its phase established, and its refusal is the
    /// one that state produces — which means it waits, as a deferred probe does.
    once: bool,
    /// The lifecycle or policy event a record of this probe must carry, where it
    /// must carry one. `None` for a probe the connection history is not about.
    event: Option<u8>,
    /// Which side of a configuration change this probe belongs to.
    ///
    /// The one thing a reconfiguration contract needs that nothing else does: a
    /// probe whose verdict is stated against the *submitted* policy must not be
    /// injected while the shipped one is still in force, or its refusal would be
    /// the old policy's and would look exactly like the new one working.
    wave: Wave,
}

/// Which policy a probe's verdict is stated against.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Wave {
    /// The configuration the image was built around, in force from boot.
    #[default]
    Shipped,
    /// The configuration submitted over the management API during the run.
    Submitted,
}

impl Probe {
    /// Whether this probe may only go out once every *immediate* probe that must
    /// be delivered has arrived.
    ///
    /// True for a deferred probe and for a `once` probe alike: both are about a
    /// flow another probe opened, and injecting either alongside the opening
    /// would race it into a refusal about no flow at all.
    const fn waits(&self) -> bool {
        self.deferred || self.once
    }

    /// Judge one frame that carried this probe's marker back to the harness.
    ///
    /// # Errors
    /// The verdict, naming this probe and — where the delivery differs from the
    /// contract — every field it differs in. A hex dump would say the frame was
    /// wrong; naming the field says whether the router rewrote the wrong MAC,
    /// failed to decrement, or corrupted the payload.
    fn judge(&self, egress: usize, frame: &[u8]) -> Result<Delivery, String> {
        let name = &self.name;
        let (expected_egress, expected_bytes, datagram) = match &self.expectation {
            Expectation::Dropped { because } => {
                return Err(format!(
                    "probe {name} came back on port{egress}, but {because}, so the appliance \
                     must never put it on a wire"
                ));
            }
            Expectation::Routed {
                to,
                delivered,
                datagram,
            } => (to.port, delivered, datagram.as_ref()),
        };
        if egress != expected_egress {
            return Err(format!(
                "probe {name} was delivered on port{egress}, but the route it takes puts it on \
                 port{expected_egress}"
            ));
        }
        // A probe this harness does not model field by field: byte equality is the
        // whole contract, and a difference is reported as the offset it falls at.
        let Some(Datagrams {
            delivered: expected,
            ..
        }) = datagram
        else {
            if frame != expected_bytes.as_slice() {
                return Err(format!(
                    "probe {name}: the frame delivered on port{egress} is not the frame the \
                     routed contract names: {}",
                    byte_difference(expected_bytes, frame)
                ));
            }
            return Ok(Delivery {
                packet: None,
                bytes: frame.len(),
            });
        };

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
        if frame != expected_bytes.as_slice() {
            // Every field the contract is written in agrees, so what differs is
            // a byte the field view does not model — Ethernet padding, an IPv4
            // identification or flag the router must carry through untouched.
            return Err(format!(
                "probe {name}: the frame delivered on port{egress} carries every field of the \
                 routed contract but differs outside them: {}",
                byte_difference(expected_bytes, frame)
            ));
        }
        Ok(Delivery {
            packet: Some(observed),
            bytes: frame.len(),
        })
    }
}

/// One accepted delivery as it arrived: the frame's own fields where this harness
/// models them, and its length on the wire including any padding the field view
/// disclaims.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Delivery {
    packet: Option<UdpPacket>,
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
    /// Absent, on a boot whose contract asks nothing about forwarding. Distinct
    /// from [`Self::Missing`], which is the same observation where it *is* a
    /// failure: a report that spelled both the same way would put failure words
    /// on a row nothing was owed for.
    Unjudged,
    Broke,
}

impl Seen {
    fn label(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Refused => "dropped",
            Self::Missing => "missing",
            Self::Unjudged => "unjudged",
            Self::Broke => "failed",
        }
    }
}

/// One rendered line of the traffic report.
#[derive(Debug)]
struct Row {
    seen: Seen,
    name: String,
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

/// Whether the node the report describes had a committed policy to forward under.
///
/// It changes what a probe's *absence* means, which is the one thing a table of
/// absences cannot say for itself. Under a policy, a probe the document admits and
/// that never came back is a contract unmet and the row must read as one. On a node
/// that committed nothing, the same absence **is** the contract — nothing may cross
/// — and a row calling it `missing` would put failure words on the evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forwarding {
    /// A generation is in force, so a probe the policy admits must have crossed.
    UnderAPolicy,
    /// The node refused its own configuration and is running generation 0, so
    /// nothing may cross whatever the probes are addressed to.
    NothingCommitted,
    /// A generation is in force and the boot's contract says nothing about
    /// forwarding, so neither a crossing nor an absence is a verdict. The rows
    /// still say what happened; what they must not do is dress an absence the
    /// contract never asked about as a failure.
    NotThisBootsSubject,
}

impl TrafficReport {
    /// Derive the report from what the run recorded: the delivery accepted for
    /// each probe, if any, and the index of the probe whose delivery ended the
    /// run. Deriving it here rather than accumulating lines as the run goes
    /// keeps one place deciding what each state means.
    ///
    /// `forwarding` decides how an absence reads, which is the whole of the
    /// difference between a fail-closed boot's evidence and a routed boot's
    /// failure — see [`Forwarding`].
    fn new(
        endpoints: [Endpoint; PORTS],
        probes: &[Probe],
        deliveries: &[Option<Delivery>],
        broke: Option<usize>,
        forwarding: Forwarding,
    ) -> Self {
        let rows = probes
            .iter()
            .zip(deliveries)
            .enumerate()
            .map(|(index, (probe, delivery))| {
                let path = match probe.expectation.destination() {
                    Some(to) => format!("{}->{}", probe.from.name(), to.name()),
                    // Nothing left the appliance, so naming a far end would
                    // claim a journey the packet never made.
                    None => format!("{}->.", probe.from.name()),
                };
                let (seen, detail) = match (broke == Some(index), delivery, &probe.expectation) {
                    (true, _, _) => (Seen::Broke, "see the verdict below".to_owned()),
                    (false, Some(delivery), Expectation::Routed { datagram, .. }) => (
                        Seen::Delivered,
                        describe(delivery, datagram.as_ref().map(|both| both.sent.ttl)),
                    ),
                    // A refused probe that arrived is the `broke` case above,
                    // so a delivery here can only belong to a routed probe.
                    (false, Some(delivery), Expectation::Dropped { because }) => (
                        Seen::Broke,
                        format!("{because}, yet {} bytes came back", delivery.bytes),
                    ),
                    (false, None, Expectation::Routed { .. }) => match forwarding {
                        Forwarding::UnderAPolicy => (Seen::Missing, "never came back".to_owned()),
                        // The row this boot is run to produce: the shipped
                        // document forwards this probe, and here it did not
                        // cross. Two things stop it and the node is in both
                        // states at once — nobody has onboarded it, and it
                        // committed no generation — so the row names both rather
                        // than crediting the absence to whichever one a reader
                        // happens to have in mind. Which of them the appliance
                        // reached first is a question for its counters, and the
                        // console says the ownership half outright.
                        Forwarding::NothingCommitted => (
                            Seen::Refused,
                            String::from(
                                "the document this image carries forwards it, and this node has \
                                 no owner and committed no generation, so nothing admitted it",
                            ),
                        ),
                        Forwarding::NotThisBootsSubject => (
                            Seen::Unjudged,
                            String::from("not judged: this boot's contract is not about routing"),
                        ),
                    },
                    (false, None, Expectation::Dropped { because }) => {
                        (Seen::Refused, (*because).to_owned())
                    }
                };
                Row {
                    seen,
                    name: probe.name.clone(),
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
///
/// A probe this harness does not model field by field yields its length alone: a
/// row that invented fields for it would report numbers nothing read.
fn describe(delivery: &Delivery, sent_ttl: Option<u8>) -> String {
    let (Some(packet), Some(sent_ttl)) = (&delivery.packet, sent_ttl) else {
        return format!("{} bytes, byte-identical to the contract", delivery.bytes);
    };
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
            name: String::from("legacy-l2-broadcast"),
            marker: b"LFW-PROBE/legacy-l2-broadcast",
            from: a,
            frame: legacy_broadcast_frame(b"LFW-PROBE/legacy-l2-broadcast"),
            expectation: Expectation::Dropped {
                because: "it is neither IPv4 nor addressed to the port's own MAC",
            },
            // The one probe no recording holds, and the reason [`Probe`]'s
            // field exists: the router's parser cannot read it, so it is
            // discarded before a decision the tap could record.
            observed: false,
            deferred: false,
            once: false,
            event: None,
            wave: Wave::Shipped,
        },
    ])
}

/// The shipped routed set, with every probe owed a refusal because the appliance
/// has no owner.
///
/// Built from [`probes`] rather than beside it, which is the point: the frames an
/// unowned appliance must refuse are *the same bytes* the owned one forwards, so a
/// set written out here could drift into proving that some other traffic does not
/// cross. What changes is the expectation, and it changes for all six — including
/// the four the owned appliance also refuses, because under an unowned one they no
/// longer reach the stage that names their reason. A TTL of 1 is not why this node
/// dropped anything.
///
/// Every routed probe also loses its expected log event. A conversation is opened
/// by a packet the appliance decided to carry, and this one carries none.
///
/// # Errors
/// Whatever [`probes`] refuses the bench for.
fn unowned_probes(topology: &Topology) -> Result<Vec<Probe>, String> {
    /// One reason for all six, and it names the appliance rather than the frame —
    /// which is what the refusal is. The wording is the operator's, not the
    /// vocabulary's token: this string is what a reader of the traffic table sees.
    const BECAUSE: &str =
        "no management plane has onboarded this appliance, so it forwards nothing at all";
    Ok(probes(topology)?
        .into_iter()
        .map(|probe| Probe {
            expectation: Expectation::Dropped { because: BECAUSE },
            event: None,
            ..probe
        })
        .collect())
}

/// Which packets a boot injects into the two dataplane ports.
///
/// Two sets rather than one grown by three, and that is the whole point: the
/// routed set is the regression guard, and every scenario that injected it before
/// the filter existed must still see exactly the same two deliveries and four
/// refusals afterwards. A frame added to it would move those counts and destroy
/// the only evidence that the appliance's behaviour on the wire is unchanged —
/// so the filter's own probes are a separate set, injected by scenarios written
/// for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Traffic {
    /// Two packets that must be routed and four that must be refused, none of
    /// them for a reason the filter decides: what the routed contract has always
    /// been. The two that are routed now reach the far port *because a rule
    /// permitted them*, which is the equivalence this set exists to state.
    Routed,
    /// One packet per outcome the filter can reach: permitted by a rule, denied
    /// by a rule, and denied by the fallthrough. Every one of them is perfectly
    /// routable, so the only thing that separates their fates is the policy.
    Policy,
    /// The set a **connection lifecycle** needs: a TCP conversation that opens,
    /// is refused a segment outside its window, and closes.
    ///
    /// It is TCP because only TCP has a close, and it needs a document whose
    /// rules are not UDP-only — a TCP segment matches neither of the other two
    /// documents' rules and falls to the default deny, which is correct and
    /// leaves a lifecycle unreachable. What it produces that no other set can is
    /// an open event and a close event that says *how* the conversation ended.
    ///
    /// The same document is what makes the **other** thing only this set reaches
    /// possible: an opening segment to the port the *dropping* rule names, which
    /// that rule refuses. On every other bench a TCP segment is refused by the
    /// default deny for its protocol, so no rule about a port ever decides one —
    /// and a filter that matched a port criterion against a datagram's ports and
    /// nothing else would satisfy every other scenario in this gate.
    Lifecycle,
    /// The set only a *stateful* appliance can pass, and the one no rule of the
    /// shipped policy permits more than half of.
    ///
    /// A request, then its reply — and the reply is carried although the document
    /// names nothing about the port it is addressed to. Beside it, the same
    /// packet with no request in front of it, which must be refused, and a TCP
    /// segment from the middle of a conversation, which must be refused as such
    /// rather than adopted. Every one of the four is perfectly routable, so what
    /// separates their fates is the connection table and nothing else.
    Stateful,
    /// The one probe set that spans a **configuration change**: two probes under
    /// the shipped policy and two more, on the same two ports, under one submitted
    /// over the management API while the node runs.
    ///
    /// The four together are the reversal. The port the shipped policy accepts is
    /// forwarded before the change and dropped after it; the port it drops is
    /// dropped before and **forwarded** after. Both directions, because a set that
    /// only tightened the policy would leave "the dataplane applied the new rules"
    /// and "the dataplane stopped forwarding" looking alike.
    Reconfiguration,
    /// The set that spans a configuration change and states what it did to the
    /// conversations **already running** — which no other set can, every other one
    /// opening its second wave's conversations afresh.
    ///
    /// Two conversations open under the shipped policy, differing in their source
    /// port and in nothing else. A document is then submitted that narrows the
    /// accepting rule to one of those source ports. Afterwards, the surviving
    /// conversation's next packet still crosses — carried by its flow, which no
    /// rule of the new policy names — and the other's does not, though under the
    /// previous behaviour it would have, a tracked flow being forwarded before the
    /// filter is consulted at all.
    ///
    /// **The fourth probe is the one that proves this is a re-decision and not a
    /// flush**: a commit that emptied the table would refuse it too.
    Revocation,
    /// The set that spans a configuration change and states that **relating an ICMP
    /// error to a conversation decides where it would go and never whether it may.**
    ///
    /// A conversation opens, and an error quoting one of its datagrams arrives from
    /// the far side — a quote the tracker's own corroboration accepts, so the frame
    /// really is related and not merely refused as unreadable. Under the shipped
    /// policy, whose rules are both about UDP, no rule is about it and the default
    /// deny refuses it. A document is then submitted that adds one rule admitting
    /// related traffic, and the same error on the same flow crosses.
    ///
    /// **Both halves are needed and neither is enough.** A denial alone would leave
    /// "the policy refused it" and "the tracker never related it" looking alike; an
    /// admission alone would say nothing about the default. Together they are the
    /// policy deciding.
    Related,
    /// The set that puts a **connection flood** across the appliance: one
    /// conversation the policy admits, and [`FLOOD_TUPLES`] distinct five-tuples it
    /// does not.
    ///
    /// Every datagram of the burst opens a flow and is then refused by the default
    /// deny, so the appliance gives each slot back in the same evaluation — which
    /// is the denial-of-service property a default-deny appliance owes and the one
    /// the isolation model carries a separate adversary for. The conversation's own
    /// reply is deferred past the burst, so what its delivery says is that the
    /// table still held the flow the flood had been arriving alongside.
    Flood,
    /// The shipped routed set, injected into an appliance **nobody has
    /// onboarded** — where every one of the six is refused and none crosses.
    ///
    /// The same six frames as [`Self::Routed`] on purpose, and that is the whole
    /// experiment: two of them are the packets six other scenarios watch cross
    /// this appliance, addressed between the same endpoints under the same
    /// document, and here they do not. What separates the two runs is not the
    /// traffic and not the policy — it is whether a management plane has taken
    /// the node, which is the one precondition that sits in front of every other
    /// decision the dataplane makes.
    ///
    /// So this is the negative half of ownership, stated the only way a negative
    /// can be: with the positive alongside it, from the same bytes. A set of its
    /// own rather than a flag on the routed one, because a probe set *is* the
    /// experiment, and a table saying which set a boot injected is where a reader
    /// finds out what the boot was asking.
    Unowned,
}

impl Traffic {
    /// Every probe set, so a check stated over all of them cannot be one a new set
    /// silently escapes.
    ///
    /// That it really is every one of them is *checked* rather than asserted here:
    /// [`Self::position`] is an exhaustive match, so a variant added to this enum
    /// does not compile without a line there, and
    /// `the_list_of_every_probe_set_holds_every_one_of_them` holds the two to each
    /// other. A comment claiming completeness that nothing compared would be the
    /// defect this exists to close — a set added and left out of the attribution
    /// check fails at its own boot, minutes in, with the harness in the wrong.
    ///
    /// The checks are the only consumer, so it exists only in a test build: a
    /// production-visible list nothing reads would be dead code.
    #[cfg(test)]
    pub const ALL: [Self; 9] = [
        Self::Routed,
        Self::Policy,
        Self::Lifecycle,
        Self::Stateful,
        Self::Flood,
        Self::Reconfiguration,
        Self::Revocation,
        Self::Related,
        Self::Unowned,
    ];

    /// Where this set sits in [`Self::ALL`].
    ///
    /// Its only purpose is to be an exhaustive match beside that array, so the two
    /// cannot disagree about which sets exist.
    #[cfg(test)]
    const fn position(self) -> usize {
        match self {
            Self::Routed => 0,
            Self::Policy => 1,
            Self::Lifecycle => 2,
            Self::Stateful => 3,
            Self::Flood => 4,
            Self::Reconfiguration => 5,
            Self::Revocation => 6,
            Self::Related => 7,
            Self::Unowned => 8,
        }
    }

    /// The document this set's second wave is decided under, where it submits one
    /// over the management API.
    ///
    /// The one place a probe set and the document it is stated against are related,
    /// so a set that grew a `Wave::Submitted` probe without a document to submit
    /// fails here rather than injecting a probe whose verdict the shipped policy
    /// still decides.
    const fn submitted(self) -> Option<&'static [u8]> {
        match self {
            Self::Reconfiguration => Some(crate::config_submission_contract::SUBMITTED),
            Self::Revocation => Some(crate::config_submission_contract::NARROWED),
            Self::Related => Some(crate::config_submission_contract::RELATED),
            Self::Routed
            | Self::Policy
            | Self::Lifecycle
            | Self::Stateful
            | Self::Flood
            | Self::Unowned => None,
        }
    }

    /// How many rules this set's submitted document adds to the booted one's, which
    /// is what the per-rule counter family's cardinality moves by.
    ///
    /// Stated here rather than parsed out of the submitted bytes: it is a property
    /// of the experiment each set is, and a set whose document grew a rule without
    /// this moving fails the cardinality check with the numbers in the verdict.
    const fn rules_added(self) -> usize {
        match self {
            Self::Related => 1,
            Self::Routed
            | Self::Policy
            | Self::Lifecycle
            | Self::Stateful
            | Self::Flood
            | Self::Reconfiguration
            | Self::Revocation
            | Self::Unowned => 0,
        }
    }

    /// Whether this set states what a commit did to the conversations already
    /// running, which is the one contract that has to wait for the re-decision a
    /// commit arms.
    const fn re_decides(self) -> bool {
        matches!(self, Self::Revocation)
    }
}

/// What the injected probes oblige the appliance's filter to have counted.
///
/// The independent half of the per-rule cross-check: the ports and the rule ids
/// come out of the document, and these two say which of the filter's outcomes the
/// boot put traffic through at all.
///
/// **Whether, not how many**, and that is a property of the harness rather than a
/// weakening. A probe that must be *delivered* is re-injected until it arrives —
/// QEMU loses a frame put on a port that has not yet posted a receive buffer — so
/// how many times a refused probe was injected is decided by how long the routed
/// half took. What the appliance forwarded is still an exact number, because the
/// harness counted the frames that came back; what it refused leaves nothing to
/// count but its absence. So the exact statements are the ones stated against the
/// wire and against the appliance's own second account of the same refusals, and
/// these two decide which counters must have moved and which must still read
/// zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyWitness {
    /// The document's own two port rules, which name the two counters.
    pub policy: PortPolicy,
    /// Whether any probe was injected to the port the dropping rule names.
    pub probed_the_denying_rule: bool,
    /// Whether any probe was injected to a port no rule names, which only the
    /// fallthrough can refuse.
    pub probed_the_fallthrough: bool,
    /// Whether the boot injected a packet an *existing flow* had to account for
    /// — a reply to a request that went first.
    ///
    /// Every probe set reaches this, because a probe re-injected before its
    /// delivery was observed is a second packet of a flow the first one opened.
    /// What only the stateful set does is reach it *deliberately*, with a packet
    /// no rule permits, so the counter it raises is evidence rather than a side
    /// effect — which is why the assertion this drives is one-directional.
    pub probed_an_established_flow: bool,
    /// Whether the boot injected a TCP segment from the middle of a conversation
    /// nothing opened. Both directions are asserted on this one: no other probe
    /// in any set is a TCP segment at all, so a refusal on a boot that injected
    /// none is a frame nobody put on the wire.
    pub probed_mid_stream: bool,
    /// How many rules the policy **in force when the scrape is taken** declares,
    /// which is the whole cardinality of the per-rule counter family.
    ///
    /// Not always the booted document's. A scenario that submits one is scraped
    /// under the submitted policy, and a submission may add a rule the booted
    /// document never had — so a count taken from the built-around document alone
    /// would refuse a scrape that is exactly right.
    pub rules: usize,
    /// Whether this boot's appliance had **no owner**, so nothing could be
    /// forwarded and the cross-check that means anything is the refusal count.
    ///
    /// Its own flag rather than "forwarded nothing", because those are different
    /// claims: a boot may forward nothing because its policy admitted nothing,
    /// and then the zero is the filter's. Here the zero is the appliance's, every
    /// frame having been settled in front of admission — so what the exposition
    /// owes is a rise under one reason and a zero under every other, which is a
    /// statement no forwarding number can make.
    pub unowned: bool,
    /// Whether the boot ran **two** policies: one it booted with and one submitted
    /// over the management API while it ran.
    ///
    /// It changes which per-rule statement is available, and that is worth stating
    /// rather than working around. On a boot under one policy each rule's hit count
    /// is attributable — the accepting rule's matches are the openings and the
    /// denying rule's are the denials — because a rule's action does not move. Here
    /// the two rules keep their ids and exchange their actions, so each accrues
    /// hits under both, and what stays exact is the *sum*: every packet that
    /// reached the filter and matched something is an opening or a denial, whichever
    /// generation decided it.
    pub reconfigured: bool,
    /// How many distinct five-tuples this boot floods the appliance with, or zero
    /// where it floods it with none.
    ///
    /// The number the bounded-state claims are stated against: the tracker must
    /// have opened at least this many flows and given back at least this many, and
    /// its occupancy must be a small fraction of it rather than a multiple. Zero
    /// says nothing about the counters — every set that has a probe the filter
    /// refuses withdraws a flow — so the assertions it gates are one-directional.
    pub flooded_tuples: u64,
}

/// The probes one boot injects, and what they oblige the filter to have counted.
///
/// # Errors
/// A bench or a policy this harness cannot state the chosen contract against.
fn injected_probes(
    topology: &Topology,
    traffic: Traffic,
) -> Result<(Vec<Probe>, PolicyWitness), String> {
    let policy = topology.port_policy().map_err(|error| error.to_string())?;
    // Which of the filter's two refusals each set provokes, and whether it reaches
    // the tracker deliberately. Three flags rather than two derived from one,
    // because the reconfiguration set is the first whose answers differ: it
    // provokes the *dropping rule* under both policies and the fallthrough under
    // neither, both of its ports being named by both documents.
    let (probes, denying_rule, fallthrough, stateful) = match traffic {
        // Not one of the six names a port the dropping rule is about, and none of
        // them falls past the last rule: the four refusals are the admission and
        // routing stages', decided before the filter is consulted, and the two
        // routed ones carry the port the accepting rule names. So this set obliges
        // both of the filter's refusal counters to still read zero, which is as
        // strong a statement as a rise and is only available from a set that
        // provokes neither.
        Traffic::Routed => (probes(topology)?, false, false, false),
        // Neither of the filter's refusals, and for a stronger reason than the
        // routed set's: on this boot the filter is never consulted at all. The
        // ownership stage settles every frame in front of admission, so both
        // counters must read zero and so must every other stage's — which is
        // exactly the shape of the claim, an unowned appliance having no opinion
        // about anybody's traffic.
        Traffic::Unowned => (unowned_probes(topology)?, false, false, false),
        Traffic::Policy => (policy_probes(topology, policy), true, true, false),
        // The fallthrough, but not the dropping rule: the unsolicited packet
        // falls past every rule, and nothing in this set is addressed to the port
        // the dropping rule names.
        Traffic::Stateful => (stateful_probes(topology, policy), false, true, true),
        // The dropping rule, and not the fallthrough: one segment is addressed to
        // the port that rule names and every other one to the port the accepting
        // rule names, so nothing here falls past the last rule. The zero is the
        // stronger half of the pair, as it is for the routed set — and the rise is
        // the only place in this gate where a *rule* refuses a TCP segment, every
        // other bench's rules being about UDP alone.
        Traffic::Lifecycle => (lifecycle_probes(topology, policy), true, false, false),
        // The dropping rule under both policies — the shipped one refuses the first
        // wave's second probe and the submitted one refuses the second wave's — and
        // the fallthrough under neither: both ports are named by both documents, so
        // nothing here falls past the last rule. The zero is the stronger half of
        // the pair, as it is for the routed set.
        Traffic::Reconfiguration => (reconfiguration_probes(topology, policy), true, false, false),
        // The fallthrough and nothing else: the revoked conversation's last packet
        // falls past every rule once its flow is gone, and no probe here is
        // addressed to the port the dropping rule names.
        Traffic::Revocation => (revocation_probes(topology, policy), false, true, false),
        // The fallthrough and nothing else: the shipped policy has no rule about
        // related traffic, so the error falls past every rule, and no probe here is
        // addressed to the port the dropping rule names.
        Traffic::Related => (related_probes(topology, policy), false, true, false),
        // The fallthrough, sixty-four times over plus once for good measure: every
        // datagram of the burst is addressed to the port no rule is about. Nothing
        // here carries the dropping rule's port, so that counter must still read
        // zero — which is what keeps a flood that somehow matched a rule from
        // reading as the default deny doing its job.
        Traffic::Flood => (flood_probes(topology, policy), false, true, false),
    };
    Ok((
        probes,
        PolicyWitness {
            policy,
            probed_the_denying_rule: denying_rule,
            probed_the_fallthrough: fallthrough || stateful,
            // The revocation and flood sets reach it deliberately too, and each with
            // a packet no rule permits: the surviving conversation's last frame is
            // carried by its flow under a policy whose one accept rule is about the
            // other direction.
            probed_an_established_flow: stateful
                || matches!(traffic, Traffic::Revocation | Traffic::Flood),
            probed_mid_stream: stateful,
            unowned: matches!(traffic, Traffic::Unowned),
            // The booted document's rules, plus whatever the submitted one adds.
            rules: topology.rule_ids().len() + traffic.rules_added(),
            reconfigured: matches!(
                traffic,
                Traffic::Reconfiguration | Traffic::Revocation | Traffic::Related
            ),
            flooded_tuples: match traffic {
                Traffic::Flood => u64::from(FLOOD_TUPLES),
                Traffic::Routed
                | Traffic::Policy
                | Traffic::Lifecycle
                | Traffic::Stateful
                | Traffic::Reconfiguration
                | Traffic::Revocation
                | Traffic::Related
                | Traffic::Unowned => 0,
            },
        },
    ))
}

/// Two probes under the policy the image was built around, and two more under the
/// policy submitted over HTTP while it runs — the same two destination ports, with
/// the verdicts exchanged.
///
/// Every probe carries its own marker, so a delivery is attributed to the wave that
/// caused it and a frame left over from the first can never satisfy the second.
/// That matters more here than anywhere else in this harness: the second wave's
/// *accepted* probe goes to the port the first wave's *refused* probe went to, so
/// two probes with one marker would make a stale retransmission read as the
/// reversal.
fn reconfiguration_probes(topology: &Topology, policy: PortPolicy) -> Vec<Probe> {
    let [a, b] = topology.endpoints();
    /// The source port the second wave opens its conversations from.
    ///
    /// **A different one, and it is what keeps this scenario about the policy
    /// alone.** A policy decides which conversations may *start*, and on the packet
    /// path a packet an existing flow accounts for is forwarded before the filter
    /// is consulted at all. The first wave's accepted probe opened a conversation,
    /// so a second packet on the same five-tuple would test what the *commit* did
    /// to that conversation rather than what the new document admits — which is a
    /// different contract, and `Traffic::Revocation`'s. So the second wave opens its
    /// own conversations, and what it proves is exactly what a policy is about:
    /// which conversations may start under the document now in force.
    const REOPENED_FROM: u16 = SOURCE_PORT + 1;

    let to_port = |port: u16, marker: &'static [u8]| UdpPacket {
        destination_port: port,
        payload: marker.to_vec(),
        ..datagram(a, b, INJECTED_TTL, marker)
    };
    let reopened = |port: u16, marker: &'static [u8]| UdpPacket {
        source_port: REOPENED_FROM,
        ..to_port(port, marker)
    };
    vec![
        // Under the shipped policy: the accepted port is forwarded and the denied
        // one is dropped by a rule, which is the baseline the reversal is measured
        // against.
        routed(
            "shipped-accepted",
            b"LFW-PROBE/shipped-accepted",
            a,
            b,
            to_port(
                policy.accepted.destination_port,
                b"LFW-PROBE/shipped-accepted",
            ),
        ),
        refused_by_policy(
            recording_contract::EVENT_POLICY_DENIED,
            dropped(
                "shipped-denied",
                b"LFW-PROBE/shipped-denied",
                a,
                "the shipped policy has a rule matching it that says drop",
                to_port(policy.denied.destination_port, b"LFW-PROBE/shipped-denied"),
            ),
        ),
        // And under the submitted one, on the same two ports with the verdicts
        // exchanged. Injected only once the forwarding domain reports the
        // committed generation, so a refusal here is the new policy's.
        after_the_commit(routed(
            "submitted-accepted",
            b"LFW-PROBE/submitted-accepted",
            a,
            b,
            reopened(
                policy.denied.destination_port,
                b"LFW-PROBE/submitted-accepted",
            ),
        )),
        after_the_commit(refused_by_policy(
            recording_contract::EVENT_POLICY_DENIED,
            dropped(
                "submitted-denied",
                b"LFW-PROBE/submitted-denied",
                a,
                "the submitted policy turned the rule that accepted this port into a drop, and \
                 this conversation is a new one rather than the one the first wave opened",
                reopened(
                    policy.accepted.destination_port,
                    b"LFW-PROBE/submitted-denied",
                ),
            ),
        )),
    ]
}

/// Two conversations that differ in one header field, and the two packets that say
/// what a narrowing commit did to each.
///
/// **Both open under the shipped policy's one accept rule** — same destination
/// port, same addresses, same everything but the source port — so nothing about
/// their fates before the commit distinguishes them. The submitted document then
/// narrows that rule to one of the two source ports, and the last two probes are
/// each conversation's *next* packet, on the five-tuple it has been using all
/// along:
///
///   * the surviving conversation's crosses, and it can only be its flow that
///     carries it: the new policy's accept rule is about the request direction and
///     this frame is the reply direction, which no rule of either document names.
///     That is also what says the dataplane is still forwarding across the commit;
///   * the revoked conversation's does not, and that is the whole landing — under
///     the behaviour before it, a tracked flow was forwarded before the filter was
///     consulted, so this frame would have crossed.
///
/// A commit that flushed the table would refuse both and a commit that re-decided
/// nothing would carry both, so the pair separates re-deciding from either.
///
/// Each probe carries its own marker, so a frame left over from the first wave can
/// never satisfy the second — which matters more here than anywhere else in this
/// harness, the last two probes reusing the first two's five-tuples exactly.
fn revocation_probes(topology: &Topology, policy: PortPolicy) -> Vec<Probe> {
    let [a, b] = topology.endpoints();
    let permitted = policy.accepted.destination_port;
    /// The source port the submitted document's narrowed rule still admits.
    const KEPT_FROM: u16 = SOURCE_PORT;
    /// The one it does not. A different source port is the whole of what tells the
    /// two conversations apart, and it is the field the submitted document narrows
    /// on — so the appliance's own re-decision is what has to separate them.
    const REVOKED_FROM: u16 = SOURCE_PORT + 1;

    let request = |source_port: u16, marker: &'static [u8]| UdpPacket {
        source_port,
        destination_port: permitted,
        payload: marker.to_vec(),
        ..datagram(a, b, INJECTED_TTL, marker)
    };
    // The reply direction of one of those conversations: source and destination
    // exchanged, which is what makes it the same flow rather than a second one.
    let reply = |destination_port: u16, marker: &'static [u8]| UdpPacket {
        source_port: permitted,
        destination_port,
        payload: marker.to_vec(),
        ..datagram(b, a, INJECTED_TTL, marker)
    };
    vec![
        routed(
            "revocation-kept-open",
            b"LFW-PROBE/revocation-kept-open",
            a,
            b,
            request(KEPT_FROM, b"LFW-PROBE/revocation-kept-open"),
        ),
        routed(
            "revocation-doomed-open",
            b"LFW-PROBE/revocation-doomed-open",
            a,
            b,
            request(REVOKED_FROM, b"LFW-PROBE/revocation-doomed-open"),
        ),
        // Each conversation answered, so both are flows the tracker has seen in
        // both directions — the state an operator would least expect a policy edit
        // to be able to end, and the one this scenario ends exactly one of.
        routed_after(
            "revocation-kept-reply",
            b"LFW-PROBE/revocation-kept-reply",
            b,
            a,
            reply(KEPT_FROM, b"LFW-PROBE/revocation-kept-reply"),
        ),
        routed_after(
            "revocation-doomed-reply",
            b"LFW-PROBE/revocation-doomed-reply",
            b,
            a,
            reply(REVOKED_FROM, b"LFW-PROBE/revocation-doomed-reply"),
        ),
        // And after the commit, on those same two five-tuples. The surviving
        // conversation is already two-way, so its next packet leaves the flow's
        // state where it was — traffic on a conversation already accounted for,
        // which the connection history deliberately does not record. That is why
        // this one names no event: it is a delivery on the wire and nothing else,
        // and the wire is where the whole of what it proves lies.
        after_the_commit(carried_by_its_flow(routed(
            "revocation-kept-survives",
            b"LFW-PROBE/revocation-kept-survives",
            b,
            a,
            reply(KEPT_FROM, b"LFW-PROBE/revocation-kept-survives"),
        ))),
        after_the_commit(refused_by_policy(
            recording_contract::EVENT_POLICY_NO_MATCH,
            dropped(
                "revocation-doomed-refused",
                b"LFW-PROBE/revocation-doomed-refused",
                b,
                "the commit took back the flow this conversation was being carried by, so it \
                 reaches the filter — where the narrowed policy has no rule about the reply \
                 direction and the default deny refuses it",
                reply(REVOKED_FROM, b"LFW-PROBE/revocation-doomed-refused"),
            ),
        )),
    ]
}

/// An ICMP error, quoting a datagram of a conversation the appliance holds — the
/// only frame in this harness whose classification is decided by bytes the *sender*
/// chose, and the reason those bytes are built here field by field.
///
/// The four agreements `lfw_flow::icmp` corroborates a quote against are all
/// properties of these fields, so a quote built carelessly is refused as
/// `QuotedInvalid` and proves nothing about policy. Two of them are visible in this
/// signature: the quoted `source` must be the error's own `destination` — an error
/// travels from a router back to the sender of the datagram it quotes — and the
/// quoted five-tuple must name a flow the table holds in a direction that flow has
/// carried traffic in.
///
/// The `marker` sits behind the quote. RFC 792 requires the original header and
/// eight bytes of it; carrying more is what every real implementation does, and it
/// is what gives this harness bytes to attribute a delivery by that the quote's own
/// header does not already carry.
struct IcmpErrorPacket {
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source: [u8; 4],
    destination: [u8; 4],
    /// The error type. One of destination-unreachable, time-exceeded and
    /// parameter-problem, which are the three that relate to a flow; anything else
    /// is refused as a type the tracker neither tracks nor relates.
    message_type: u8,
    code: u8,
    ttl: u8,
    /// The datagram this error reports on: a UDP one, whose source must be the
    /// party the error is addressed to.
    quoted_source: [u8; 4],
    quoted_destination: [u8; 4],
    quoted_source_port: u16,
    quoted_destination_port: u16,
    marker: Vec<u8>,
}

impl IcmpErrorPacket {
    fn build(&self) -> Vec<u8> {
        let mut quoted = Vec::with_capacity(IPV4_HEADER_LEN + UDP_HEADER_LEN);
        let mut inner = [0u8; IPV4_HEADER_LEN];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&((IPV4_HEADER_LEN + UDP_HEADER_LEN) as u16).to_be_bytes());
        inner[8] = INJECTED_TTL;
        inner[9] = UDP_PROTOCOL;
        inner[12..16].copy_from_slice(&self.quoted_source);
        inner[16..20].copy_from_slice(&self.quoted_destination);
        let inner_checksum = header_checksum(&inner);
        inner[10..12].copy_from_slice(&inner_checksum.to_be_bytes());
        quoted.extend_from_slice(&inner);
        quoted.extend_from_slice(&self.quoted_source_port.to_be_bytes());
        quoted.extend_from_slice(&self.quoted_destination_port.to_be_bytes());
        quoted.extend_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());
        quoted.extend_from_slice(&0u16.to_be_bytes());

        let mut message = Vec::with_capacity(ICMP_HEADER_LEN + quoted.len());
        message.push(self.message_type);
        message.push(self.code);
        // The checksum, filled in below.
        message.extend_from_slice(&[0, 0]);
        // The four unused bytes an error's header carries.
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&quoted);
        message.extend_from_slice(&self.marker);
        let checksum = ones_complement(&message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = Vec::with_capacity(MIN_ETHERNET_FRAME + message.len());
        frame.extend_from_slice(&self.destination_mac);
        frame.extend_from_slice(&self.source_mac);
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + message.len()) as u16).to_be_bytes());
        ip[8] = self.ttl;
        ip[9] = ICMP_PROTOCOL;
        ip[12..16].copy_from_slice(&self.source);
        ip[16..20].copy_from_slice(&self.destination);
        let checksum = header_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&message);
        if frame.len() < MIN_ETHERNET_FRAME {
            frame.resize(MIN_ETHERNET_FRAME, 0);
        }
        frame
    }

    /// The same error as it must arrive at the far endpoint: the three changes a
    /// hop makes, and nothing else. The ICMP checksum is unaffected — a router
    /// rewrites no byte the message covers.
    fn delivered(&self, to: Endpoint) -> Vec<u8> {
        Self {
            destination_mac: to.mac,
            source_mac: to.gateway_mac,
            ttl: self.ttl - 1,
            marker: self.marker.clone(),
            ..*self
        }
        .build()
    }
}

/// A conversation, an ICMP error about it the shipped policy refuses, and the same
/// error under a document that admits related traffic.
///
/// **The two errors quote the same conversation and differ only in the marker
/// behind the quote**, which is what makes them the same experiment run twice: a
/// second five-tuple would be a second flow, and the difference between the two
/// verdicts would be about the flow rather than about the policy.
fn related_probes(topology: &Topology, policy: PortPolicy) -> Vec<Probe> {
    let [a, b] = topology.endpoints();
    let permitted = policy.accepted.destination_port;
    /// Destination unreachable, port unreachable: what a host answers a datagram
    /// no socket is listening for, and the commonest related error there is.
    const UNREACHABLE: u8 = 3;
    const PORT_UNREACHABLE: u8 = 3;

    let request = |marker: &'static [u8]| UdpPacket {
        source_port: SOURCE_PORT,
        destination_port: permitted,
        payload: marker.to_vec(),
        ..datagram(a, b, INJECTED_TTL, marker)
    };
    // Addressed to A, quoting the datagram A sent to B: the agreement that stops an
    // attacker quoting a conversation it merely knows about.
    let error = |marker: &'static [u8]| IcmpErrorPacket {
        destination_mac: b.gateway_mac,
        source_mac: b.mac,
        source: b.address,
        destination: a.address,
        message_type: UNREACHABLE,
        code: PORT_UNREACHABLE,
        ttl: INJECTED_TTL,
        quoted_source: a.address,
        quoted_destination: b.address,
        quoted_source_port: SOURCE_PORT,
        quoted_destination_port: permitted,
        marker: marker.to_vec(),
    };
    let denied = error(b"LFW-PROBE/related-denied");
    let allowed = error(b"LFW-PROBE/related-allowed");

    vec![
        routed(
            "related-open",
            b"LFW-PROBE/related-open",
            a,
            b,
            request(b"LFW-PROBE/related-open"),
        ),
        // Refused by the default deny, and that refusal is the whole of the first
        // half: the quote is corroborated, so the tracker relates the frame — and
        // relating it still does not admit it.
        deferred_probe(refused_by_policy(
            recording_contract::EVENT_POLICY_NO_MATCH,
            dropped_frame(
                "related-denied",
                b"LFW-PROBE/related-denied",
                b,
                "the shipped policy has no rule about related traffic, so an ICMP error the                  tracker relates to a live conversation still falls to the default deny",
                denied.build(),
            ),
        )),
        // The conversation, re-opened under the submitted generation.
        //
        // Not a duplicate of the first wave's request and not tuning: what the
        // second half of this scenario asks is whether the *submitted* policy
        // admits an error related to a live conversation, so the conversation
        // has to be live when the error arrives. Between the two waves the
        // harness commits a configuration and waits out a settle window, and
        // this bench is otherwise silent for the whole of it — so on a slow
        // enough machine the tracker ages the first wave's flow out and the
        // error that follows is unrelated to anything, refused for a reason
        // this scenario is not about. Re-opening makes the second half depend
        // on the policy rather than on how fast the machine ran, which is the
        // only thing it was ever meant to state. It is a routed request under a
        // policy that admits it, so it is immediate: the error below defers
        // behind it and therefore behind the flow it needs.
        after_the_commit(on_a_flow_it_may_or_may_not_open(routed(
            "related-reopen",
            b"LFW-PROBE/related-reopen",
            a,
            b,
            request(b"LFW-PROBE/related-reopen"),
        ))),
        // And after the commit, the same error on the same flow. It opens no
        // conversation — an error reports on one somebody else opened — so its
        // record names no lifecycle event and the whole of what it proves is the
        // delivery and the rule that admitted it.
        after_the_commit(carried_by_its_flow(Probe {
            name: String::from("related-allowed"),
            marker: b"LFW-PROBE/related-allowed",
            from: b,
            frame: allowed.build(),
            expectation: Expectation::Routed {
                to: a,
                delivered: allowed.delivered(a),
                // Not a datagram this harness models field by field, so a delivery
                // that departs from the contract is reported as bytes.
                datagram: None,
            },
            observed: true,
            deferred: false,
            once: false,
            event: None,
            wave: Wave::Shipped,
        })),
    ]
}

/// A probe that must wait for the conversation it belongs to.
fn deferred_probe(probe: Probe) -> Probe {
    Probe {
        deferred: true,
        ..probe
    }
}

/// A probe whose delivery is the contract and whose effect on the connection
/// history deliberately is not.
///
/// The one shape that needs this is a request re-sent onto a conversation an
/// earlier phase opened: whether it *opens* a flow or *advances* one depends on
/// whether the earlier flow is still there, which depends on how long the phase
/// between them took, which is a property of the machine and not of the
/// appliance. Asserting either lifecycle event would make the scenario state
/// something it does not mean; asserting neither leaves exactly what it does —
/// that the frame was routed. Every other probe still names its event, so this
/// is a hole in one probe's contract and not a weakening of the check.
fn on_a_flow_it_may_or_may_not_open(probe: Probe) -> Probe {
    Probe {
        event: None,
        ..probe
    }
}

/// A probe that must wait for the conversation it belongs to and that moves that
/// conversation's state nowhere: traffic on a flow already accounted for, which the
/// connection history holds no record of by design.
fn carried_by_its_flow(probe: Probe) -> Probe {
    Probe {
        deferred: true,
        event: None,
        ..probe
    }
}

/// A probe whose verdict is the submitted policy's, so it must not go out while the
/// shipped one is still in force.
fn after_the_commit(probe: Probe) -> Probe {
    Probe {
        wave: Wave::Submitted,
        ..probe
    }
}

/// A request, its reply, an unsolicited packet in the reply direction, and a TCP
/// segment from mid-conversation.
///
/// **The reply is the whole point.** It is addressed to the port the request came
/// *from*, and the document says nothing about that port in either direction — so
/// a stateless filter could only carry it by naming it in a rule of its own, and
/// this appliance carries it because the request opened a flow it belongs to.
/// `librefirewall_flow_packets_total{outcome="established"}` is what says so, and
/// `librefirewall_rule_hits_total` is what says no rule did.
///
/// The other two are what keep that from being a hole. The unsolicited packet has
/// the same *shape* as the reply — reply direction, out of the port the accepting
/// rule names — and no request in front of it, so it falls past every rule to the
/// default deny. And a bare `ACK` for a five-tuple nothing opened must be refused
/// as mid-stream rather than adopted, which is the one packet that would otherwise
/// buy an attacker a way around default deny.
///
/// The reply's destination port is the request's source port and the unsolicited
/// packet's is one above it, so the two are different five-tuples and the second
/// cannot be answered by the first's flow. Both come from `policy` rather than
/// from a literal, so a document that renamed its ports is asserted against its
/// own text.
fn stateful_probes(topology: &Topology, policy: PortPolicy) -> Vec<Probe> {
    let [a, b] = topology.endpoints();
    let permitted = policy.accepted.destination_port;
    let request = UdpPacket {
        destination_port: permitted,
        payload: b"LFW-PROBE/stateful-request".to_vec(),
        ..datagram(a, b, INJECTED_TTL, b"LFW-PROBE/stateful-request")
    };
    // The reply: source and destination exchanged, which is what makes it the
    // same flow rather than a second one.
    let reply = |marker: &'static [u8], destination_port: u16| UdpPacket {
        source_port: permitted,
        destination_port,
        payload: marker.to_vec(),
        ..datagram(b, a, INJECTED_TTL, marker)
    };
    vec![
        routed(
            "stateful-request",
            b"LFW-PROBE/stateful-request",
            a,
            b,
            request,
        ),
        routed_after(
            "stateful-reply",
            b"LFW-PROBE/stateful-reply",
            b,
            a,
            reply(b"LFW-PROBE/stateful-reply", SOURCE_PORT),
        ),
        refused_by_policy(
            recording_contract::EVENT_POLICY_NO_MATCH,
            dropped(
                "stateful-unsolicited",
                b"LFW-PROBE/stateful-unsolicited",
                b,
                "it is the reply direction with no request in front of it, so it opens a flow no \
                 rule permits and falls to the default deny",
                reply(
                    b"LFW-PROBE/stateful-unsolicited",
                    SOURCE_PORT.saturating_add(1),
                ),
            ),
        ),
        refused_by_tracker(dropped_frame(
            "stateful-mid-stream",
            b"LFW-PROBE/stateful-mid-stream",
            a,
            "it is a bare ACK for a five-tuple nothing opened, which the tracker refuses rather \
             than adopting",
            TcpPacket {
                destination_mac: a.gateway_mac,
                source_mac: a.mac,
                source: a.address,
                destination: b.address,
                source_port: SOURCE_PORT,
                destination_port: permitted,
                // A bare `ACK`: the shape of a segment from the middle of a
                // conversation. The two sequence numbers decide nothing — a
                // segment on an unknown five-tuple is refused for its flags
                // before any window is consulted.
                flags: 0x10,
                sequence: 0x0001_0000,
                acknowledgement: 0x0002_0000,
                ttl: INJECTED_TTL,
                payload: b"LFW-PROBE/stateful-mid-stream".to_vec(),
            }
            .build(),
        )),
    ]
}

/// A TCP conversation that opens, is refused a segment outside its window, and
/// closes — plus the one segment a rule refuses outright.
///
/// **The close is a reset, and that is the shortest honest one.** A graceful close
/// needs four more segments and every one of them a sequence number this harness
/// would have to keep in step with the appliance's own window arithmetic; a reset
/// is admissible from the state a `SYN` leaves and moves the flow straight to the
/// state a conversation does not leave. So the recording carries an open and a
/// close, and the close names *how* — which is what a reader asks of a connection
/// history.
///
/// **The refusal is between them, and goes out once.** A segment a million bytes
/// past anything the peer authorised is outside the window of a flow that is open;
/// once the reset has closed the flow, the same segment is one no state admits at
/// all, which is a different refusal. So it is injected exactly once, into the
/// state the opening established, and its reason is the one that state produces.
///
/// The three segments above carry the accepting rule's destination port, so the
/// difference between the reset's fate and the out-of-window segment's is the
/// connection table and nothing else.
///
/// **The fourth segment is the only probe in this harness a rule refuses for its
/// protocol.** It is a `SYN` to the port the *dropping* rule names, and it is
/// reachable on no other bench: both other documents' rules say `protocol="udp"`,
/// so a TCP segment matches neither and is refused by the default deny — a
/// refusal that says nothing about protocol matching, since a rule about the port
/// never decided it. Here the two rules say `protocol="any"`, so the segment
/// reaches the dropping rule and the rule refuses it: the same rule that drops a
/// datagram to that port drops a segment to it, and the per-rule counter is what
/// separates that from the fallthrough. Every port comes from `policy` rather than
/// from a literal, so a document that renamed its ports is asserted against its
/// own text.
fn lifecycle_probes(topology: &Topology, policy: PortPolicy) -> Vec<Probe> {
    let [a, b] = topology.endpoints();
    /// The sequence space the conversation opens on. Its value decides nothing;
    /// what matters is that the two segments below are stated against it.
    const CLIENT_ISN: u32 = 0x0051_0000;
    /// How far past the window the refused segment sits — far beyond the 65535
    /// bytes a `SYN` can advertise, so no window this exchange establishes
    /// reaches it.
    const PAST_THE_WINDOW: u32 = 1_000_000;
    let to_port = |destination_port: u16, flags: u8, sequence: u32, marker: &[u8]| {
        TcpPacket {
            destination_mac: a.gateway_mac,
            source_mac: a.mac,
            source: a.address,
            destination: b.address,
            source_port: SOURCE_PORT,
            destination_port,
            flags,
            sequence,
            // No segment here carries an `ACK` flag, so the field is read by
            // nothing and is left at zero rather than given a plausible value
            // nothing would check.
            acknowledgement: 0,
            ttl: INJECTED_TTL,
            payload: marker.to_vec(),
        }
        .build()
    };
    let permitted = policy.accepted.destination_port;
    let segment =
        |flags: u8, sequence: u32, marker: &[u8]| to_port(permitted, flags, sequence, marker);
    vec![
        // `SYN`, which is the only thing that opens a TCP flow here.
        routed_frame(
            "lifecycle-open",
            b"LFW-PROBE/lifecycle-open",
            a,
            b,
            recording_contract::EVENT_FLOW_OPENED,
            segment(TCP_SYN, CLIENT_ISN, b"LFW-PROBE/lifecycle-open"),
        ),
        // The same opening segment, one destination port along: routable in every
        // other respect, and refused because a rule about that port says drop.
        refused_by_policy(
            recording_contract::EVENT_POLICY_DENIED,
            dropped_frame(
                "lifecycle-denied",
                b"LFW-PROBE/lifecycle-denied",
                a,
                "a rule matched it and says drop, and it is a TCP segment rather than a datagram: \
                 this bench's rules say `protocol=\"any\"`, so the rule decided it on its port \
                 rather than the default deny refusing it for its protocol",
                to_port(
                    policy.denied.destination_port,
                    TCP_SYN,
                    CLIENT_ISN,
                    b"LFW-PROBE/lifecycle-denied",
                ),
            ),
        ),
        // `RST` well past the window the `SYN` opened. Refused, so it moves no
        // state, refreshes no timeout and closes nothing.
        only_once(refused_by_tracker(dropped_frame(
            "lifecycle-out-of-window",
            b"LFW-PROBE/lifecycle-out-of-window",
            a,
            "its sequence number is a million bytes past anything the peer authorised, so the \
             tracker refuses it rather than letting it move the flow",
            segment(
                TCP_RST,
                CLIENT_ISN.wrapping_add(PAST_THE_WINDOW),
                b"LFW-PROBE/lifecycle-out-of-window",
            ),
        ))),
        // `RST` inside the window, which ends the conversation. Deferred, so the
        // flow it closes is one the opening above has been observed to create.
        Probe {
            deferred: true,
            event: Some(recording_contract::EVENT_FLOW_CLOSED),
            ..routed_frame(
                "lifecycle-close",
                b"LFW-PROBE/lifecycle-close",
                a,
                b,
                recording_contract::EVENT_FLOW_CLOSED,
                // One past the `SYN`, which occupies a byte of sequence space of
                // its own: the reset is the next thing this side sends.
                segment(
                    TCP_RST,
                    CLIENT_ISN.wrapping_add(1),
                    b"LFW-PROBE/lifecycle-close",
                ),
            )
        },
    ]
}

/// How many distinct five-tuples the flood set puts across the appliance.
///
/// Chosen against what it has to demonstrate rather than against the table's
/// size, which nothing this harness can inject would fill: the claim is that
/// occupancy does not grow with the flood, so the count has to be large enough
/// that a table holding one conversation is unmistakably not holding the flood
/// too. Sixty-four openings against the one that survives is a ratio no
/// accounting slip reproduces, and it is a burst two ports carry in one pass —
/// the frames go out together, every one of them is refused, and each is put on
/// the wire again on every retransmission pass until the run settles.
const FLOOD_TUPLES: u16 = 64;

/// The first source port the flood opens a conversation from; the burst takes
/// [`FLOOD_TUPLES`] consecutive ports up from here.
///
/// High in the ephemeral range and disjoint from every other port this harness
/// sends from, so no flood conversation can be the one the surviving
/// conversation is carried by.
const FLOOD_FIRST_SOURCE_PORT: u16 = 0xf000;

/// The marker every flood datagram carries.
///
/// One marker across the whole burst, and that is not a weakening: a marker
/// attributes a *delivery*, every frame here must be refused, and a frame of
/// this burst coming back fails the run whichever of the sixty-four it was. What
/// the frames are told apart by is their source port, which is what makes them
/// distinct five-tuples — and the capture recording is where each of them is
/// held to having arrived, byte for byte and one block per probe
/// ([`crate::surface_contract`]).
///
/// It is deliberately not `LFW-PROBE/flood`. Attribution is by *substring*, so a
/// marker that is a prefix of another probe's makes that probe's delivery read as
/// this one's — and this set's other two markers begin `LFW-PROBE/flood-`.
/// `every_probe_set_is_attributable_marker_by_marker` is what holds every set to
/// that rather than a reader noticing.
const FLOOD_MARKER: &[u8] = b"LFW-PROBE/burst";

/// A conversation the policy admits, and a burst of distinct five-tuples it does
/// not: what a **connection flood** looks like from the wire.
///
/// The order the three parts reach the appliance in is the experiment, and it
/// follows from how this harness injects rather than from a phase written for it.
/// The request and the whole burst go out together from the first pass and on
/// every retransmission pass after it, so the flood is running before the
/// appliance has answered anything. The reply is deferred — it may only go out
/// once the request has been observed coming out the far side — so **its delivery
/// is a packet the connection table carried after the table had already absorbed
/// the flood**, which is what "evicts no established flow" means on a wire. No
/// rule of any document names the port that reply is addressed to, so its flow is
/// the only thing that could have carried it.
///
/// Every datagram in the burst is addressed to the port no rule is about, so each
/// falls past the last rule to the default deny — and each therefore *opens* a
/// flow the filter then refuses, which the appliance gives back in the same
/// evaluation. That is the property this set exists for: on a default-deny
/// appliance the flood's own refusal is what returns the slot, and a node that
/// left them behind would be a state-exhaustion amplifier with a correct-looking
/// policy.
///
/// The ports come from `policy` rather than from literals, so the burst is
/// addressed to a port *this document's* rules leave to the default deny.
fn flood_probes(topology: &Topology, policy: PortPolicy) -> Vec<Probe> {
    let [a, b] = topology.endpoints();
    let permitted = policy.accepted.destination_port;
    let mut probes = Vec::with_capacity(2 + usize::from(FLOOD_TUPLES));
    probes.push(routed(
        "flood-request",
        b"LFW-PROBE/flood-request",
        a,
        b,
        UdpPacket {
            destination_port: permitted,
            payload: b"LFW-PROBE/flood-request".to_vec(),
            ..datagram(a, b, INJECTED_TTL, b"LFW-PROBE/flood-request")
        },
    ));
    // The reply, on the flow the request opened and on a port no rule names.
    // Deferred, so it goes onto the wire after the request has crossed — by which
    // time the burst below has been arriving since the first injection pass.
    probes.push(routed_after(
        "flood-survivor",
        b"LFW-PROBE/flood-survivor",
        b,
        a,
        UdpPacket {
            source_port: permitted,
            destination_port: SOURCE_PORT,
            payload: b"LFW-PROBE/flood-survivor".to_vec(),
            ..datagram(b, a, INJECTED_TTL, b"LFW-PROBE/flood-survivor")
        },
    ));
    for index in 0..FLOOD_TUPLES {
        probes.push(refused_by_policy(
            recording_contract::EVENT_POLICY_NO_MATCH,
            dropped(
                // Zero-padded so the report's rows sort as they were injected.
                format!("flood-{index:04}"),
                FLOOD_MARKER,
                a,
                "it is one of a burst of distinct five-tuples addressed to a port no rule is \
                 about, so it opens a flow, falls past the last rule to the default deny, and the \
                 appliance gives the slot straight back",
                UdpPacket {
                    source_port: FLOOD_FIRST_SOURCE_PORT.wrapping_add(index),
                    destination_port: policy.unmatched,
                    payload: FLOOD_MARKER.to_vec(),
                    ..datagram(a, b, INJECTED_TTL, FLOOD_MARKER)
                },
            ),
        ));
    }
    probes
}

/// One probe per outcome the filter can reach, differing in the one field that
/// decides which: the UDP destination port.
///
/// Every other byte is the same routable datagram, so nothing about admission or
/// routing separates the three — which is what makes the difference between their
/// fates attributable to the policy and to nothing else. The ports and the rule
/// ids come from `policy`, so a document that renamed a rule or moved a port is
/// asserted against its own text.
fn policy_probes(topology: &Topology, policy: PortPolicy) -> Vec<Probe> {
    let [a, b] = topology.endpoints();
    let to_port = |port: u16, marker: &'static [u8]| UdpPacket {
        destination_port: port,
        payload: marker.to_vec(),
        ..datagram(a, b, INJECTED_TTL, marker)
    };
    vec![
        routed(
            "policy-accepted",
            b"LFW-PROBE/policy-accepted",
            a,
            b,
            to_port(
                policy.accepted.destination_port,
                b"LFW-PROBE/policy-accepted",
            ),
        ),
        refused_by_policy(
            recording_contract::EVENT_POLICY_DENIED,
            dropped(
                "policy-denied",
                b"LFW-PROBE/policy-denied",
                a,
                "a rule matched it and says drop; it is routable in every other respect",
                to_port(policy.denied.destination_port, b"LFW-PROBE/policy-denied"),
            ),
        ),
        refused_by_policy(
            recording_contract::EVENT_POLICY_NO_MATCH,
            dropped(
                "policy-unmatched",
                b"LFW-PROBE/policy-unmatched",
                a,
                "no rule is about it, so it falls past the last one to the default deny",
                to_port(policy.unmatched, b"LFW-PROBE/policy-unmatched"),
            ),
        ),
    ]
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
    name: impl Into<String>,
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
        name: name.into(),
        marker,
        from,
        frame: sent.build(),
        expectation: Expectation::Routed {
            to,
            delivered: delivered.build(),
            datagram: Some(Datagrams { sent, delivered }),
        },
        // Built from a [`UdpPacket`], so the router parses it and reaches a
        // decision on it — which is what the tap records.
        observed: true,
        deferred: false,
        once: false,
        // A datagram to a port a rule accepts opens a conversation, and the
        // record of that is the open event. A re-injected one is a
        // retransmission that moves nothing, so it carries no event and the
        // contract is stated as "at least one record of this probe names an
        // opening" rather than as a count.
        event: Some(recording_contract::EVENT_FLOW_OPENED),
        wave: Wave::Shipped,
    }
}

/// A routed probe that may only go out once the immediate ones have arrived.
///
/// A probe that has to wait is one whose flow another probe opened, so what its
/// record names is an *advance* of that conversation and never an opening.
fn routed_after(
    name: impl Into<String>,
    marker: &'static [u8],
    from: Endpoint,
    to: Endpoint,
    sent: UdpPacket,
) -> Probe {
    Probe {
        deferred: true,
        event: Some(recording_contract::EVENT_FLOW_ADVANCED),
        ..routed(name, marker, from, to, sent)
    }
}

/// A probe the appliance must forward, carrying a frame this harness built itself
/// rather than a [`UdpPacket`].
///
/// The delivery is derived from the injection by applying exactly the three
/// changes a hop makes — the far endpoint's MAC, the far interface's MAC, and one
/// less TTL, with the IPv4 header checksum recomputed over the result. Derived
/// rather than written out for [`routed`]'s reason: "every other byte unchanged"
/// stays the default the contract has to break.
fn routed_frame(
    name: impl Into<String>,
    marker: &'static [u8],
    from: Endpoint,
    to: Endpoint,
    event: u8,
    frame: Vec<u8>,
) -> Probe {
    let delivered = hopped(&frame, to);
    Probe {
        name: name.into(),
        marker,
        from,
        frame,
        expectation: Expectation::Routed {
            to,
            delivered,
            // Not a datagram this harness models, so its delivery is judged and
            // reported as bytes.
            datagram: None,
        },
        observed: true,
        deferred: false,
        once: false,
        event: Some(event),
        wave: Wave::Shipped,
    }
}

/// The frame the appliance must put on the wire for `frame`, routed towards `to`.
///
/// Written against the offsets rather than through a decoder, because the point
/// is to change *only* what a hop changes: a decoder would rebuild the frame and
/// silently normalise whatever it did not model.
fn hopped(frame: &[u8], to: Endpoint) -> Vec<u8> {
    let mut out = frame.to_vec();
    if let Some(target) = out.get_mut(..MAC_PAIR_LEN) {
        target[..6].copy_from_slice(&to.mac);
        target[6..].copy_from_slice(&to.gateway_mac);
    }
    let at = ETHERNET_HEADER_LEN;
    if let Some(header) = out
        .get_mut(at..at.saturating_add(IPV4_HEADER_LEN))
        .and_then(|slice| <&mut [u8; IPV4_HEADER_LEN]>::try_from(slice).ok())
    {
        header[8] = header[8].saturating_sub(1);
        header[10..12].copy_from_slice(&[0, 0]);
        let checksum = header_checksum(header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
    out
}

/// A probe whose refusal the **filter** reached, under whichever of its two
/// outcomes `event` names.
fn refused_by_policy(event: u8, probe: Probe) -> Probe {
    Probe {
        event: Some(event),
        ..probe
    }
}

/// A probe the **tracker** refused, so it never reached the filter at all and the
/// record names the refusal rather than a policy decision.
fn refused_by_tracker(probe: Probe) -> Probe {
    Probe {
        event: Some(recording_contract::EVENT_FLOW_REFUSED),
        ..probe
    }
}

/// A probe injected exactly once, into the flow state its phase established.
fn only_once(probe: Probe) -> Probe {
    Probe {
        once: true,
        ..probe
    }
}

fn dropped(
    name: impl Into<String>,
    marker: &'static [u8],
    from: Endpoint,
    because: &'static str,
    sent: UdpPacket,
) -> Probe {
    Probe {
        name: name.into(),
        marker,
        from,
        frame: sent.build(),
        expectation: Expectation::Dropped { because },
        // A refusal is a decision, and the tap records it with the reason. Only
        // a frame the parser cannot read at all escapes observation, and every
        // probe built from a [`UdpPacket`] parses.
        observed: true,
        deferred: false,
        once: false,
        // Which of the refusals it is depends on which stage refused it, so a
        // caller that knows says so; the default claims nothing.
        event: None,
        wave: Wave::Shipped,
    }
}

/// A probe that must be refused, carrying a frame this harness built itself
/// rather than a [`UdpPacket`].
fn dropped_frame(
    name: impl Into<String>,
    marker: &'static [u8],
    from: Endpoint,
    because: &'static str,
    frame: Vec<u8>,
) -> Probe {
    Probe {
        name: name.into(),
        marker,
        from,
        frame,
        expectation: Expectation::Dropped { because },
        // A TCP segment over well-formed IPv4 parses, so the router reaches a
        // decision on it and the tap records that decision with its reason.
        observed: true,
        deferred: false,
        once: false,
        event: None,
        wave: Wave::Shipped,
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

/// What a boot must prove. Every variant injects the same packets into the same
/// ports; they differ in which observation is success.
pub enum BootContract<'a> {
    /// Both routed packets must arrive on the far port rewritten exactly for
    /// their next hop, and no refused packet may arrive at all.
    ///
    /// The traffic is what this variant *proves*, and on a boot that also owes a
    /// record of the channel it dials it is not the whole of what ends the run:
    /// such a boot waits for that record too ([`BootTest::channel`]). The two
    /// are settled by different domains on different passes, and a run that
    /// stopped on the traffic alone would race the one the appliance writes last.
    Routed,
    /// **The cryptography domain came up and finished**, and nothing else is
    /// judged at all.
    ///
    /// The narrowest contract here, and deliberately so: it exists for a boot
    /// whose only question is whether the shipped image's cryptography executes
    /// on a *different* accelerator from the one the rest of the run used. Every
    /// other statement this harness can make — the routed contract, the
    /// configuration transcript, the management port's count, the recordings —
    /// is a statement about the image and not about the accelerator, and the
    /// boots that carry it already made all of them. Re-making them here would
    /// buy a second verdict on the same fact and pay a whole boot for it.
    ///
    /// So the probes go out as on any other boot and no delivery is required;
    /// nothing is injected on the management wire and nothing is expected back
    /// from it. The one thing the run waits for is the cryptography domain
    /// having said it finished, either way, which is also what ends the boot:
    /// such a node keeps running, so nothing else would.
    ///
    /// The verdict itself is the caller's, from the records this leaves in the
    /// capture — a domain that refused is a refusal to report rather than a
    /// boot that failed to complete.
    ///
    /// It waits for the **store domain** to have finished too, which is not a
    /// second contract but the same one: this domain authenticates under a key
    /// that domain holds, and the claim that the two name one appliance can only
    /// be checked with both renderings in the capture. That domain establishes its
    /// identity before this one's first vector runs, so the wait is free.
    Cryptography,
    /// **The store domain came up and established an identity**, and nothing else
    /// is judged at all.
    ///
    /// [`Self::Cryptography`]'s shape and, for the pair of boots it belongs to,
    /// its reasoning: the routed contract, the transcript and the management
    /// port's count are statements about the image that the shipped boots already
    /// make, and re-making them here would pay two whole boots for a second
    /// verdict on the same fact. What only these two boots can settle is whether
    /// the appliance's identity survives a reboot, which is a claim about a
    /// medium and not about a boot.
    ///
    /// So the probes go out as on any other boot and no delivery is required, and
    /// the one thing the run waits for is the store domain having said it
    /// finished — its fingerprint record, or a refusal. Such a node keeps
    /// running, so nothing else would end the boot.
    ///
    /// It owes the store medium's own verdict and not the recorder's, and that
    /// asymmetry is deliberate: the store domain writes before it parks and the
    /// run ends on its own last record, so the medium is settled by then. Nothing
    /// orders that against the recorder's proof of its own path, which is why the
    /// recorder's disk is not judged here — a witness asserted there would be
    /// asserted on a race.
    StoreIdentity,
    /// No injected packet may come back in any form (nothing bootable may have
    /// started) and the guest must emit `marker` on the serial channel. Used
    /// for the boot manager's halt path, where the absence of a dataplane is
    /// the point.
    Halted {
        /// The structured record whose presence proves the halt path was
        /// reached. It is matched as an exact byte substring, never as prose.
        marker: &'a str,
    },
    /// **The node booted and forwards nothing**, because it refused the
    /// configuration document its own image carries.
    ///
    /// Distinct from both siblings, and from each for a different reason. Unlike
    /// [`Self::Routed`], no injected packet may come back — there is no committed
    /// policy for one to be admitted by, and no route for one to take. Unlike
    /// [`Self::Halted`], a slot *did* boot: every protection domain is running, the
    /// recorder puts its witness on the medium, and the guest never exits. So the
    /// absence of traffic alone would be indistinguishable from a node that died
    /// before its drivers came up, and what separates the two is the console —
    /// which is the only surface such a node has, its management port being
    /// unaddressed until a generation commits.
    ///
    /// Nothing may come back on the management wire either, and that is a second
    /// statement rather than a restatement: the port answers ARP and ICMP echo for
    /// the address a *committed* configuration gives it, so a reply here would be a
    /// domain answering under addressing no generation published.
    FailedClosed {
        /// The transcript the boot must produce. It also decides when the run may
        /// stop waiting: the absences are judged once the capture is complete, but
        /// the records are what say the node has finished refusing.
        transcript: &'a crate::config_transcript::RefusedContract,
    },
}

/// The non-QEMU inputs of one boot test: what it must prove and where its run
/// log goes.
pub struct BootTest<'a> {
    /// The contract the boot is judged against.
    pub contract: BootContract<'a>,
    /// The workspace this run builds in. Reached for by the one client that
    /// composes rather than only reads: the management server this harness
    /// plays keeps its certification authority under the build tree and carries
    /// the committed package fixture out of the source tree.
    pub root: &'a Path,
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
    /// Which probe set the boot injects.
    pub traffic: Traffic,
    /// What the boot holds the appliance to on the channel it dials out of its
    /// management port, and how the station on the far end of it behaves. Every
    /// socket-backed wire answers a dial; this decides whether the exchange must
    /// complete, whether the appliance's own record of it is read, and which of
    /// the four ways a management server can misbehave this station plays.
    pub dial: crate::qemu::DialContract,
    /// How the station this harness plays on the appliance's **second** listening
    /// port behaves — the onboarding port, which carries a byte stream rather
    /// than a request.
    ///
    /// Every boot but the four whose subject it is opens nothing there, and not
    /// out of economy: the port holds one connection at a time, so a session on
    /// every boot would put one beside every other contract this harness states.
    ///
    /// The whole contract rather than the station's behaviour alone, because the
    /// fourth of those boots has no station: it lets real clients onto the wire
    /// through a forwarded host port, which is a different thing to be told.
    pub onboard: crate::qemu::OnboardContract,
    /// What the appliance owes on the **console** for the channel it dials, which
    /// is what such a boot waits for before it ends.
    ///
    /// Its own field beside [`Self::dial`] because the two are different
    /// surfaces: that one is the transport's account, read off a station on the
    /// wire, and this is the session's, read off the appliance's own output. A
    /// boot that stopped when its traffic was decided would kill the guest with
    /// the session's record still unwritten — the domain that terminates a
    /// session writes on the pass that decided it, which is later than anything
    /// the routed contract waits for.
    pub channel: crate::channel_contract::ChannelContract,
    /// Whether QEMU is executing the guest on hardware rather than emulating
    /// it. Carried through to [`Booted`] because one judge needs it and cannot
    /// re-derive it honestly: a cycle count taken under emulation measures the
    /// emulator, so the throughput floor is asserted on an accelerated run and
    /// reported without a verdict on any other.
    pub hardware_accelerated: bool,
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
    /// QEMU's user-mode (SLIRP) stack with a host port forward to **each** of
    /// the two ports the endpoint listens on, so `curl` and `openssl` — clients
    /// nothing in this repository wrote — can be pointed at them. Nothing at
    /// frame level is asserted on this wire: the harness never sees one.
    UserNetwork {
        /// The loopback port on the host side of the forward to the request
        /// surface, reserved by [`reserve_host_ports`] before QEMU is told about
        /// it.
        host_port: u16,
        /// The same, for the onboarding port. Both forwards exist on every
        /// user-mode boot rather than one per scenario: a forward nothing dials
        /// costs a line of QEMU's command and carries nothing, and a backing
        /// whose shape depended on the contract would be two backings.
        onboard_port: u16,
    },
}

impl ManagementBacking {
    /// Whether the harness holds a socket for the management port, and so
    /// whether there is a stream to accept and a station to play — and,
    /// negated, whether a real client can reach the endpoint and pull what it
    /// serves.
    pub const fn is_socket(self) -> bool {
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
                (
                    GuestNic::Management,
                    ManagementBacking::UserNetwork {
                        host_port,
                        onboard_port,
                    },
                ) => user_netdev(
                    &nic.netdev_id(),
                    &topology.management(),
                    host_port,
                    onboard_port,
                ),
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
fn user_netdev(id: &str, management: &ManagementPort, host_port: u16, onboard_port: u16) -> String {
    let endpoint = ipv4(management.address);
    format!(
        "user,id={id},net={}/{},host={},hostfwd=tcp:127.0.0.1:{host_port}-{endpoint}:\
         {MANAGEMENT_TCP_PORT},hostfwd=tcp:127.0.0.1:{onboard_port}-{endpoint}:{}",
        ipv4(management.network()),
        management.prefix_length,
        ipv4(management.station),
        pd_runtime::ONBOARDING_PORT,
    )
}

/// Take `N` loopback ports nothing else holds, and let them all go at once.
///
/// The same trick the NIC listeners use, for the same reason: a fixed port would
/// collide with whatever else is running on a shared runner. There is a window
/// between releasing them and QEMU binding them, and it is accepted — the
/// alternative is handing QEMU listening sockets, which its `hostfwd` does not
/// take.
///
/// **Every listener is held until every port has been taken**, and that is the
/// whole reason this reserves a set rather than being called once per port. A
/// function that bound one socket, read its number and dropped it hands the next
/// caller a port the kernel has just freed — which it readily reuses, so two
/// consecutive calls can answer the same number. QEMU then refuses the second
/// forwarding rule and exits before a single frame crosses, which reads as a boot
/// that failed rather than as two rules for one port.
///
/// # Errors
/// A port that could not be bound, or a set with a repeat in it — which cannot
/// arise while the listeners are alive and is answered rather than asserted,
/// because a duplicate reaching QEMU is the failure this exists to prevent.
pub fn reserve_host_ports<const N: usize>() -> Result<[u16; N], String> {
    let mut held = Vec::with_capacity(N);
    let mut ports = [0_u16; N];
    for port in &mut ports {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("reserve a host port for the management forward: {error}"))?;
        *port = listener
            .local_addr()
            .map(|address| address.port())
            .map_err(|error| format!("read the reserved host port: {error}"))?;
        held.push(listener);
    }
    for (at, port) in ports.iter().enumerate() {
        if ports
            .iter()
            .skip(at.saturating_add(1))
            .any(|other| other == port)
        {
            return Err(format!(
                "the host reserved port {port} twice for one boot's forwards, which QEMU refuses \
                 as a duplicate forwarding rule. The listeners are held until every port is \
                 taken, so this is the host handing back a port it had not freed"
            ));
        }
    }
    Ok(ports)
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

/// The ARP reply the station answers the appliance's own request with: the
/// station's pair as the sender, and the port that asked as the target.
///
/// Composed here rather than reused from the appliance's own builder, on
/// [`tcp_frame`]'s terms: a frame built by the code under test and answered to
/// that code would agree with itself.
fn station_arp_reply(management: &ManagementPort) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
    frame.extend_from_slice(&management.mac);
    frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
    frame.extend_from_slice(&ARP_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&ARP_REPLY.to_be_bytes());
    frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
    frame.extend_from_slice(&management.station);
    frame.extend_from_slice(&management.mac);
    frame.extend_from_slice(&management.address);
    frame
}

/// The ARP reply a misbehaving station answers with: a station nothing asked
/// about, claiming its own address at its own hardware address.
///
/// Every field of it is well formed. It is addressed to the port that asked, its
/// Ethernet source is the sender its payload names, the sender is unicast, and
/// the address it claims is on the prefix the port is addressed from — so it
/// passes every check a frame faces before the neighbour cache is consulted, and
/// the one thing wrong with it is that this end asked about somebody else.
fn impostor_arp_reply(management: &ManagementPort) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
    frame.extend_from_slice(&management.mac);
    frame.extend_from_slice(&IMPOSTOR_MAC);
    frame.extend_from_slice(&ARP_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&ARP_REPLY.to_be_bytes());
    frame.extend_from_slice(&IMPOSTOR_MAC);
    frame.extend_from_slice(&IMPOSTOR_ADDRESS);
    frame.extend_from_slice(&management.mac);
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
    decode_tcp_to(frame, management, management.station)
}

/// The destination port of a TCP-over-IPv4 frame, read positionally and without
/// judging anything else about it.
///
/// It is what routes a segment to the half of this wire it belongs to — the
/// connection the harness opened, or the one the appliance did — and it is
/// deliberately not a decode: the chosen judge decodes the frame whole and
/// verifies its checksum, so nothing here decides whether a segment is
/// well-formed.
fn tcp_destination_port(frame: &[u8]) -> Option<u16> {
    let at = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 2;
    let pair = frame.get(at..at + 2)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

/// [`decode_tcp`], for a segment addressed somewhere other than the station's
/// own address.
///
/// The pseudo-header the checksum covers names the datagram's own addresses, and
/// the appliance dials a first-party constant rather than the station it reaches
/// that constant through. Passing the destination in is what keeps one decoder
/// for both halves of this wire: a second copy would be a second checksum
/// routine to be right or wrong on its own.
fn decode_tcp_to(
    frame: &[u8],
    management: &ManagementPort,
    destination: [u8; 4],
) -> Result<TcpFrame, String> {
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
    let computed = tcp_checksum(&management.address, &destination, segment);
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
    station_segment(
        management,
        management.station,
        Ports {
            source: CLIENT_PORT,
            destination: MANAGEMENT_TCP_PORT,
        },
        Numbers {
            sequence,
            acknowledgement,
        },
        flags,
        CLIENT_WINDOW,
        payload,
    )
}

/// The two ports a segment this harness composes runs between, named rather
/// than passed as an adjacent pair: the station speaks to two halves of the
/// appliance on this wire, and a pair swapped by hand would address one of them
/// as the other.
#[derive(Clone, Copy)]
struct Ports {
    source: u16,
    destination: u16,
}

/// A segment's own two numbers, named for [`Ports`]' reason.
#[derive(Clone, Copy)]
struct Numbers {
    sequence: u32,
    acknowledgement: u32,
}

/// One TCP segment from this harness's station to the appliance, as a whole
/// frame on the wire.
///
/// The composition every segment this harness sends goes through, whichever half
/// it is addressed to: the client's connection into the endpoint's listening
/// port, and the station's answers to the connection the appliance dialled out
/// of it. One composer rather than two, so a checksum or a header field can only
/// be right or wrong once.
fn station_segment(
    management: &ManagementPort,
    source: [u8; 4],
    ports: Ports,
    numbers: Numbers,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (sequence, acknowledgement) = (numbers.sequence, numbers.acknowledgement);
    let mut segment = Vec::with_capacity(TCP_HEADER_LEN + payload.len());
    segment.extend_from_slice(&ports.source.to_be_bytes());
    segment.extend_from_slice(&ports.destination.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&acknowledgement.to_be_bytes());
    // Five words of header and no options: the client offers no maximum segment
    // size, so the appliance must fall back on RFC 1122's default rather than on
    // whatever the option would have said.
    segment.push(5 << 4);
    segment.push(flags);
    segment.extend_from_slice(&window.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    let checksum = tcp_checksum(&source, &management.address, &segment);
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
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&management.address);
    let header_checksum = header_checksum(&ip);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&segment);
    frame
}

/// The RFC 793 section 3.1 checksum over the pseudo-header and the segment.
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
    /// One step of the connection the appliance itself dialled, named by the
    /// step it completed. The other direction of this wire: everything above is
    /// the appliance answering, and this is the appliance asking.
    Dial(DialStep),
    /// One step of the connection this harness opened to the appliance's
    /// onboarding port, named by the step it completed. The appliance answering
    /// again, on the other of the two ports its endpoint listens on.
    Onboard(OnboardStep),
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

/// Where the station's side of the connection the appliance dialled has got to.
///
/// The mirror of [`TcpStep`]: there the harness opens and the appliance answers,
/// and here the appliance opens and the harness answers. Each step both asserts
/// what came in and composes what goes back, so the contract is met only by
/// walking the whole of it — and the last step is the one that says the
/// appliance closed cleanly rather than merely stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DialStep {
    /// Nothing yet: the appliance has not asked who holds the station's address.
    Unasked,
    /// It asked and the station answered for itself, so the next hop it dials
    /// through is resolved.
    Resolved,
    /// Its `SYN` arrived, the station answered `SYN-ACK`, and its own
    /// acknowledgement completed the handshake. **The last step there is**: the
    /// channel is a stream this appliance has nothing to put on yet, so the
    /// connection is held from here and a station that waited for anything more
    /// would be waiting for a byte no part of this appliance composes.
    Handshaken,
}

/// How the station on the far end of the appliance's dial behaves.
///
/// A property of the station rather than of the boot, so every scenario whose
/// subject is something else takes [`Answers`](Self::Answers) and is unaffected.
/// The four that do not are the four ways a management server or the link to it
/// can misbehave, and each is a *mode* rather than a phase: the station holds it
/// for the whole boot, so a reader never has to work out which half of a run a
/// frame belongs to.
///
/// What every mode has in common is the claim beside the outcome — the node goes
/// on forwarding, its management port goes on counting to the byte, and no bound
/// of either end is exceeded. A channel that fails is a channel that fails, and
/// nothing else about the appliance moves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DialMisbehaviour {
    /// Answers for its own address and completes the handshake, and then holds
    /// the connection open — which is the whole of what a well-behaved
    /// management server does to a channel meant to persist.
    #[default]
    Answers,
    /// Answers the resolution and never the `SYN`. Nothing on the far end is
    /// listening, and nothing says so either.
    SilentToTheDial,
    /// Answers the `SYN` with a reset acknowledging it — what a station with
    /// nothing bound to that port sends, and the fastest refusal there is.
    ResetsTheDial,
    /// Answers the `SYN` with a `SYN-ACK` acknowledging a number the appliance
    /// never sent.
    ///
    /// The one mode whose subject is an *ordering*: RFC 793's arrival processing
    /// checks the acknowledgement before it believes a handshake, so this draws a
    /// reset and leaves the dial standing rather than cancelling it. A single
    /// segment naming a number nobody sent must not be able to end a connection
    /// this node originated, and what this scenario watches is that it does not.
    AcknowledgesTheWrongSequence,
    /// Answers the resolution for an address nothing asked about, and never for
    /// the next hop.
    AnswersForAnotherAddress,
}

impl DialMisbehaviour {
    /// Whether this station carries the channel through to a connection that is
    /// up, which is what a boot judging the whole exchange waits for.
    const fn completes(self) -> bool {
        matches!(self, Self::Answers)
    }

    /// Whether the appliance's own reset is part of this station's contract.
    ///
    /// True for exactly the mode that provokes one: an acknowledgement of what
    /// was never sent is answered with a reset carrying the number that was
    /// claimed. Everywhere else a reset from the appliance is a connection it
    /// tore down and a failure of the boot — including where a dial is
    /// abandoned, the transport composing none for a handshake that never
    /// completed.
    const fn expects_a_reset(self) -> bool {
        matches!(self, Self::AcknowledgesTheWrongSequence)
    }

    /// How many `SYN`s this station will answer before it calls the appliance
    /// broken.
    const fn dial_limit(self) -> usize {
        match self {
            // The two that leave a `SYN` unanswered: every retransmission of it
            // reaches this wire, so the bound is the whole budget the appliance
            // may spend rather than the restart allowance.
            Self::SilentToTheDial | Self::AcknowledgesTheWrongSequence => {
                DIAL_SYNS_WHILE_UNANSWERED
            }
            _ => DIAL_RESTART_LIMIT,
        }
    }

    /// How many resolutions this station will answer before it calls the
    /// appliance broken.
    const fn resolution_limit(self) -> usize {
        match self {
            Self::AnswersForAnotherAddress => DIAL_REQUESTS_WHILE_UNRESOLVED,
            _ => DIAL_RESTART_LIMIT,
        }
    }
}

impl DialStep {
    /// What the appliance still owes, as a clause for a verdict.
    fn outstanding(self) -> &'static str {
        match self {
            Self::Unasked => "the ARP request for the station it dials through",
            Self::Resolved => "the SYN of the connection it dials",
            Self::Handshaken => "none",
        }
    }
}

/// The station's own end of the connection the appliance dialled.
///
/// Deliberately not a TCP stack, on [`TcpClient`]'s terms: the wire is a host
/// socket, so it is lossless and in-order. What it does hold is the whole of the
/// sequence-number arithmetic and the ephemeral port the appliance chose, both
/// of which are learned from the appliance rather than assumed.
#[derive(Clone, Debug)]
struct DialStation {
    /// How this station behaves, chosen once per boot and held for the whole of
    /// it.
    misbehaviour: DialMisbehaviour,
    /// Resets the appliance sent because this station acknowledged what it never
    /// sent. Counted rather than merely tolerated: the mode that provokes one
    /// must see one, or the ordering it exists to state was never exercised.
    resets: usize,
    step: DialStep,
    /// The ephemeral port the appliance dialled from, learned from its `SYN`. A
    /// station cannot know it in advance: the transport picks it, and picking it
    /// here would be the harness testing its own guess.
    peer_port: Option<u16>,
    /// The appliance's initial sequence number, kept for the verdict and for the
    /// same reason [`TcpClient::peer_isn`] is: a constant one would be an
    /// off-path injection primitive.
    peer_isn: Option<u32>,
    /// The next sequence number this station will send, and what it expects to
    /// receive next.
    sequence: u32,
    expect: u32,
    /// The probe as it arrived, accumulated across however many segments carry
    /// it. Judged whole rather than per segment, a request being a stream.
    probe: Vec<u8>,
    /// What the station owes the wire, composed as each step is judged and put
    /// on it by the caller against the console's own count.
    owed: VecDeque<Vec<u8>>,
    /// Resolutions asked for and connections opened, each bounded by
    /// [`DIAL_RESTART_LIMIT`].
    ///
    /// Both are counted rather than forbidden, because both are ordinary on a
    /// link where the dial does not complete: an entry that expires is asked
    /// about again, and a session the appliance gives up on is followed by
    /// another under its own schedule. What a bound catches is the case
    /// neither of those explains — a node asking or opening without end.
    resolutions: usize,
    dials: usize,
    /// Bytes the appliance has put on the channel, accumulated across every
    /// session of the boot. Counted rather than kept: what a station that
    /// answers nothing can state about them is how many there were.
    offered: usize,
    /// Segments that repeated sequence space this station had already taken,
    /// across every session of the boot. Bounded by [`DIAL_REPEAT_LIMIT`]: a
    /// peer whose every segment is one it already sent is not carrying a
    /// channel, and the bytes of a re-send are not new bytes offered.
    repeats: usize,
}

impl DialStation {
    fn new(misbehaviour: DialMisbehaviour) -> Self {
        Self {
            misbehaviour,
            resets: 0,
            step: DialStep::Unasked,
            peer_port: None,
            peer_isn: None,
            sequence: STATION_ISN,
            expect: 0,
            probe: Vec::new(),
            owed: VecDeque::new(),
            resolutions: 0,
            dials: 0,
            offered: 0,
            repeats: 0,
        }
    }

    /// Whether the appliance has finished the channel it opened.
    fn completed(&self) -> bool {
        self.step == DialStep::Handshaken
    }

    /// The pair this station claimed against what the appliance had really
    /// sent, where it claims one at all.
    ///
    /// It is the harness's own arithmetic — the number it chose, and one past
    /// the initial sequence number it read off the appliance's `SYN` — so
    /// comparing the appliance's console against it is two independent accounts
    /// of one exchange rather than the appliance agreeing with itself.
    fn claim(&self) -> Option<(u32, u32)> {
        (self.misbehaviour == DialMisbehaviour::AcknowledgesTheWrongSequence)
            .then_some(())
            .and(self.peer_isn)
            .map(|isn| (UNSENT_ACKNOWLEDGEMENT, isn.wrapping_add(1)))
    }

    /// What this station has seen, as a clause for a verdict.
    fn seen(&self) -> String {
        format!(
            "the station is {:?}; the appliance's own dial is at {:?} and still owes {}; it \
             dialled from port {} with initial sequence {}, opened {} connection(s) after {} \
             resolution(s) and reset {} of them, {} segments repeated space already taken, and {} \
             probe bytes have arrived — with this station having put nothing on the wire to carry \
             any of it",
            self.misbehaviour,
            self.step,
            self.step.outstanding(),
            self.peer_port
                .map_or_else(|| String::from("(none)"), |port| port.to_string()),
            self.peer_isn
                .map_or_else(|| String::from("(none)"), |isn| isn.to_string()),
            self.dials,
            self.resolutions,
            self.resets,
            self.repeats,
            self.probe.len()
        )
    }
}

/// How the station on the appliance's **onboarding** port behaves.
///
/// [`DialMisbehaviour`]'s shape on the other direction of the same wire, and the
/// reason it is a mode rather than a script is the same: the station holds one
/// for the whole boot, so a reader never has to work out which half of a capture
/// a frame belongs to, and a failure in one of the three is attributable to the
/// scenario that chose it.
///
/// What differs is which end connects. The dial's station *accepts* what the
/// appliance opens; this one *opens* what the appliance accepts, which is
/// [`TcpClient`]'s shape — and it is the half of that port no scenario had ever
/// driven, the port having been proved by host tests and fuzzing alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OnboardBehaviour {
    /// Nothing is opened at all. Every scenario whose subject is something else
    /// takes this, and takes it for a reason beyond economy: the port holds one
    /// connection, so a station that opened one on every boot would put a
    /// session beside every other contract this harness states.
    #[default]
    Untouched,
    /// Connects, delivers one payload in one segment, closes its half, and
    /// acknowledges the close the appliance answers with. The ordinary end of a
    /// session an administrator finished with.
    Completes,
    /// The same up to the appliance's acknowledgement of the payload, and then a
    /// **reset** instead of a close.
    ///
    /// The acknowledgement is what it waits on rather than an interval, so the
    /// reset lands on a session the appliance has certainly taken the bytes of.
    /// Neither end says the session is over, so what both domains must report is
    /// a session the transport forgot — which is a different thing for an
    /// operator to look at from one a peer hung up on, and was a single token
    /// between them until the far end was told how a close ended.
    Abandons,
    /// [`Completes`](Self::Completes), and opens a **second** connection from a
    /// port of its own while the first is established.
    ///
    /// The port holds one connection and an established one is not evictable, so
    /// the second `SYN` finds no slot and is dropped by the transport itself.
    /// What this scenario states is therefore an **absence** — nothing comes back
    /// to that port at all, not a handshake and not a refusal — beside the
    /// evidence that the session already running was not disturbed by it.
    Crowds,
}

impl OnboardBehaviour {
    /// Whether this boot opens a session on the onboarding port at all.
    pub(crate) const fn opens(self) -> bool {
        !matches!(self, Self::Untouched)
    }

    /// Whether this station ends its session with a reset rather than a close.
    const fn resets(self) -> bool {
        matches!(self, Self::Abandons)
    }

    /// Whether this station opens a second connection beside the one it is
    /// carrying.
    pub(crate) const fn crowds(self) -> bool {
        matches!(self, Self::Crowds)
    }
}

/// Where the onboarding station's connection has got to.
///
/// [`TcpStep`]'s shape on the port that carries a byte stream rather than a
/// request: the exchange is a sequence, each step asserts what came back and
/// decides what goes out, and the contract is met only by walking the whole of
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnboardStep {
    /// Nothing sent yet.
    Unopened,
    /// `SYN` sent; the appliance owes a `SYN-ACK`.
    AwaitSynAck,
    /// The payload is out; the appliance owes an acknowledgement covering it.
    AwaitAck,
    /// This end has closed its half; the appliance owes its own `FIN`.
    AwaitFin,
    /// This end reset the connection. Terminal: the station owes nothing further
    /// and composes nothing, whatever arrives.
    ///
    /// Segments still may arrive, and tolerating them is the contract rather than
    /// a relaxation of it. A reset agrees nothing with the peer and does not
    /// overtake what the peer already put on the wire, so the close it had decided
    /// on for itself — or a repeat of what it already sent — crosses the reset and
    /// lands here. What is refused is a segment the appliance could not have
    /// composed before it saw the reset: a `SYN` re-offering the connection, or a
    /// sequence number past the space it had reached.
    Reset,
    /// The appliance's `FIN` has been acknowledged and both halves are closed.
    Closed,
}

impl OnboardStep {
    /// What the appliance still owes, as a clause for a verdict.
    fn outstanding(self) -> &'static str {
        match self {
            Self::Unopened => "the onboarding connection has not been opened",
            Self::AwaitSynAck => "the SYN-ACK of the onboarding connection",
            Self::AwaitAck => "the acknowledgement of the onboarding payload",
            Self::AwaitFin => "the FIN closing the onboarding session",
            Self::Reset | Self::Closed => "none",
        }
    }

    /// Whether the appliance has finished with this station, whichever way the
    /// station ended it.
    const fn finished(self) -> bool {
        matches!(self, Self::Reset | Self::Closed)
    }
}

/// This harness's own end of the connection it opens to the appliance's
/// onboarding port.
///
/// [`TcpClient`]'s arithmetic driven by [`DialStation`]'s machinery: it connects
/// and holds the whole of the sequence-number arithmetic, and it holds a mode
/// for the whole boot and queues what it owes rather than answering inline. The
/// queue is what lets one event owe two frames — the crowding `SYN` and the
/// close after it — and what keeps every frame released against the console's
/// own count, exactly as the dial station's are.
#[derive(Clone, Debug)]
struct OnboardStation {
    /// How this station behaves, chosen once per boot and held for the whole of
    /// it.
    behaviour: OnboardBehaviour,
    step: OnboardStep,
    /// The next sequence number this station will send, and what it expects to
    /// receive next.
    sequence: u32,
    expect: u32,
    /// The appliance's initial sequence number for this connection, kept for the
    /// verdict.
    peer_isn: Option<u32>,
    /// Payload bytes this station has actually put on the wire.
    ///
    /// Counted rather than taken from the constant, because it is what both
    /// domains' `onboard-received=` is held to: a contract compared against a
    /// literal beside the sender would agree with itself about a segment that
    /// was never composed.
    delivered: u64,
    /// Segments the appliance has sent on the session's connection, bounded by
    /// [`ONBOARD_SEGMENT_LIMIT`].
    segments: usize,
    /// Whether the second connection's `SYN` has gone out, and how many segments
    /// came back addressed to it.
    ///
    /// The second number is the whole of what the crowding scenario asserts, and
    /// it is asserted as an absence: a well-behaved port answers a `SYN` it has
    /// no slot for with nothing at all, so any segment here is a frame that must
    /// not exist. It is counted as well as refused so the station's own account
    /// can state the zero rather than leaving a reader to infer it from the run
    /// having passed.
    crowded: bool,
    crowd_answers: usize,
    /// What this station owes the wire, composed as each segment is judged and
    /// put on it by the caller against the console's own count.
    owed: VecDeque<Vec<u8>>,
}

impl OnboardStation {
    fn new(behaviour: OnboardBehaviour) -> Self {
        Self {
            behaviour,
            step: OnboardStep::Unopened,
            sequence: ONBOARD_STATION_ISN,
            expect: 0,
            peer_isn: None,
            delivered: 0,
            segments: 0,
            crowded: false,
            crowd_answers: 0,
            owed: VecDeque::new(),
        }
    }

    /// Open the connection, once.
    ///
    /// The one frame on this half of the wire nothing provokes: every other is
    /// composed while a segment is judged. Called by the run loop when the boot
    /// has reached the point where an exact management count is possible, and
    /// never twice — a re-sent `SYN` would be this harness retransmitting on a
    /// lossless host socket, which is the harness testing itself.
    fn open(&mut self, port: &ManagementPort) {
        if self.step != OnboardStep::Unopened || !self.behaviour.opens() {
            return;
        }
        self.step = OnboardStep::AwaitSynAck;
        self.owed.push_back(onboard_segment(
            port,
            ONBOARD_STATION_PORT,
            Numbers {
                sequence: self.sequence,
                acknowledgement: 0,
            },
            TCP_SYN,
            &[],
        ));
    }

    /// Whether this boot's station has finished everything it set out to do.
    ///
    /// The wire's half of the answer only: what the run waits on besides is the
    /// appliance's own record of the session, which is where the session's
    /// account and the port's totals are.
    fn completed(&self) -> bool {
        !self.behaviour.opens() || self.step.finished()
    }

    /// What this station has seen, as a clause for a verdict.
    fn seen(&self) -> String {
        if !self.behaviour.opens() {
            return String::from("this boot opens no onboarding session");
        }
        format!(
            "the onboarding station is {:?}; its connection is at {:?} and still owes {}; it \
             opened from port {ONBOARD_STATION_PORT} and the appliance answered with initial \
             sequence {}, {} payload byte(s) went out, {} segment(s) came back, the second \
             connection was {}opened and drew {} answer(s) — with this station having put nothing \
             on the wire to carry any of it",
            self.behaviour,
            self.step,
            self.step.outstanding(),
            self.peer_isn
                .map_or_else(|| String::from("(none)"), |isn| isn.to_string()),
            self.delivered,
            self.segments,
            if self.crowded { "" } else { "not " },
            self.crowd_answers
        )
    }

    /// What the run reports back about this station, for the contract that
    /// judges the console beside it.
    fn account(&self) -> OnboardAccount {
        OnboardAccount {
            behaviour: self.behaviour,
            delivered: self.delivered,
            crowded: self.crowded,
            crowd_answers: self.crowd_answers,
            segments: self.segments,
        }
    }
}

/// One segment from the onboarding station, on either of the two ports it opens
/// from, as a whole frame on the wire.
///
/// [`tcp_frame`]'s counterpart for this station: the same composer underneath,
/// so a header field or a checksum can only be right or wrong once, with the
/// port and the window this station's own.
fn onboard_segment(
    port: &ManagementPort,
    source: u16,
    numbers: Numbers,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    station_segment(
        port,
        port.station,
        Ports {
            source,
            destination: pd_runtime::ONBOARDING_PORT,
        },
        numbers,
        flags,
        ONBOARD_WINDOW,
        payload,
    )
}

/// What the onboarding station observed, carried out of the boot so the console
/// can be held to it.
///
/// The harness's own numbers rather than the appliance's: `delivered` is what
/// this end actually put on the wire, and the two domains' `onboard-received=`
/// is compared against it, so the two accounts of one session are independent
/// rather than the appliance agreeing with itself.
#[derive(Clone, Copy, Debug)]
pub struct OnboardAccount {
    pub behaviour: OnboardBehaviour,
    pub delivered: u64,
    /// Whether the second connection's `SYN` was ever put on the wire, and how
    /// many segments came back addressed to it. The crowding scenario's whole
    /// claim is that the first is true and the second is zero.
    pub crowded: bool,
    pub crowd_answers: usize,
    pub segments: usize,
}

impl OnboardAccount {
    /// This station's account, in the voice of the routed-traffic lines.
    pub fn render(&self, port: &ManagementPort) -> String {
        format!(
            "  answered   onboarding-session    station->mgmt  {}:{ONBOARD_STATION_PORT} -> \
             {}:{}  station {:?}  {} payload byte(s) delivered, {} segment(s) back, second \
             connection {}",
            ipv4(port.station),
            ipv4(port.address),
            pd_runtime::ONBOARDING_PORT,
            self.behaviour,
            self.delivered,
            self.segments,
            if self.crowded {
                format!("opened and answered {} time(s)", self.crowd_answers)
            } else {
                String::from("not opened")
            }
        )
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
    /// Of those, the ones that repeated sequence space this client had already
    /// taken. Bounded by [`CLIENT_REPEAT_LIMIT`]: a peer whose every segment is
    /// one it already sent is not making the exchange happen.
    repeats: usize,
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
            repeats: 0,
            last_segment: None,
        }
    }

    /// What this client has seen, as a clause for a verdict.
    fn seen(&self) -> String {
        match self.last_segment {
            None => String::from("no segment has come back at all"),
            Some((flags, sequence, acknowledgement, payload)) => format!(
                "{} segments came back holding {} response bytes, {} of them repeating sequence \
                 space already taken, the last with flags {flags:#04x} sequence {sequence} \
                 acknowledgement {acknowledgement} and {payload} payload bytes; this client's next \
                 sequence is {} and it expects {}",
                self.segments,
                self.response.len(),
                self.repeats,
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
            // Reached on every station-backed boot, and often: the caller routes
            // a TCP step to `opened` and everything else here, so each of the
            // dial's own frames — the resolutions, the `SYN`s, the segments of
            // the exchange — lands on this line. `dialled` and `resolved` are
            // the transitions, printed once each where the step moves; this is
            // the frame beside them, and the step is the whole of what it has to
            // say about one.
            ManagementReply::Dial(step) => format!("  answered   dial-step {step:?}"),
            // Reached on every boot that opens an onboarding session, and once
            // per segment of it: the account of the whole session is written
            // where the run ends, and this is the frame beside it.
            ManagementReply::Onboard(step) => format!("  answered   onboard-step {step:?}"),
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
        station: &mut DialStation,
        onboard: &mut OnboardStation,
    ) -> Result<ManagementReply, String> {
        for probe in probes {
            if contains(frame, probe.marker) {
                return Err(format!(
                    "probe {} came back on the management port. The design isolates that port \
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
            // ARP is one of two things here, and the operation separates them:
            // the reply the harness's own request obliges, or the request the
            // appliance asks its next hop with when it dials out.
            Some(ARP_ETHERTYPE) => {
                if decode_arp(frame)?.operation == ARP_REQUEST {
                    return self
                        .judge_dial_arp(frame, station)
                        .map(ManagementReply::Dial);
                }
                self.judge_arp(frame).map(|()| ManagementReply::Arp)
            }
            // An IPv4 datagram is one of three things on this wire. The protocol
            // number separates the echo reply from the segments, and the ports
            // separate the two connections: one the harness opened into the
            // endpoint's listening port, one the appliance opened out of its own.
            Some(IPV4_ETHERTYPE) if is_tcp(frame) => {
                if tcp_destination_port(frame) == Some(DIAL_PORT) {
                    return self
                        .judge_dial_tcp(frame, station)
                        .map(ManagementReply::Dial);
                }
                // The two connections this harness opens are told apart by the
                // port it opened each from, which is the only thing that
                // separates them: both run from the station's address to the
                // appliance's, and both are answered by the same endpoint.
                if matches!(
                    tcp_destination_port(frame),
                    Some(ONBOARD_STATION_PORT | ONBOARD_CROWD_PORT)
                ) {
                    return self
                        .judge_onboard_tcp(frame, onboard)
                        .map(ManagementReply::Onboard);
                }
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
    /// matches a substring or a rendered line.
    ///
    /// A segment carrying sequence space this client has already taken is the
    /// appliance re-sending one it has not seen acknowledged, which is a peer
    /// working: it is judged against what was sent there before
    /// ([`judge_repeat`]), leaves the client where it was, and counts against
    /// [`CLIENT_REPEAT_LIMIT`]. Everything else belongs to a step.
    ///
    /// # Errors
    /// The verdict, naming the field and the two values. A segment carrying
    /// sequence space this connection has not reached and arriving at a step it
    /// does not belong to is refused rather than tolerated: the whole value of
    /// asserting a sequence is that its order is part of the contract.
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
        // A retransmission is not misbehaviour, and it reaches this client at
        // every step past the handshake. This end answers on its own schedule —
        // one queued frame a pass, released against what the console says
        // arrived — so the appliance's timer fires on a range this client has
        // already taken while its answer is still in the queue, and what comes
        // back is a segment it has seen before. The wire can lose a frame
        // outright as well, which is the same thing arriving for a different
        // reason.
        //
        // Such a segment is identified by its numbers rather than by its shape:
        // it occupies sequence space this client has already taken, ending no
        // later than the number it next expects, compared as offsets from the
        // appliance's own initial number so the arithmetic wraps with the
        // sequence space rather than breaking across it. It carries nothing
        // new, so nothing in this client's model moves for it — and what is
        // refused inside that branch is every shape a repeat cannot have.
        //
        // Zero-length segments are deliberately not repeats: they occupy no
        // sequence space at all, so *every* one of them would qualify, and the
        // per-step assertions on the acknowledgement they carry are exactly
        // what this connection is judged by. They go on to the step, as they
        // always did.
        if let Some(peer_isn) = client.peer_isn {
            let occupied = (segment.payload.len() as u32)
                .saturating_add(u32::from(segment.carries(TCP_SYN, 0)))
                .saturating_add(u32::from(segment.carries(TCP_FIN, 0)));
            let start = segment.sequence.wrapping_sub(peer_isn);
            let taken = client.expect.wrapping_sub(peer_isn);
            if occupied > 0 && start.saturating_add(occupied) <= taken {
                return judge_repeat(&segment, client, peer_isn, start);
            }
        }
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
                // A `SYN` reaching here is one the repeat branch above did not
                // account for: it sits on sequence space this connection has
                // not reached, so it is not the passive open being re-sent but
                // a second one at a number of its own — a transport offering to
                // establish a connection it is already carrying.
                if !segment.carries(TCP_ACK, TCP_SYN) {
                    return Err(format!(
                        "the appliance answered with flags {:#04x} at sequence {}, and an \
                         established connection owes an ACK with no SYN. Its passive open sat on \
                         {}, and re-sending that one is taken; this is another",
                        segment.flags,
                        segment.sequence,
                        client.peer_isn.map_or_else(
                            || String::from("(no number at all)"),
                            |isn| isn.to_string()
                        )
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
                // The appliance's own `FIN` re-sent is not refused here — the
                // repeat branch above took it, this end's `FIN` having already
                // acknowledged it. What this refuses is a `FIN` on sequence
                // space the appliance had not reached, which is a second close
                // of a connection it had already closed once.
                if !segment.carries(TCP_ACK, TCP_SYN | TCP_FIN) {
                    return Err(format!(
                        "the appliance answered the client's FIN with flags {:#04x} at sequence \
                         {}, and a peer that has already closed owes a bare ACK; this client had \
                         taken up to {}",
                        segment.flags, segment.sequence, client.expect
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
            // A close agrees what both ends have exchanged and nothing about
            // what is still travelling, so a segment repeating that agreed
            // space crosses it and was taken by the branch above. This refuses
            // what genuinely contradicts the close: sequence space the
            // appliance had not reached when it acknowledged this end's `FIN`,
            // which is a connection it is still writing to.
            TcpStep::Closed => Err(format!(
                "a segment came back after the connection closed carrying sequence space the \
                 appliance had not reached: flags {:#04x}, sequence {}, and this client had taken \
                 up to {}",
                segment.flags, segment.sequence, client.expect
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
            // The appliance has re-sent its passive open, so this end's own
            // acknowledgement has not reached it — and that acknowledgement is
            // the segment carrying the request. A bare one here would complete
            // the handshake and then wait out the whole budget for a response to
            // a request the appliance never took, so what goes back is the
            // segment again: `client.sequence` is what the appliance last
            // acknowledged, and it standing short of everything this client has
            // sent is the definition of an outstanding range.
            TcpStep::AwaitResponse if client.sequence != TcpClient::sent_through_request() => (
                TcpStep::AwaitResponse,
                tcp_frame(
                    &self.port,
                    client.sequence,
                    client.expect,
                    TCP_ACK | TCP_PSH,
                    TCP_REQUEST,
                ),
            ),
            TcpStep::AwaitResponse => (
                TcpStep::AwaitResponse,
                tcp_frame(&self.port, client.sequence, client.expect, TCP_ACK, &[]),
            ),
            // The client's `FIN` is already out; what remains is the appliance's
            // acknowledgement of it, which `judge_tcp` closes the exchange on.
            //
            // Nothing is composed for a segment repeating what this end has
            // already taken here either, and that is deliberate rather than an
            // omission. The `FIN` this client sent acknowledges the appliance's
            // own and is on the wire; a re-send of it would agree nothing more,
            // and the appliance answers every acceptable segment in TIME-WAIT
            // with an acknowledgement — so it would draw one more segment out of
            // a connection this end had finished with.
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

    /// One segment of the connection this harness opened to the onboarding port,
    /// judged against the step it belongs to, with the station's answer composed
    /// for it.
    ///
    /// Every assertion is a field comparison, on [`judge_tcp`](Self::judge_tcp)'s
    /// terms: the flags that must be set and the flags that must not, and the
    /// acknowledgement against what this station actually sent. Nothing here
    /// matches a substring.
    ///
    /// **A segment addressed to the second connection is refused wherever it
    /// arrives**, and that is the crowding scenario's whole claim: the port holds
    /// one connection and an established one is not evictable, so a `SYN` for a
    /// second finds no slot and is dropped in silence. A handshake, a reset, or
    /// anything else answering it would each be the port doing something other
    /// than nothing.
    ///
    /// # Errors
    /// The verdict, naming the field and the two values.
    fn judge_onboard_tcp(
        &self,
        frame: &[u8],
        station: &mut OnboardStation,
    ) -> Result<OnboardStep, String> {
        let segment = decode_tcp(frame, &self.port)?;
        if segment.source_port != pd_runtime::ONBOARDING_PORT {
            return Err(format!(
                "a segment addressed to the onboarding station came from port {} and the station \
                 opened to {}",
                segment.source_port,
                pd_runtime::ONBOARDING_PORT
            ));
        }
        if segment.destination_port == ONBOARD_CROWD_PORT {
            station.crowd_answers = station.crowd_answers.saturating_add(1);
            return Err(format!(
                "the appliance answered the second connection's SYN with flags {:#04x} (sequence \
                 {}, acknowledgement {}). This port holds one connection and an established one \
                 is not evictable, so a second SYN finds no slot and nothing to take one from — \
                 the transport drops it, and an answer of any shape here is that bound not \
                 holding",
                segment.flags, segment.sequence, segment.acknowledgement
            ));
        }
        station.segments = station.segments.saturating_add(1);
        if station.segments > ONBOARD_SEGMENT_LIMIT {
            return Err(format!(
                "{} segments have come back on the onboarding connection and a session of this \
                 shape is a handshake, one acknowledgement and a close. A port answering past \
                 that is one that does not stop",
                station.segments
            ));
        }
        if segment.carries(TCP_RST, 0) {
            return Err(format!(
                "the appliance reset the onboarding connection at the {:?} step (sequence {}, \
                 acknowledgement {})",
                station.step, segment.sequence, segment.acknowledgement
            ));
        }
        // Ahead of the step, because it holds at every one of them: the domain
        // that terminates a session answers with nothing today, and both domains
        // report that as a fact rather than as a placeholder. A byte here would
        // be one this port invented, and it would make both accounts' `sent`
        // unreadable.
        if !segment.payload.is_empty() {
            return Err(format!(
                "the appliance sent {} byte(s) back on the onboarding connection at the {:?} \
                 step. The domain that terminates a session answers with nothing, so a byte here \
                 is one this port put on the wire without being answered anything",
                segment.payload.len(),
                station.step
            ));
        }
        match station.step {
            OnboardStep::Unopened => Err(format!(
                "a segment came back on the onboarding port before this station opened a \
                 connection: flags {:#04x}, sequence {}",
                segment.flags, segment.sequence
            )),
            OnboardStep::AwaitSynAck => {
                if !segment.carries(TCP_SYN | TCP_ACK, TCP_FIN) {
                    return Err(format!(
                        "the appliance answered the onboarding SYN with flags {:#04x}, and a \
                         passive open owes SYN and ACK together and no FIN",
                        segment.flags
                    ));
                }
                // The `SYN` occupies one sequence number, so this is the whole of
                // what the appliance may acknowledge.
                let owed = ONBOARD_STATION_ISN.wrapping_add(1);
                if segment.acknowledgement != owed {
                    return Err(format!(
                        "the onboarding SYN-ACK acknowledges {} and the station's SYN occupied \
                         {owed}",
                        segment.acknowledgement
                    ));
                }
                station.peer_isn = Some(segment.sequence);
                station.expect = segment.sequence.wrapping_add(1);
                station.sequence = owed;
                // The handshake's third segment and the payload in one, which is
                // what a client with something to say does. One segment for the
                // whole payload deliberately: what both domains report received
                // is held to this length, and a payload split across two
                // segments would be a length decided by this harness's own
                // pacing.
                station.owed.push_back(onboard_segment(
                    &self.port,
                    ONBOARD_STATION_PORT,
                    Numbers {
                        sequence: station.sequence,
                        acknowledgement: station.expect,
                    },
                    TCP_ACK | TCP_PSH,
                    ONBOARD_PAYLOAD,
                ));
                station.delivered = ONBOARD_PAYLOAD.len() as u64;
                station.sequence = station.sequence.wrapping_add(ONBOARD_PAYLOAD.len() as u32);
                Ok(OnboardStep::AwaitAck)
            }
            OnboardStep::AwaitAck => {
                if !segment.carries(TCP_ACK, TCP_SYN) {
                    return Err(format!(
                        "the appliance answered the onboarding payload with flags {:#04x}, and an \
                         established connection owes an ACK with no SYN",
                        segment.flags
                    ));
                }
                if segment.acknowledgement != station.sequence {
                    // Not yet the acknowledgement this station is waiting for.
                    // Nothing is owed back and the step does not move: the
                    // appliance may acknowledge the handshake before it has
                    // taken the payload, and treating that as the payload's
                    // acknowledgement would end the session a segment early.
                    return Ok(OnboardStep::AwaitAck);
                }
                // The payload is acknowledged, so the appliance has taken it and
                // this session has carried what it was opened to carry. What
                // ends it is the whole of what separates the three stations.
                if station.behaviour.crowds() && !station.crowded {
                    // Before the close and after the acknowledgement, so the
                    // connection this one crowds is certainly established at the
                    // appliance: it has answered on it.
                    station.crowded = true;
                    station.owed.push_back(onboard_segment(
                        &self.port,
                        ONBOARD_CROWD_PORT,
                        Numbers {
                            sequence: ONBOARD_CROWD_ISN,
                            acknowledgement: 0,
                        },
                        TCP_SYN,
                        &[],
                    ));
                }
                if station.behaviour.resets() {
                    // A reset rather than a close, and it carries no
                    // acknowledgement: this end is abandoning a connection
                    // rather than agreeing anything about it.
                    station.owed.push_back(onboard_segment(
                        &self.port,
                        ONBOARD_STATION_PORT,
                        Numbers {
                            sequence: station.sequence,
                            acknowledgement: 0,
                        },
                        TCP_RST,
                        &[],
                    ));
                    return Ok(OnboardStep::Reset);
                }
                station.owed.push_back(onboard_segment(
                    &self.port,
                    ONBOARD_STATION_PORT,
                    Numbers {
                        sequence: station.sequence,
                        acknowledgement: station.expect,
                    },
                    TCP_FIN | TCP_ACK,
                    &[],
                ));
                station.sequence = station.sequence.wrapping_add(1);
                Ok(OnboardStep::AwaitFin)
            }
            OnboardStep::AwaitFin => {
                if !segment.carries(TCP_ACK, TCP_SYN) {
                    return Err(format!(
                        "the appliance answered the onboarding FIN with flags {:#04x}, and a peer \
                         acknowledging a close owes an ACK with no SYN",
                        segment.flags
                    ));
                }
                if !segment.carries(TCP_FIN, 0) {
                    // The bare acknowledgement of this end's own `FIN`, which
                    // arrives before the close the session's other end owes.
                    return Ok(OnboardStep::AwaitFin);
                }
                // The `FIN` occupies one sequence number past the data, of which
                // there is none.
                station.expect = segment.sequence.wrapping_add(1);
                station.owed.push_back(onboard_segment(
                    &self.port,
                    ONBOARD_STATION_PORT,
                    Numbers {
                        sequence: station.sequence,
                        acknowledgement: station.expect,
                    },
                    TCP_ACK,
                    &[],
                ));
                Ok(OnboardStep::Closed)
            }
            // A reset is not a barrier on the wire. This end abandoned the
            // connection without agreeing anything about it, so whatever the
            // appliance had already put on the wire is still travelling — and a
            // segment that crossed the reset is the transport working, not the
            // port answering a connection it was told to forget. It is the close
            // the peer had decided on for itself, or a repeat of what it already
            // sent, and both are what a real peer produces.
            //
            // What is refused is a segment the appliance could not have composed
            // before it saw the reset. Two things say that, and nothing else can:
            //
            // A `SYN` — the passive open being offered again. The appliance sends
            // that flag only in a `SYN-ACK`, so one arriving here is a transport
            // still trying to establish a connection it has been told to drop.
            //
            // Sequence space the appliance had not yet reached. Everything it had
            // composed lies between its own initial sequence number and the next
            // number this station expects; it never sends a payload byte, so that
            // span is one flag wide and a segment past it is new transmission
            // rather than an old one still in flight. Compared as offsets from
            // that one origin, so the arithmetic is a wrap of the sequence space
            // rather than a comparison that breaks across it.
            //
            // The tolerance is bounded by the same thing every other step's is:
            // [`ONBOARD_SEGMENT_LIMIT`] counts every segment on this connection
            // before the step is even looked at, so a port that answers without
            // end still fails — on the count, which is what such a port is.
            OnboardStep::Reset => {
                if segment.carries(TCP_SYN, 0) {
                    return Err(format!(
                        "the appliance offered the onboarding connection again after this station \
                         reset it: flags {:#04x}, sequence {}. A SYN reaches this port only in a \
                         SYN-ACK, so one here is a transport still establishing a connection it \
                         was told to forget rather than a segment that was already travelling",
                        segment.flags, segment.sequence
                    ));
                }
                let Some(peer_isn) = station.peer_isn else {
                    return Err(format!(
                        "a segment came back after this station reset the onboarding connection \
                         and the appliance never claimed an initial sequence number for it: flags \
                         {:#04x}, sequence {}",
                        segment.flags, segment.sequence
                    ));
                };
                let composed = segment.sequence.wrapping_sub(peer_isn);
                let reached = station.expect.wrapping_sub(peer_isn);
                if composed > reached {
                    return Err(format!(
                        "the appliance sent sequence {} after this station reset the onboarding \
                         connection, and it had composed no further than {}: flags {:#04x}. A \
                         segment already travelling carries a number the appliance had reached, \
                         so one past it is a connection this port is still writing to",
                        segment.sequence, station.expect, segment.flags
                    ));
                }
                // Nothing is owed back and the step does not move: this end
                // abandoned the connection, so it acknowledges nothing on it.
                Ok(OnboardStep::Reset)
            }
            OnboardStep::Closed => Err(format!(
                "a segment came back after the onboarding connection closed: flags {:#04x}, \
                 sequence {}",
                segment.flags, segment.sequence
            )),
        }
    }

    /// The ARP request the appliance asks its next hop with, and the reply the
    /// station owes it.
    ///
    /// Every field is compared: a request that named a different target, or
    /// claimed a sender the frame that carried it did not, is refused rather
    /// than answered — the station answers for its own address and for nothing
    /// else.
    ///
    /// # Errors
    /// The verdict, naming the field and the two values.
    fn judge_dial_arp(&self, frame: &[u8], station: &mut DialStation) -> Result<DialStep, String> {
        let request = decode_arp(frame)?;
        let expected = ArpFrame {
            destination_mac: [0xff; 6],
            source_mac: self.port.mac,
            operation: ARP_REQUEST,
            sender_mac: self.port.mac,
            sender_address: self.port.address,
            target_mac: [0; 6],
            target_address: self.port.station,
        };
        if request != expected {
            return Err(format!(
                "the ARP request the appliance dialled through departs from the contract in {}",
                arp_differences(&expected, &request).join("; ")
            ));
        }
        station.resolutions = station.resolutions.saturating_add(1);
        if station.resolutions > station.misbehaviour.resolution_limit() {
            return Err(format!(
                "the appliance has asked about {} {} times and this station answers {}. An entry \
                 is learned once and kept for its lifetime, so asking past that is a cache that \
                 is not keeping what it learns — or, where the answers name another sender, one \
                 that is not giving up on an address nothing claims",
                ipv4(self.port.station),
                station.resolutions,
                station.misbehaviour.resolution_limit()
            ));
        }
        if station.misbehaviour == DialMisbehaviour::AnswersForAnotherAddress {
            // A well-formed reply from a station nobody asked about. Nothing is
            // resolved by it, so the step does not move: the appliance is owed
            // an answer for the next hop and has not had one.
            station.owed.push_back(impostor_arp_reply(&self.port));
            return Ok(DialStep::Unasked);
        }
        station.owed.push_back(station_arp_reply(&self.port));
        Ok(DialStep::Resolved)
    }

    /// One segment of the connection the appliance dialled, judged against the
    /// step it belongs to, with the station's answer composed for it.
    ///
    /// Every assertion is a field comparison, on [`judge_tcp`](Self::judge_tcp)'s
    /// terms: the flags that must be set and the flags that must not, the
    /// acknowledgement against what this station actually sent, and the probe
    /// against the bytes the appliance is contracted to carry.
    ///
    /// # Errors
    /// The verdict, naming the field and the two values.
    fn judge_dial_tcp(&self, frame: &[u8], station: &mut DialStation) -> Result<DialStep, String> {
        let segment = decode_tcp_to(frame, &self.port, DIAL_DESTINATION)?;
        // Ahead of everything a segment can be, so the reset below is held to it
        // as well: one connection is one port, and a segment from another is one
        // this station never answered. A `SYN` is the exception it has always
        // been — a fresh open arrives from a port of its own choosing.
        if let Some(port) = station.peer_port
            && segment.source_port != port
            && !segment.carries(TCP_SYN, TCP_ACK)
        {
            return Err(format!(
                "a segment of the dial came from port {} and the appliance opened it from {port}. \
                 One connection is one port, so a segment from another is one this station never \
                 answered",
                segment.source_port
            ));
        }
        if segment.carries(TCP_RST, 0) {
            if !station.misbehaviour.expects_a_reset() {
                return Err(format!(
                    "the appliance reset the connection it dialled at the {:?} step (sequence {}, \
                     acknowledgement {})",
                    station.step, segment.sequence, segment.acknowledgement
                ));
            }
            // The reset RFC 793 owes an acknowledgement of what was never sent:
            // it carries the number that was claimed as its own sequence and
            // acknowledges nothing, because there is nothing this end has agreed
            // to acknowledge. Both fields are compared rather than the flag
            // alone — a reset naming some other number would be this end
            // answering about a connection nobody described.
            if segment.sequence != UNSENT_ACKNOWLEDGEMENT {
                return Err(format!(
                    "the appliance reset a handshake acknowledging {UNSENT_ACKNOWLEDGEMENT} with \
                     sequence {}, and the reset owed to an unacceptable acknowledgement carries \
                     the number that was claimed",
                    segment.sequence
                ));
            }
            if segment.flags & TCP_ACK != 0 {
                return Err(format!(
                    "the appliance's reset carries flags {:#04x}: a connection with nothing agreed \
                     acknowledges nothing, so the ACK bit here would be this end conceding a \
                     sequence space it never entered",
                    segment.flags
                ));
            }
            station.resets = station.resets.saturating_add(1);
            if station.resets > station.misbehaviour.dial_limit() {
                return Err(format!(
                    "the appliance has reset {} handshakes and it may open {} of them",
                    station.resets,
                    station.misbehaviour.dial_limit()
                ));
            }
            // And the dial is left standing, which is the whole of what this
            // mode states. Nothing is owed back: the appliance's own
            // retransmission is what carries the connection on from here.
            return Ok(station.step);
        }
        // A `SYN` is an open wherever it arrives, and it is judged before the
        // step is: the appliance re-sends one whose answer never reached it, and
        // opens another under its own schedule where a whole session went
        // away. Both are the same thing on this wire — a connection this station
        // has not carried yet — so both are answered by starting one. What is
        // refused is a `SYN` before the resolution, and a node opening them
        // without end.
        if segment.carries(TCP_SYN, TCP_ACK) {
            if station.step == DialStep::Unasked {
                return Err(format!(
                    "the appliance dialled before asking who holds {}: flags {:#04x}, sequence \
                     {}. The next hop is resolved from an answer to its own request, so a segment \
                     here is one addressed from an entry nothing on this link supplied",
                    ipv4(self.port.station),
                    segment.flags,
                    segment.sequence
                ));
            }
            if !segment.payload.is_empty() {
                return Err(format!(
                    "the appliance's SYN carried {} payload bytes, and a dial carries its request \
                     after the handshake rather than on it",
                    segment.payload.len()
                ));
            }
            station.dials = station.dials.saturating_add(1);
            if station.dials > station.misbehaviour.dial_limit() {
                return Err(format!(
                    "{} SYNs have reached this station and it answers {}. The appliance's own \
                     schedule keeps two attempts a wakeup apart and its transport bounds the \
                     re-sends of one SYN, so dialling past that is one of those two bounds not \
                     holding",
                    station.dials,
                    station.misbehaviour.dial_limit()
                ));
            }
            station.peer_port = Some(segment.source_port);
            station.peer_isn = Some(segment.sequence);
            // The `SYN` occupies one sequence number. Every open is answered
            // from the same initial number, so an answer re-sent is the same
            // bytes rather than a second station.
            station.expect = segment.sequence.wrapping_add(1);
            station.sequence = STATION_ISN;
            station.probe.clear();
            let answer = |flags: u8, acknowledgement: u32| {
                station_segment(
                    &self.port,
                    DIAL_DESTINATION,
                    Ports {
                        source: DIAL_PORT,
                        destination: segment.source_port,
                    },
                    Numbers {
                        sequence: STATION_ISN,
                        acknowledgement,
                    },
                    flags,
                    STATION_WINDOW,
                    &[],
                )
            };
            match station.misbehaviour {
                DialMisbehaviour::Answers => {
                    station
                        .owed
                        .push_back(answer(TCP_SYN | TCP_ACK, station.expect));
                    station.sequence = station.sequence.wrapping_add(1);
                    return Ok(DialStep::Handshaken);
                }
                // Nothing at all, which is the mode. The connection stays on the
                // appliance's books and its own retransmission carries it to the
                // bound that ends it.
                DialMisbehaviour::SilentToTheDial => return Ok(station.step),
                // What a station with nothing bound to that port answers: a
                // reset acknowledging the `SYN` it really did receive, which is
                // the one shape a peer must believe.
                DialMisbehaviour::ResetsTheDial => {
                    station
                        .owed
                        .push_back(answer(TCP_RST | TCP_ACK, station.expect));
                    return Ok(station.step);
                }
                // A handshake acknowledging a number this connection never
                // occupied. The appliance owes a reset carrying that number and
                // owes the dial nothing: what it must NOT do is treat this as
                // the answer to its own `SYN`.
                DialMisbehaviour::AcknowledgesTheWrongSequence => {
                    station
                        .owed
                        .push_back(answer(TCP_SYN | TCP_ACK, UNSENT_ACKNOWLEDGEMENT));
                    return Ok(station.step);
                }
                // Unreachable: this mode resolves nothing, so the step above is
                // `Unasked` and the check there refused the segment already. A
                // value rather than a panic, a rendering being no place to fail
                // a run on.
                DialMisbehaviour::AnswersForAnotherAddress => return Ok(station.step),
            }
        }
        match station.step {
            DialStep::Unasked => Err(format!(
                "the appliance sent a segment before asking who holds {}: flags {:#04x}, sequence \
                 {}",
                ipv4(self.port.station),
                segment.flags,
                segment.sequence
            )),
            DialStep::Resolved => Err(format!(
                "the appliance opened its connection with flags {:#04x}, and an active open owes \
                 a SYN alone",
                segment.flags
            )),
            // **The end of what this station can observe, and it is no longer
            // the handshake.** The appliance now speaks first over the channel:
            // the domain that holds the device key composes a TLS client hello
            // the moment the connection comes up, and it arrives here as
            // ordinary stream bytes.
            //
            // This station **takes them and answers nothing**, which is the
            // deliberate half. It is not a TLS server and pretending to be one
            // would be this harness re-implementing the peer the boots that
            // point a real server at the appliance already drive; what it states
            // instead is that the transport under the channel behaves — in
            // order, acknowledged, and the connection held open — while the
            // session above it waits for a server that never speaks. A
            // management server listening and not answering is a real thing for
            // an appliance to meet, and this is what it looks like from the
            // wire.
            DialStep::Handshaken => {
                if !segment.carries(TCP_ACK, TCP_SYN) {
                    return Err(format!(
                        "the appliance answered with flags {:#04x}, and an established connection \
                         owes an ACK with no SYN",
                        segment.flags
                    ));
                }
                if segment.acknowledgement != station.sequence {
                    return Err(format!(
                        "a segment of the dial acknowledges {} and the station had sent up to {}",
                        segment.acknowledgement, station.sequence
                    ));
                }
                // Ahead of everything a segment's numbers say, because it holds
                // whatever they are: this channel is a connection the appliance
                // holds, so a close is the defect whether it arrives in order or
                // behind one.
                if segment.carries(TCP_FIN, 0) {
                    return Err(String::from(
                        "the appliance closed the channel it dialled, and a management channel is \
                         a connection it holds: a close here is a node that will re-dial a server \
                         that did nothing wrong",
                    ));
                }
                // A segment repeating space this station has already taken is the
                // appliance re-sending one it has not seen acknowledged, and this
                // station is exactly the peer that provokes that: it answers on
                // the run loop's schedule, one queued frame a pass. Acknowledged
                // again and nothing else — the bytes are not new bytes offered,
                // the stream does not move, and a station that answered nothing
                // would let the appliance spend its retransmission budget and
                // abandon a connection this boot judges as held open.
                //
                // Compared as offsets from the appliance's own initial number so
                // the arithmetic wraps with the sequence space, and bounded on a
                // count: a peer that only ever repeats itself is not carrying a
                // channel, and a station that simply went on acknowledging could
                // not tell that from a slow machine.
                if let Some(peer_isn) = station.peer_isn {
                    let occupied = segment.payload.len() as u32;
                    let start = segment.sequence.wrapping_sub(peer_isn);
                    let taken = station.expect.wrapping_sub(peer_isn);
                    if occupied > 0 && start.saturating_add(occupied) <= taken {
                        station.repeats = station.repeats.saturating_add(1);
                        if station.repeats > DIAL_REPEAT_LIMIT {
                            return Err(format!(
                                "the appliance has re-sent {} segments this station had already \
                                 taken and acknowledged, over the {} session(s) a boot may open. A \
                                 peer that only repeats itself is one that never gets its flight \
                                 across",
                                station.repeats, DIAL_RESTART_LIMIT
                            ));
                        }
                        station.owed.push_back(station_segment(
                            &self.port,
                            DIAL_DESTINATION,
                            Ports {
                                source: DIAL_PORT,
                                destination: segment.source_port,
                            },
                            Numbers {
                                sequence: station.sequence,
                                acknowledgement: station.expect,
                            },
                            TCP_ACK,
                            STATION_WINDOW,
                            &[],
                        ));
                        return Ok(DialStep::Handshaken);
                    }
                }
                // In order and with no gap, on the client's own terms: what runs
                // over this connection is a stream, so a segment out of place is
                // refused rather than reassembled.
                if segment.sequence != station.expect {
                    return Err(format!(
                        "a segment of the dial begins at sequence {} and the station expected {}; \
                         it had taken up to there and this is neither the next of the stream nor a \
                         re-send of what it holds",
                        segment.sequence, station.expect
                    ));
                }
                if !segment.payload.is_empty() {
                    // Bounded by what the appliance's own outbound window holds,
                    // which is the one number that says this is a session's
                    // first flight and not a node emitting without end. A
                    // station that accumulated whatever arrived would still be
                    // accumulating on a boot whose channel had gone wrong.
                    station.offered = station.offered.saturating_add(segment.payload.len());
                    if station.offered > DIAL_OFFER_LIMIT {
                        return Err(format!(
                            "the appliance has put {} bytes on the channel it dialled against an \
                             outbound window of {}, and this station has acknowledged every one \
                             of them and answered nothing. A session whose peer never speaks owes \
                             one flight, so more than a window's worth is a node composing \
                             without end",
                            station.offered, DIAL_OFFER_LIMIT
                        ));
                    }
                    station.expect = station.expect.wrapping_add(segment.payload.len() as u32);
                    // Acknowledged and nothing else. The window is re-advertised
                    // whole, so nothing the appliance does next turns on this
                    // station closing one.
                    station.owed.push_back(station_segment(
                        &self.port,
                        DIAL_DESTINATION,
                        Ports {
                            source: DIAL_PORT,
                            destination: segment.source_port,
                        },
                        Numbers {
                            sequence: station.sequence,
                            acknowledgement: station.expect,
                        },
                        TCP_ACK,
                        STATION_WINDOW,
                        &[],
                    ));
                }
                Ok(DialStep::Handshaken)
            }
        }
    }

    /// The dial as evidence, in the voice of the routed-traffic lines.
    fn dialled(&self, station: &DialStation) -> String {
        format!(
            "  answered   tcp-dial              mgmt->station  {}:{} -> {}:{DIAL_PORT}  isn {}  \
             handshake complete, connection held open",
            ipv4(self.port.address),
            station
                .peer_port
                .map_or_else(|| String::from("(none)"), |port| port.to_string()),
            ipv4(self.port.station),
            station
                .peer_isn
                .map_or_else(|| String::from("(none)"), |isn| isn.to_string()),
        )
    }

    /// A misbehaving station's account of the channel, in the voice of the
    /// routed-traffic lines.
    ///
    /// The counterpart of [`dialled`](Self::dialled) for a channel that did not
    /// come up: what this end refused to do, and what the appliance did about it.
    /// Every number in it was counted while the frames were judged, so it is a
    /// rendering of what was proved rather than a second reading of the wire.
    fn misdialled(&self, station: &DialStation) -> String {
        format!(
            "  refused    tcp-dial              mgmt->station  {}:{} -> {}:{DIAL_PORT}  \
             station {:?}  {} resolution(s) answered, {} SYN(s) seen, {} reset(s) from the \
             appliance, and no frame injected to carry it",
            ipv4(self.port.address),
            station
                .peer_port
                .map_or_else(|| String::from("(none)"), |port| port.to_string()),
            ipv4(self.port.station),
            station.misbehaviour,
            station.resolutions,
            station.dials,
            station.resets
        )
    }

    /// The station's answer to the appliance's resolution, in the voice of the
    /// routed-traffic lines.
    fn resolved(&self) -> String {
        format!(
            "  answered   arp-request           mgmt->station  who-has {} tell {}  is-at {}",
            ipv4(self.port.station),
            ipv4(self.port.address),
            mac(MANAGEMENT_STATION_MAC)
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

/// Judge a segment that repeats sequence space this client has already taken,
/// and leave the client exactly where it was.
///
/// The step does not move and nothing is composed here: a repeat carries no
/// information this client does not already hold, and a model that moved for one
/// would be counting the same bytes twice. What it must still be is *the same
/// segment again*, and four things say it is not:
///
/// An acknowledgement outside what this client has sent. It is the one field a
/// re-send composes afresh rather than repeats, so it is held to the same span
/// every step here holds it to: an appliance claiming bytes nobody sent is a
/// defect whatever else the segment is.
///
/// A `SYN` anywhere but on the appliance's own initial number, which is the one
/// place the connection's only `SYN` ever sat. One inside the stream is a
/// transport re-offering a connection it is already carrying.
///
/// A `SYN` at all once this connection has gone past the handshake. The
/// appliance sets that flag in one segment — the passive open — and re-sends it
/// only while this client's acknowledgement has not reached it. The moment a
/// byte of the response or the `FIN` arrives, that acknowledgement demonstrably
/// did reach it, so a `SYN` after that is the appliance answering an established
/// connection with an offer to establish it. That is the defect this whole check
/// exists to catch, and it is caught here rather than made tolerable.
///
/// Payload bytes that differ from the ones already taken at the same numbers. A
/// stream is what is under test, and a peer that answers one sequence number
/// with two different bytes has not sent the same segment again — it has sent a
/// second stream.
///
/// # Errors
/// The verdict, naming the field and the two values, or the count where the
/// appliance has done nothing but repeat itself.
fn judge_repeat(
    segment: &TcpFrame,
    client: &mut TcpClient,
    peer_isn: u32,
    start: u32,
) -> Result<TcpStep, String> {
    client.repeats = client.repeats.saturating_add(1);
    if client.repeats > CLIENT_REPEAT_LIMIT {
        return Err(format!(
            "the appliance has re-sent {} segments this client had already taken, and an exchange \
             of this shape has a handful of ranges in it. A peer that only repeats itself is one \
             that never finishes",
            client.repeats
        ));
    }
    // The one field of a re-send that is not a repeat of anything: the
    // acknowledgement is composed afresh from what the appliance has taken by
    // now. This client sends its `SYN`, its request and its `FIN` and nothing
    // else, so that is the whole of what may be acknowledged — as offsets from
    // this client's own initial number, the arithmetic wrapping with the
    // sequence space rather than breaking across it.
    let acknowledged = segment.acknowledgement.wrapping_sub(CLIENT_ISN);
    let sent = TcpClient::sent_through_request()
        .wrapping_add(1)
        .wrapping_sub(CLIENT_ISN);
    if acknowledged == 0 || acknowledged > sent {
        return Err(format!(
            "the appliance re-sent sequence {} acknowledging {}, and this client has sent its SYN, \
             its request and its FIN — {} numbers from {CLIENT_ISN}. An acknowledgement outside \
             that is one for bytes nobody sent",
            segment.sequence, segment.acknowledgement, sent
        ));
    }
    if segment.carries(TCP_SYN, 0) {
        if start != 0 {
            return Err(format!(
                "the appliance set SYN on sequence {} and its own initial sequence number was \
                 {peer_isn}: flags {:#04x}. The connection's only SYN sat on that number, so one \
                 inside the stream is a transport re-offering a connection it is already carrying",
                segment.sequence, segment.flags
            ));
        }
        // One past the `SYN` is the whole of what this client has taken while
        // the handshake is still outstanding, so anything more is the response.
        if client.expect != peer_isn.wrapping_add(1) {
            return Err(format!(
                "the appliance answered with flags {:#04x} after it had already answered up to \
                 sequence {}. Re-sending the passive open is what a peer does while this end's \
                 acknowledgement has not reached it, and a response byte proves that it did",
                segment.flags, client.expect
            ));
        }
        if !segment.carries(TCP_SYN | TCP_ACK, TCP_FIN) {
            return Err(format!(
                "the appliance re-sent its passive open with flags {:#04x}, and a passive open \
                 owes SYN and ACK together and no FIN",
                segment.flags
            ));
        }
        // The client's `SYN` is the whole of what an appliance still offering
        // the handshake can have taken: the segment that acknowledges the offer
        // carries the request with it, so one that took the request would have
        // taken the acknowledgement too and would owe no passive open at all.
        let owed = CLIENT_ISN.wrapping_add(1);
        if segment.acknowledgement != owed {
            return Err(format!(
                "the re-sent SYN-ACK acknowledges {} and an appliance still offering the handshake \
                 has taken the client's SYN alone, which occupied {owed}",
                segment.acknowledgement
            ));
        }
        if !segment.payload.is_empty() {
            return Err(format!(
                "the appliance's re-sent SYN carried {} payload bytes, and it answers the request \
                 after the handshake rather than on it",
                segment.payload.len()
            ));
        }
        return Ok(client.step);
    }
    if !segment.carries(TCP_ACK, 0) {
        return Err(format!(
            "the appliance re-sent sequence {} with flags {:#04x}, and every segment of an \
             established connection carries an ACK",
            segment.sequence, segment.flags
        ));
    }
    if !segment.payload.is_empty() {
        if start == 0 {
            return Err(format!(
                "the appliance re-sent {} bytes on sequence {peer_isn}, which is the number its \
                 own SYN occupied alone. The response begins one past it, so bytes there are a \
                 stream this connection never carried",
                segment.payload.len()
            ));
        }
        // The response begins one past the `SYN`, so this is where in it the
        // re-sent bytes belong.
        let at = start.wrapping_sub(1) as usize;
        let already = client
            .response
            .get(at..at.saturating_add(segment.payload.len()))
            .ok_or_else(|| {
                format!(
                    "the appliance re-sent {} bytes at sequence {} and this client holds {} \
                     response bytes: the range ends past every byte it has taken, and the only \
                     sequence space there is the number the appliance's own FIN occupied. Data on \
                     it is not the segment it sent there before",
                    segment.payload.len(),
                    segment.sequence,
                    client.response.len()
                )
            })?;
        if already != segment.payload {
            return Err(format!(
                "the appliance re-sent {} bytes at sequence {} and they are not the bytes it sent \
                 there before. A stream answers one sequence number with one byte, so a second \
                 answer is a second stream",
                segment.payload.len(),
                segment.sequence
            ));
        }
    }
    Ok(client.step)
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
/// a dataplane port is the required management/dataplane isolation having
/// stopped being true — in the direction no console record would ever show.
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
    /// The station's end of the one connection the appliance dials out. The
    /// other direction of this wire, and the half no other scenario watches.
    station: DialStation,
    /// This harness's end of the connection it opens to the appliance's *second*
    /// listening port. A third conversation on one wire, told apart from the
    /// other two by the ports it runs between.
    onboard: OnboardStation,
    /// Every frame this harness has put on the wire, accumulated as it goes.
    ///
    /// Accumulated rather than precomputed because the TCP exchange's frames are
    /// decided by the appliance's own answers: the console's count is an equality
    /// (`crate::management_contract`), so it must be stated against what was
    /// actually sent and not against a tally written in advance.
    injected: ManagementInjection,
}

impl ManagementWire {
    /// Whether the port has answered everything it owes: both stateless replies,
    /// a whole TCP exchange, and whatever the boot's dial contract obliges.
    ///
    /// `dial_decided` is the caller's reading of the console, and it is what a
    /// misbehaving station waits on. Such a station never sees a channel close —
    /// that is the point of it — so what says the appliance has finished is the
    /// appliance's own record of the outcome, which is an observable rather than
    /// a duration.
    /// `onboard_reported` is the caller's reading of the console on the other
    /// half of the same question: this station's own connection can be finished
    /// while the appliance has not yet closed the session's account, the pass
    /// that writes those records running after the connection is gone. So what
    /// says the port has finished is the port's own records, which are an
    /// observable rather than a duration.
    fn answered(
        &self,
        dial: crate::qemu::DialContract,
        dial_decided: bool,
        onboard_reported: bool,
    ) -> bool {
        let dialled = match dial {
            crate::qemu::DialContract::Answered => true,
            crate::qemu::DialContract::Judged => self.station.completed(),
            crate::qemu::DialContract::Misbehaves(_) => dial_decided,
        };
        let onboarded =
            !self.onboard.behaviour.opens() || (self.onboard.completed() && onboard_reported);
        self.arp_reply
            && self.echo_reply
            && self.client.step == TcpStep::Closed
            && dialled
            && onboarded
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
        if !self.station.completed() && self.station.misbehaviour.completes() {
            owed.push(self.station.step.outstanding());
        }
        if !self.onboard.completed() {
            owed.push(self.onboard.step.outstanding());
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
            ManagementReply::Tcp(_) | ManagementReply::Dial(_) | ManagementReply::Onboard(_) => {
                return Ok(());
            }
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
        // Both preconditions, each with the value it actually held, and never one
        // of them stated as the cause. The burst waits on two independent facts —
        // every routed probe having crossed, and the capture showing every port
        // up — and a clause that named the second while the first was the one
        // outstanding sent a reader to the console to look for a record that was
        // already there. What the port itself made of the wire goes beside them,
        // because a run that put nothing on that wire and a run whose peer said
        // nothing back are different failures: this is the second's only
        // evidence.
        return format!(
            "the management frames were never injected, so the burst's two preconditions are what \
             to read: every routed probe across (the probes above say which had not) and every \
             port up (ports_are_ready is {}). What did cross that wire meanwhile: {}; {}; {}",
            management_contract::ports_are_ready(output),
            wire.client.seen(),
            wire.station.seen(),
            wire.onboard.seen()
        );
    }
    format!(
        "{} management frames of {} bytes were injected, and the port still owes {}; {}; {}; {}",
        injected.frames,
        injected.bytes,
        wire.outstanding(),
        wire.client.seen(),
        wire.station.seen(),
        wire.onboard.seen()
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
    /// What [`BootTest::hardware_accelerated`] said, carried to the judges.
    pub hardware_accelerated: bool,
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
    /// What a station that acknowledges the wrong sequence number claimed, and
    /// what the appliance had really sent — the harness's own reading of both,
    /// from the last handshake it saw.
    ///
    /// Returned so the appliance's console can be held to it: the two numbers on
    /// that record are the whole diagnosis of this fault, and a console agreeing
    /// with itself about them would prove nothing. `None` on every boot whose
    /// station claims nothing.
    pub dial_claim: Option<(u32, u32)>,
    /// One line per reply the management port owed and gave, in the order they
    /// were accepted. Empty exactly when the run had no routed contract to meet:
    /// a routed run that reached its verdict answered both, the wait for them
    /// being what ends it.
    pub management_replies: Vec<String>,
    /// When this run's QEMU process was started, on the host's clock.
    ///
    /// It is an **upper bound on the appliance's uptime** and it is here for the
    /// one question that needs one: whether the appliance's periodic wakeup is
    /// arriving faster than it was armed for, which is what an interrupt input
    /// shared with another device looks like. A bound rather than a
    /// measurement, and deliberately the loose direction — firmware, the boot
    /// manager and the kernel all run before the domain arms anything, so the
    /// real uptime is shorter and a count under this bound proves nothing on
    /// its own. What it catches is a count that could not have been produced by
    /// this timer in the time the machine has existed.
    pub started_at: Instant,
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
    /// What the injected probes oblige the appliance's filter to have counted,
    /// which is the independent half of the per-rule cross-check the scrape
    /// scenarios make.
    pub policy: PolicyWitness,
    /// What `curl` got out of `/logs.pcapng` and `/capture.pcapng`, in that
    /// order, on every boot whose management port a real client can reach.
    /// Empty on every socket-backed boot.
    pub recordings: Vec<Download>,
    /// What each of those two extents already held **going into** this boot, in
    /// the same order. Empty on every boot that made its own medium.
    ///
    /// Filled by the caller rather than here, because it is a fact about the
    /// image that was attached and not about anything the guest did: this
    /// function never opens the medium, and the reading has to be taken before
    /// QEMU is spawned to mean anything at all. What it is for is
    /// [`crate::surface_contract::Surface::carried`] — a download taken on a
    /// resumed recording answers earlier boots' records, and this is what tells
    /// them from the ones this boot's counters are an account of.
    pub carried_recordings: Vec<recording_contract::Parsed>,
    /// Every frame this boot put on a dataplane port, with the probe that put
    /// it there and whether the appliance's tap must have observed it.
    ///
    /// What the configuration submission proved, on the two scenarios that make
    /// one. `None` everywhere else, and a scenario that should have made one and
    /// did not has already failed above.
    pub applied: Option<crate::config_submission_contract::Applied>,
    /// What the re-decision that commit armed did to the conversations already
    /// running, on the one scenario that states it. `None` everywhere else.
    pub revoked: Option<crate::config_submission_contract::Revoked>,
    /// What every real client this boot ran against the onboarding port made of
    /// it, in the order it ran them. Empty on every boot whose subject is
    /// something else.
    pub handshakes: Vec<onboard_tls_contract::Attempt>,
    /// The requests real clients made on the surface above those handshakes,
    /// where the boot ran any.
    pub requests: Vec<onboard_request_contract::Attempt>,
    /// What this run's **management server** did to the appliance, on the two
    /// boots that play one: the package it issued and uploaded, or the closed
    /// surface it met on an appliance somebody already owns. `None` everywhere
    /// else.
    pub installs: Option<onboard_install_contract::Onboarded>,
    /// What the station this harness played on the onboarding port observed, on
    /// the three scenarios that open a session there. `None` everywhere else.
    ///
    /// Returned so the appliance's console can be held to it: the bytes this end
    /// put on the wire are what both domains' account of the session is compared
    /// against, and a console agreeing with itself about them would prove
    /// nothing.
    pub onboard: Option<OnboardAccount>,
    /// Returned so [`crate::surface_contract`] can hold the recordings to the
    /// bytes the harness itself injected rather than to a literal: the probes
    /// are derived from the configuration document, so an image built from the
    /// other document is judged against the probes *that* bench produced.
    pub injected: Vec<Injected>,
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
    // The budget follows from the station this boot plays: one that leaves the
    // appliance's `SYN` unanswered is watched through the whole of the
    // transport's retransmission backoff, three times over, and a run that
    // stopped short of it would report a channel the appliance had not finished
    // deciding as a channel that never was.
    let timeout = if test.dial.leaves_the_dial_unanswered() {
        UNANSWERED_DIAL_BOOT_TIMEOUT
    } else {
        BOOT_TEST_TIMEOUT
    };
    run_boot(command, backends, test, ACCEPT_TIMEOUT, timeout)
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
    let (probes, policy) = injected_probes(test.topology, test.traffic)?;

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
    // The **first** claim and never a later one, because the first is what the
    // appliance's own first record carries — and that record is what the dial
    // contract judges. Every attempt opens a fresh sequence space from a fresh
    // ephemeral port, so a later attempt's pair is a different pair; holding the
    // console's first record to it would be comparing two different handshakes
    // and would pass or fail on how far the run happened to get.
    let mut observed_claim: Option<(u32, u32)> = None;
    // What the harness saw come back on the two dataplane ports, and what a real
    // client got out of the management endpoint. Both live outside the run block
    // so they survive every exit path.
    let mut dataplane_frames: u64 = 0;
    let mut scrapes: Vec<Scrape> = Vec::new();
    let mut recordings: Vec<Download> = Vec::new();
    let mut handshakes: Vec<onboard_tls_contract::Attempt> = Vec::new();
    let mut requests: Vec<onboard_request_contract::Attempt> = Vec::new();
    let mut installs: Option<onboard_install_contract::Onboarded> = None;
    // What the configuration submission proved, on the one scenario that makes one.
    // Outside the run block for the reason the two above are: a boot that reached
    // the submission and then failed later still observed what it observed.
    let mut applied: Option<crate::config_submission_contract::Applied> = None;
    let mut revoked: Option<crate::config_submission_contract::Revoked> = None;
    // What the onboarding station observed, on the three scenarios that open a
    // session. Outside the run block for the same reason, and read by the
    // contract that holds the console's account of that session to this one.
    let mut onboarded: Option<OnboardAccount> = None;

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
                    station: DialStation::new(test.dial.misbehaviour()),
                    onboard: OnboardStation::new(test.onboard.behaviour()),
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
        // Whether the deferred probes have gone out yet. They are what a stateful
        // contract needs and a stateless one has none of, so on every other
        // scenario this is true from the start and the arm below never fires.
        let mut deferred_injected = !probes.iter().any(Probe::waits);
        // Which policy the probes now going out are stated against. Every scenario
        // but the reconfiguration one has a single wave and never leaves this.
        let mut wave = Wave::Shipped;
        // The refusal probes go out once, and the branch that sends them now runs
        // on several passes while the management burst is chunked out.
        let mut refusals_injected = false;
        // Whether the burst this boot owes its **channel** has gone out: one
        // further wave of the traffic the recordings are made of, sent once the
        // appliance has said it shipped everything the medium had taken. What
        // that ordering buys is the whole of what the channel contract then
        // asserts — a record shipped after it is a record that did not exist
        // when the appliance said it had caught up.
        let mut channel_burst_injected = false;
        // How many times over that wave goes out. A recording becomes visible to
        // a reader a **sector** at a time, so a burst that produced less than one
        // would leave the appliance correctly with nothing new to ship and this
        // boot waiting for a record it is not owed. One pass of the routed set is
        // a few hundred bytes of capture records; this many is several sectors,
        // whichever of them the medium happens to be part way through.
        const CHANNEL_BURST_PASSES: usize = 8;
        // How many of the management frames have gone out.
        let mut management_sent = 0usize;
        // What the harness's own TCP client owes the management port, waiting for
        // the port to have acknowledged everything ahead of it.
        let mut client_pending: VecDeque<Vec<u8>> = VecDeque::new();
        // And what the station on the far end of the appliance's dial owes it,
        // kept apart from the queue above and released ahead of it.
        //
        // The two are not the same kind of frame. Everything in `client_pending`
        // is this harness's own initiative — it opens that connection, it decides
        // when each segment goes, and nothing at the far end is counting while it
        // waits. A station frame is an ANSWER: the appliance asked, and it is
        // holding a bound of its own open for the reply. Its neighbour cache
        // spends a fixed number of requests a fixed interval apart and then
        // reports the next hop unreachable, so an answer that arrives after that
        // interval is not a late answer, it is no answer — and the appliance is
        // right to say nobody replied.
        //
        // Sharing one queue made the harness's own leisurely exchange stand in
        // front of that answer. Both go out under the same gate below and one
        // frame is still in flight at a time, so nothing about how the pipeline
        // is fed changes; what changes is which frame takes the next opening when
        // both are waiting, and only one of the two is being timed.
        let mut station_pending: VecDeque<Vec<u8>> = VecDeque::new();
        let mut last_management_inject = Instant::now();
        inject_probes(&mut endpoints, &probes, |probe| {
            probe.wave == wave && !probe.waits()
        });

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
                            match management_probe.judge(
                                &frame,
                                &probes,
                                &mut management.client,
                                &mut management.station,
                                &mut management.onboard,
                            ) {
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
                                    // The station's own answers are released
                                    // against the console's count exactly as the
                                    // client's are — the appliance drains one
                                    // pipeline, and a frame put on the wire
                                    // faster than its driver refills is a frame
                                    // lost — but into a queue of their own, so
                                    // the reply the appliance is timing takes the
                                    // next opening rather than the segment this
                                    // harness happened to compose first.
                                    if let ManagementReply::Dial(step) = reply {
                                        // The step this segment moved the station
                                        // to, if it moved it at all: a station
                                        // that misbehaves stays where it is for
                                        // frame after frame, and a line printed
                                        // per frame rather than per transition
                                        // would bury the run's evidence in
                                        // repetitions of one fact.
                                        let moved = management.station.step != step;
                                        management.station.step = step;
                                        while let Some(next) = management.station.owed.pop_front() {
                                            station_pending.push_back(next);
                                        }
                                        match step {
                                            DialStep::Resolved if moved => {
                                                answered.push(management_probe.resolved());
                                            }
                                            DialStep::Handshaken if moved => {
                                                answered.push(
                                                    management_probe.dialled(&management.station),
                                                );
                                                // The settle window restarts from
                                                // the last frame this harness
                                                // sent, on the client exchange's
                                                // terms: the console's total is an
                                                // equality, and breaking out at
                                                // the instant the connection came
                                                // up would race the record of it.
                                                //
                                                // A restart and never a start, and
                                                // this is the caller that makes
                                                // the difference: the appliance
                                                // opens this connection when it
                                                // chooses, so a handshake can
                                                // complete while the harness is
                                                // still injecting.
                                                restart_settling(&mut settling_since);
                                            }
                                            DialStep::Unasked
                                            | DialStep::Resolved
                                            | DialStep::Handshaken => {}
                                        }
                                    }
                                    // The onboarding station's answers are
                                    // queued beside the other two conversations
                                    // on this wire and released against the
                                    // console's count exactly as those are.
                                    if let ManagementReply::Onboard(step) = reply {
                                        let moved = management.onboard.step != step;
                                        management.onboard.step = step;
                                        while let Some(next) = management.onboard.owed.pop_front() {
                                            client_pending.push_back(next);
                                        }
                                        // The settle window restarts from the
                                        // last frame this harness sent, on the
                                        // client exchange's terms: the console's
                                        // total is an equality, and breaking out
                                        // at the instant the session ended would
                                        // race the records of it.
                                        if moved && step.finished() {
                                            restart_settling(&mut settling_since);
                                        }
                                    }
                                    if matches!(reply, ManagementReply::Tcp(_)) {
                                        observed_isn = management.client.peer_isn;
                                        if let Some(next) =
                                            management_probe.advance(&mut management.client)
                                        {
                                            // Queued, not injected. The appliance
                                            // can answer several segments in a row
                                            // and this client acknowledges each as
                                            // it reads it, so injecting inline puts
                                            // frames on the wire back to back —
                                            // faster than the port's driver refills
                                            // receive buffers, and a frame with none
                                            // posted is lost. The queue is drained
                                            // one frame at a time against what the
                                            // console says arrived.
                                            client_pending.push_back(next);
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
                                            restart_settling(&mut settling_since);
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
                        BootContract::FailedClosed { .. } => {
                            break 'run Err(format!(
                                "{} bytes came back on the management port of a node that \
                                 committed no generation. The port takes its addressing from the \
                                 committed configuration and is unaddressed until one commits, so \
                                 an answer here is a domain replying under addressing nothing \
                                 published; see {}",
                                frame.len(),
                                log_path.display()
                            ));
                        }
                        // Nothing was put on this wire, so whatever the port
                        // said is unsolicited and is not this boot's subject.
                        // Drained and discarded rather than judged: the frame
                        // still has to leave the host socket buffer, or QEMU's
                        // transmit path blocks on it.
                        BootContract::Cryptography | BootContract::StoreIdentity => {}
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
                        "{} bytes carrying management traffic came back on port{egress}. The design \
                         isolates the management port from the dataplane, and no domain is \
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
                        BootContract::FailedClosed { .. } => {
                            break 'run Err(format!(
                                "probe {} came back on port{egress} from a node that committed no \
                                 configuration. Generation 0 is the empty table: it has no \
                                 interface to admit a frame on, no route to send one by and no \
                                 rule to permit one, so a delivery means the dataplane is \
                                 forwarding under something the appliance refused; see {}",
                                probe.name,
                                log_path.display()
                            ));
                        }
                        // Neither required nor forbidden. The accelerated boots
                        // own the routed verdict on this image; asserting it a
                        // second time under emulation would state the same fact
                        // about the same bytes.
                        BootContract::Cryptography | BootContract::StoreIdentity => {}
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
                    // The deferred probes, once every immediate one that must be
                    // delivered has arrived. This is where a reply becomes a
                    // reply: the flow it belongs to now exists, because the
                    // request that opened it has been observed coming out the far
                    // side. Before the refusals below, so the settle window still
                    // starts after everything has been injected.
                    None if !deferred_injected
                        && all_routed_among(&probes, &deliveries, |probe| {
                            probe.wave == wave && !probe.waits()
                        }) =>
                    {
                        deferred_injected = true;
                        last_injection = Instant::now();
                        inject_probes(&mut endpoints, &probes, |probe| {
                            probe.wave == wave && probe.waits()
                        });
                    }
                    None if all_routed_among(&probes, &deliveries, |probe| probe.wave == wave)
                        && management_contract::ports_are_ready(&output) =>
                    {
                        if !refusals_injected {
                            refusals_injected = true;
                            inject_probes(&mut endpoints, &probes, |probe| {
                                probe.wave == wave && !probe.once && !probe.expectation.is_routed()
                            });
                        }
                        // Each frame goes out **once** and is never retransmitted:
                        // a retransmission is a second frame, and both halves of
                        // this contract are equalities — the console's count, and
                        // one reply per request.
                        //
                        // But they do not all go out at once, and the reason is
                        // structural rather than a tuning choice. A frame put on a
                        // wire with no receive buffer posted for it is lost, and
                        // the whole management pipeline holds [`POOL_BUFFERS`]
                        // buffers — so a burst larger than that can only be
                        // received if the guest recycles buffers faster than QEMU
                        // delivers, which is a race an *exact* count cannot be
                        // stated against. So the burst is cut into chunks the
                        // pipeline provably holds, and each waits for the console
                        // to report every frame ahead of it received.
                        let owed = management_probe.frames.len();
                        if let Some(wire) = management.as_mut()
                            && management_sent < owed
                        {
                            let acknowledged = management_contract::frames_reported(&output);
                            if acknowledged >= management_sent as u64 {
                                last_injection = Instant::now();
                                let end =
                                    management_sent.saturating_add(MANAGEMENT_BURST).min(owed);
                                for frame in management_probe
                                    .frames
                                    .get(management_sent..end)
                                    .unwrap_or_default()
                                {
                                    wire.inject(frame);
                                }
                                management_sent = end;
                                injected = wire.injected;
                                last_management_inject = Instant::now();
                            }
                        } else {
                            // Every chunk is out — or there is no management wire
                            // to put one on — so the dataplane is quiet and the
                            // settle window may start.
                            settling_since = Some(Instant::now());
                        }
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
                            client_pending.push_back(syn);
                        }
                    }
                    // Everything the port owes has arrived, and the console has
                    // caught up with what was put on the wire.
                    //
                    // The second half is what the settle window alone cannot give.
                    // The console's total is an **equality**, and the appliance
                    // reports it on the drain that moved the frame — so a run that
                    // stopped the instant the exchange closed could kill QEMU with
                    // the last record still in the log ring or the UART, and read a
                    // total one frame short of a port that received every one. So
                    // the wait is on the observable rather than on a duration, and
                    // [`MANAGEMENT_REPORT_GRACE`] bounds it: past that the run ends
                    // anyway, so a frame that was *genuinely* lost is reported as
                    // the count it is rather than as a timeout that says nothing.
                    //
                    // The grace runs from the last frame this harness PUT ON THE
                    // WIRE and not from the start of the settle window, because
                    // it is that frame's report the wait is for. Measured from
                    // the window, a boot whose channel takes minutes to decide
                    // would have spent the whole grace before its last frame was
                    // even sent, and the equality below would be waived rather
                    // than waited for — the escape hatch standing permanently
                    // open on exactly the boots that inject the most.
                    Some(since)
                        if since.elapsed() >= SETTLE_WINDOW
                            && management.as_ref().is_some_and(|wire| {
                                wire.answered(
                                    test.dial,
                                    dial_contract::reported(&output),
                                    onboard_contract::reported(&output),
                                )
                            })
                            && (management_contract::frames_reported(&output)
                                >= injected.frames as u64
                                || last_management_inject.elapsed() >= MANAGEMENT_REPORT_GRACE) =>
                    {
                        // A misbehaving station's own account of the channel,
                        // written where the run ends rather than where a step
                        // moved: its steps do not move, and what it has to say is
                        // the whole of what crossed the wire.
                        if let crate::qemu::DialContract::Misbehaves(_) = test.dial
                            && let Some(wire) = management.as_ref()
                        {
                            answered.push(management_probe.misdialled(&wire.station));
                        }
                        // And the onboarding station's, for the same reason: what
                        // it has to say is the whole session rather than any one
                        // segment of it.
                        if let Some(wire) = management.as_ref()
                            && wire.onboard.behaviour.opens()
                        {
                            let account = wire.onboard.account();
                            onboarded = Some(account);
                            answered.push(account.render(&management_probe.port));
                        }
                        break 'run Ok(());
                    }
                    // The scrape scenario: nothing more is injected anywhere, so
                    // the dataplane is quiet and the count the harness has
                    // observed is final. Take it, run a real client against the
                    // endpoint, and take it again — a number that moved across
                    // the scrape would make the cross-check meaningless rather
                    // than merely wrong, and is reported as its own failure.
                    // The configuration change, once the shipped policy's own probes
                    // have been decided and before the second wave goes out. This
                    // is the only place in the harness that *changes* what the
                    // appliance is doing, and the ordering is the whole of what
                    // makes the change evidence: the first wave's verdicts were
                    // reached under the document the image was built from, the
                    // submission is answered and waited on until the forwarding
                    // domain reports the generation, and only then is a probe
                    // whose verdict is the new policy's put on the wire.
                    Some(since)
                        if since.elapsed() >= SETTLE_WINDOW
                            && management.is_none()
                            && wave == Wave::Shipped
                            && probes.iter().any(|probe| probe.wave == Wave::Submitted) =>
                    {
                        let ManagementBacking::UserNetwork { host_port, .. } = backends.management
                        else {
                            break 'run Err(String::from(
                                "a reconfiguration scenario must be on the user-mode backing: the \
                                 document is submitted with a real client",
                            ));
                        };
                        let Some(document) = test.traffic.submitted() else {
                            break 'run Err(String::from(
                                "a probe set with a second wave must name the document that wave \
                                 is decided under",
                            ));
                        };
                        // Before the submission, so the drop in occupancy the
                        // re-decision causes is measured across the change.
                        let assured_before = if test.traffic.re_decides() {
                            match crate::config_submission_contract::assured_flows(host_port) {
                                Ok(before) => before,
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            }
                        } else {
                            0
                        };
                        match crate::config_submission_contract::apply(
                            host_port,
                            test.topology.document(),
                            document,
                        ) {
                            Ok(proved) => applied = Some(proved),
                            Err(verdict) => {
                                break 'run Err(format!("{verdict}; see {}", log_path.display()));
                            }
                        }
                        if test.traffic.re_decides() {
                            // The commit armed a pass over the connection table and
                            // a pass advances per wakeup, so the harness supplies
                            // the wakeups a quiet bench does not have — with frames
                            // the router's parser refuses, which reach no flow, no
                            // policy counter and neither recording.
                            let driver = legacy_broadcast_frame(b"LFW-SWEEP/wakeup");
                            // Which port they go to is named rather than implied:
                            // the wait reads that port's own driver back for its
                            // account of what arrived, and a domain it was handed
                            // could be the wrong one where a port it derives cannot
                            // be.
                            let Some(driven) =
                                endpoints.first().map(|attached| attached.endpoint.port)
                            else {
                                break 'run Err(String::from(
                                    "a re-deciding scenario needs a dataplane port to drive the \
                                     pass through and this boot attached none",
                                ));
                            };
                            let outcome = crate::config_submission_contract::await_revocation(
                                host_port,
                                assured_before,
                                driven,
                                || {
                                    if let Some(attached) = endpoints.first_mut() {
                                        attached.inject(&driver);
                                    }
                                },
                            );
                            match outcome {
                                Ok(proved) => revoked = Some(proved),
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            }
                        }
                        // The second wave, into a dataplane the scrape above has
                        // just observed running the submitted generation.
                        wave = Wave::Submitted;
                        deferred_injected = !probes
                            .iter()
                            .any(|probe| probe.wave == wave && probe.waits());
                        refusals_injected = false;
                        settling_since = None;
                        last_injection = Instant::now();
                        inject_probes(&mut endpoints, &probes, |probe| {
                            probe.wave == wave && !probe.waits()
                        });
                    }
                    // The channel's own burst, on a boot that holds the appliance
                    // to going on shipping. It waits on the appliance's own
                    // record rather than on a duration: the console saying both
                    // recordings are drained is what makes everything after it
                    // new, and a burst sent on a timer would land wherever the
                    // boot happened to be.
                    Some(_)
                        if !channel_burst_injected
                            && test.channel.owes_shipping_after_catching_up(&output) =>
                    {
                        channel_burst_injected = true;
                        last_injection = Instant::now();
                        for _ in 0..CHANNEL_BURST_PASSES {
                            inject_probes(&mut endpoints, &probes, |probe| {
                                probe.wave == wave && probe.expectation.is_routed()
                            });
                        }
                    }
                    // AND the console has said what this boot's channel contract
                    // owes, which is the one thing on such a boot that no other
                    // clause here waits for. The session's outcome is written by
                    // the domain that terminates it, on the pass that decided the
                    // session; the traffic, the scrape and the recordings are all
                    // settled by other domains and can be settled first. A run
                    // that broke out on those alone would kill the guest with the
                    // channel's record still in the log ring and report an
                    // appliance that was about to speak as one that never did.
                    //
                    // Waited for on the observable and never provoked, and never
                    // bounded by a count of the appliance's own re-dials: it
                    // chooses how often it dials, and each attempt writes the same
                    // record. `total_timeout` below is what bounds it, so an
                    // appliance that genuinely never reports fails on the budget
                    // every other boot takes rather than hanging here.
                    Some(since)
                        if since.elapsed() >= SETTLE_WINDOW
                            && management.is_none()
                            && scrapes.is_empty()
                            && test.channel.satisfied(&output) =>
                    {
                        let ManagementBacking::UserNetwork {
                            host_port,
                            onboard_port,
                        } = backends.management
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
                        // After the metrics, and through the same client: what
                        // an operator runs is `curl`, and a body this harness
                        // composed itself would prove nothing about the
                        // transport that carries a megabyte. Every boot that
                        // reaches the endpoint pulls both, because a scenario
                        // that booted a reachable endpoint and judged one
                        // surface of the three is the gap the cross-surface
                        // contract closes.
                        for target in [pd_runtime::LOG_TARGET, pd_runtime::CAPTURE_TARGET] {
                            match recording_contract::fetch(host_port, target) {
                                Ok(one) => recordings.push(one),
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            }
                        }
                        // And, where the scenario's subject is the *other*
                        // port, the clients that reach it. After the three
                        // surfaces above, so a boot that failed one of them
                        // fails for that rather than for a handshake, and
                        // through the same forward: what an administrator runs
                        // is a TLS client, and a handshake this harness composed
                        // itself would prove only that the appliance agrees with
                        // the appliance.
                        if test.onboard.handshakes() {
                            // The capture as it stands, drained afresh each time
                            // the contract asks: what it waits for between its
                            // clients is the appliance's own account of the
                            // session that just ended, and a snapshot taken
                            // before the clients ran could never carry one.
                            let driven = onboard_tls_contract::drive(onboard_port, || {
                                drain(&serial_receiver, &mut output);
                                output.clone()
                            });
                            match driven {
                                Ok(made) => handshakes = made,
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            }
                            // And then wait for the appliance to have said its
                            // piece. The last session's account is written on a
                            // pass that runs after its client's connection is
                            // gone, so a run that stopped when the last client
                            // exited would kill the guest mid-record and report
                            // a domain that was about to speak as one that never
                            // did.
                            //
                            // WAITED FOR RATHER THAN PROVOKED. This loop used to
                            // spend requests on the port's other surface, because
                            // nothing else would run that pass; the clock domain's
                            // tick runs it now. Requests here are not merely
                            // unnecessary, they are harmful: each one draws a
                            // console record out of the endpoint, and a domain
                            // whose log ring fills faster than a 115200-baud
                            // console drains it DROPS records — including the
                            // second of the two a session's account is written as.
                            // So the wait watches the observable and puts nothing
                            // on the wire.
                            let mut reported = false;
                            for _ in 0..ONBOARD_REPORT_POLLS {
                                drain(&serial_receiver, &mut output);
                                if onboard_tls_contract::reported(&output) {
                                    reported = true;
                                    break;
                                }
                                thread::sleep(ONBOARD_REPORT_POLL_INTERVAL);
                            }
                            drain(&serial_receiver, &mut output);
                            if !reported && !onboard_tls_contract::reported(&output) {
                                break 'run Err(format!(
                                    "the appliance had not finished reporting the handshakes this \
                                     boot drove after {ONBOARD_REPORT_POLLS} passes. A \
                                     session's account is written on the pass that ends it, so \
                                     this is a domain that stopped answering the relay rather \
                                     than one that had nothing to say; see {}",
                                    log_path.display()
                                ));
                            }
                        }
                        // And, where the scenario's subject is the surface
                        // above that handshake, the requests an administrator
                        // makes on it. After the handshake block, because a
                        // boot that runs one runs neither the other.
                        if test.onboard.requests() {
                            // The console up to here, which is where the
                            // fingerprint every one of these clients pins to
                            // was printed. Read from the appliance's own output
                            // rather than recomputed, so what is pinned is what
                            // an administrator would have read.
                            drain(&serial_receiver, &mut output);
                            let printed = onboard_request_contract::identity(&output);
                            let (_, fingerprint) = match printed {
                                Ok(identity) => identity,
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            };
                            let into = log_path.parent().unwrap_or(Path::new("."));
                            let driven =
                                onboard_request_contract::drive(onboard_port, &fingerprint, into);
                            match driven {
                                Ok(made) => requests = made,
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            }
                            // The same bounded wait the handshakes take, and
                            // for the same reason: a request's record is
                            // written on the pass that decided it, which runs
                            // after the client's connection is gone.
                            let mut reported = false;
                            for _ in 0..ONBOARD_REPORT_POLLS {
                                drain(&serial_receiver, &mut output);
                                if onboard_request_contract::reported(&output) {
                                    reported = true;
                                    break;
                                }
                                thread::sleep(ONBOARD_REPORT_POLL_INTERVAL);
                            }
                            drain(&serial_receiver, &mut output);
                            if !reported && !onboard_request_contract::reported(&output) {
                                break 'run Err(format!(
                                    "the appliance had not finished reporting the requests this \
                                     boot made after {ONBOARD_REPORT_POLLS} passes. A \
                                     request's record is written on the pass that decided it, so \
                                     this is a domain that stopped answering the relay rather \
                                     than one that had nothing to say; see {}",
                                    log_path.display()
                                ));
                            }
                        }
                        // And, on the two boots whose subject is onboarding
                        // *whole*, the management server this harness plays.
                        // Last of all, because it is the one client that
                        // changes the appliance: an install shuts the surface
                        // for good, so a boot that ran anything else after it
                        // would be asking an owned appliance for a resource
                        // that no longer exists and calling the answer a
                        // failure.
                        if test.onboard.onboards() || test.onboard.revisits() {
                            drain(&serial_receiver, &mut output);
                            // The identity this appliance printed: the
                            // fingerprint every client pins to, and the name a
                            // certification authority is about to certify.
                            // Both read off the appliance's own output, so what
                            // is issued is issued to what an administrator
                            // would have read.
                            let (device, fingerprint) =
                                match onboard_request_contract::identity(&output) {
                                    Ok(identity) => identity,
                                    Err(verdict) => {
                                        break 'run Err(format!(
                                            "{verdict}; see {}",
                                            log_path.display()
                                        ));
                                    }
                                };
                            let into = log_path.parent().unwrap_or(Path::new("."));
                            let driven = if test.onboard.onboards() {
                                onboard_install_contract::onboard(
                                    test.root,
                                    onboard_port,
                                    &fingerprint,
                                    &device,
                                    into,
                                )
                            } else {
                                onboard_install_contract::revisit(onboard_port, &fingerprint, into)
                            };
                            let driven = match driven {
                                Ok(made) => made,
                                Err(verdict) => {
                                    break 'run Err(format!(
                                        "{verdict}; see {}",
                                        log_path.display()
                                    ));
                                }
                            };
                            // The same bounded wait the requests take, and for
                            // one reason more: an install's own account is
                            // written by the domain that made it durable, which
                            // is a second ring behind the one answering the
                            // client.
                            let mut reported = false;
                            for _ in 0..ONBOARD_REPORT_POLLS {
                                drain(&serial_receiver, &mut output);
                                if driven.reported(&output) {
                                    reported = true;
                                    break;
                                }
                                thread::sleep(ONBOARD_REPORT_POLL_INTERVAL);
                            }
                            drain(&serial_receiver, &mut output);
                            if !reported && !driven.reported(&output) {
                                break 'run Err(format!(
                                    "the appliance had not finished accounting for what this \
                                     run's management server did after \
                                     {ONBOARD_REPORT_POLLS} passes. A request's record is \
                                     written on the pass that decided it and an install's on the \
                                     domain that made it durable, so this is a domain that \
                                     stopped answering rather than one that had nothing to say; \
                                     see {}",
                                    log_path.display()
                                ));
                            }
                            installs = Some(driven);
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
                // The node keeps running, so nothing ends this boot but the
                // harness. Wait for the console to have said its piece — the
                // refusal, the domain's own state and the fail-closed record —
                // and then out a settle window with no frame having come back,
                // which is the same window every refused probe elsewhere is
                // judged over. The absences the transcript also owes are judged
                // once the capture is complete: a record still in the log ring
                // and one that will never be written look alike from here.
                BootContract::FailedClosed { transcript } => match settling_since {
                    None if transcript.satisfied(&output) => {
                        settling_since = Some(Instant::now());
                    }
                    Some(since) if since.elapsed() >= SETTLE_WINDOW => break 'run Ok(()),
                    _ => {}
                },
                // This node keeps running too, and the records that end the boot
                // are the last ones the cryptography domain and the STORE domain
                // write: each runs to completion in `init`, so a `ready` or a
                // `refused` from one means every record it owes is already in the
                // capture. Both are waited for because the cryptography domain's
                // contract is no longer about one domain: it signs under a key the
                // store domain holds, and holding its `delegated-device=` to that
                // domain's own `device=` needs both renderings on the wire. It
                // costs nothing — the store domain establishes its identity before
                // the cryptography domain's first vector runs, sitting above it —
                // and what it removes is a race in which the console had drained
                // one ring and not the other. No settle window follows either way,
                // because nothing is being waited out: there is no absence in this
                // contract for a late frame to spoil.
                BootContract::Cryptography => {
                    if crate::crypto_contract::finished(&output)
                        && crate::store_contract::finished(&output)
                    {
                        break 'run Ok(());
                    }
                }
                // And this node too, on the store domain's own last record: it
                // establishes an identity once in `init` and parks, so its
                // fingerprint record — or a refusal — means every record it owes
                // is already in the capture.
                BootContract::StoreIdentity => {
                    if crate::store_contract::finished(&output) {
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
                    // A node that refused its own document keeps running, so an
                    // exit is a domain that faulted rather than an outcome.
                    BootContract::FailedClosed { .. } => {
                        break 'run Err(format!(
                            "QEMU exited ({status}) on a boot whose contract is that the node \
                             comes up and forwards nothing. Every domain runs on such a node — \
                             only its configuration was refused — so an exit is a fault; see {}",
                            log_path.display()
                        ));
                    }
                    // The same reasoning: every domain runs on this node and
                    // none of them exits, so an exit before the cryptography
                    // domain reported anything is a fault — and on this contract
                    // it is the interesting one, an image that comes up on one
                    // accelerator and dies on the other being exactly what the
                    // boot is here to catch.
                    BootContract::Cryptography => {
                        break 'run Err(format!(
                            "QEMU exited ({status}) before the cryptography domain reported \
                             either `ready` or `refused`. This boot forces emulation, so an exit \
                             here is the image executing on one accelerator and faulting on the \
                             other — read the capture for the last domain that spoke; see {}",
                            log_path.display()
                        ));
                    }
                    // The same reasoning again: every domain runs on this node
                    // and none exits, so an exit before the store domain reported
                    // is a fault. On this contract it is the interesting one — the
                    // domain that owns the appliance's identity is the one holding
                    // a device whose bytes are a physical attacker's.
                    BootContract::StoreIdentity => {
                        break 'run Err(format!(
                            "QEMU exited ({status}) before the store domain reported an identity \
                             or a refusal. The domain that owns the appliance's own medium is the \
                             one that reads bytes somebody with the disk composed, so an exit \
                             rather than a refusal is a path that faulted instead of saying no; \
                             see {}",
                            log_path.display()
                        ));
                    }
                },
                Ok(None) => {}
                Err(error) => break 'run Err(format!("poll QEMU: {error}")),
            }
            if start.elapsed() >= total_timeout {
                break 'run Err(match &test.contract {
                    // The channel clause sits beside the traffic's rather than
                    // in place of it: a boot that ran out of budget may be short
                    // of either or both, and a verdict that named one would send
                    // a reader to the wrong half. It is empty where nothing is
                    // outstanding, so every boot whose subject is something else
                    // reads exactly as it did.
                    BootContract::Routed => format!(
                        "timed out after {}s waiting for the routed contract; {}{}; {}{}; see {}",
                        total_timeout.as_secs(),
                        describe_pending(&probes, &deliveries),
                        test.channel.outstanding(&output),
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
                    BootContract::FailedClosed { transcript } => format!(
                        "timed out after {}s waiting for the console to report that the node \
                         refused its own document: {}{}; see {}",
                        total_timeout.as_secs(),
                        transcript.summary(),
                        describe_injection_failures(&endpoints),
                        log_path.display()
                    ),
                    BootContract::Cryptography => format!(
                        "timed out after {}s waiting for the cryptography domain to report \
                         `ready` or `refused` on the console. This boot forces emulation, so a \
                         domain that never finished here is one whose work the emulator would not \
                         execute{}; see {}",
                        total_timeout.as_secs(),
                        describe_injection_failures(&endpoints),
                        log_path.display()
                    ),
                    BootContract::StoreIdentity => format!(
                        "timed out after {}s waiting for the store domain to report an identity \
                         or a refusal on the console. A domain that never finished is one whose \
                         device never answered — every wait it makes is bounded by `lfw_blk`'s \
                         own poll budget, so a silence here is the budget having been spent{}; \
                         see {}",
                        total_timeout.as_secs(),
                        describe_injection_failures(&endpoints),
                        log_path.display()
                    ),
                });
            }
            // NOTHING IS INJECTED TO CARRY THE DIAL, AND THAT IS THE CONTRACT.
            // A station that answers the resolution and then falls silent used
            // to leave the appliance waiting on a `SYN` it could not re-send:
            // its transport's retransmission ran only on a pass some frame
            // provoked, and this harness had to keep speaking to provoke one.
            // The clock domain now wakes the management domain on a period, so
            // every backoff of an unanswered `SYN` and every re-ask of an
            // unanswered resolution runs on the appliance's own time. The
            // station therefore says nothing at all while a dial is outstanding,
            // and a channel that still decides is a channel the appliance
            // carried by itself.
            //
            // The onboarding session, opened once the client's own exchange on
            // this wire has closed.
            //
            // Sequential rather than beside it, and not for want of a queue: the
            // two conversations would interleave on one wire, and a failure in
            // either would be read against a capture holding both. The client's
            // exchange is also what proves the port answers at all, so a session
            // opened before it would report a port that never came up as a
            // session that never began.
            if let Some(wire) = management.as_mut()
                && wire.client.step == TcpStep::Closed
                && wire.onboard.step == OnboardStep::Unopened
            {
                wire.onboard.open(&management_probe.port);
                while let Some(next) = wire.onboard.owed.pop_front() {
                    client_pending.push_back(next);
                }
            }
            // NOTHING IS INJECTED TO CARRY A SESSION EITHER, on the dial's
            // terms and with one more of its own. The pass that closes a
            // session's account has no frame of its own once the connection is
            // gone, and the clock domain's tick runs it now. Frames sent to
            // provoke it were not merely unnecessary: every one draws a console
            // record out of the endpoint, and a domain whose log ring fills
            // faster than a 115200-baud console drains it DROPS records —
            // including the second of the two a session's account is written as,
            // which is a failure of this harness's own making. So this station
            // falls silent once its session is open and waits for the records.
            // One queued frame per pass, and only once the port has
            // reported every frame ahead of it — the burst gate applied to the
            // exchange, so no two frames are ever in flight to a driver that may
            // not have refilled. [`MANAGEMENT_REPORT_GRACE`] bounds the wait for
            // the same reason it bounds the one at the end of the run: a frame
            // that really was lost must be reported as the count it is rather
            // than as a queue that never drains.
            //
            // THE STATION'S ANSWERS TAKE THE OPENING FIRST. Both queues feed one
            // pipeline under one gate, so the choice here is only which of two
            // waiting frames goes now and which goes at the next opening — but
            // the appliance is timing one of them and not the other. It asks
            // about its next hop a bounded number of times a bounded interval
            // apart, so a reply that misses the interval it was asked in is one
            // the appliance correctly reports as never having come; the client's
            // own exchange, by contrast, is paced entirely by this harness and
            // has nothing counting at the far end. A single FIFO put this
            // harness's own segment in front of an answer that was already owed,
            // and an attempt was judged short of replies the station had
            // composed and not yet sent.
            if let Some(wire) = management.as_mut()
                && (management_contract::frames_reported(&output) >= injected.frames as u64
                    || last_management_inject.elapsed() >= MANAGEMENT_REPORT_GRACE)
            {
                let owed = if station_pending.is_empty() {
                    &mut client_pending
                } else {
                    &mut station_pending
                };
                if let Some(next) = owed.pop_front() {
                    wire.inject(&next);
                    injected = wire.injected;
                    last_management_inject = Instant::now();
                }
            }
            if observed_claim.is_none()
                && let Some(claim) = management.as_ref().and_then(|wire| wire.station.claim())
            {
                observed_claim = Some(claim);
            }
            if settling_since.is_none() && last_injection.elapsed() >= REINJECT_INTERVAL {
                last_injection = Instant::now();
                inject_probes(&mut endpoints, &probes, |probe| {
                    probe.wave == wave
                        && !probe.once
                        && (deferred_injected || !probe.waits())
                        && !is_delivered(&probes, &deliveries, probe)
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

    // A reconfiguration scenario that never reached the submission proved nothing
    // about it, and a boot whose second wave was never injected would otherwise
    // pass on the first wave's verdicts alone.
    let outcome = outcome.and_then(|()| {
        if probes.iter().any(|probe| probe.wave == Wave::Submitted) && applied.is_none() {
            return Err(format!(
                "the boot met its routed contract under the document it was built from and no \
                 configuration was submitted, so nothing was proved about a change; see {}",
                log_path.display()
            ));
        }
        // And a scenario that states what a commit did to the running
        // conversations must have watched the re-decision finish: its last two
        // probes' fates are the pass's, and a boot that never ran one would have
        // decided them under a table the commit left untouched.
        if test.traffic.re_decides() && revoked.is_none() {
            return Err(format!(
                "the boot submitted a document and no pass over its connection table was \
                 observed, so nothing was proved about the conversations it was already \
                 carrying; see {}",
                log_path.display()
            ));
        }
        Ok(())
    });
    let outcome = decide(outcome, &test.contract, &output, log_path);
    // How an absence reads follows from the contract, and from nothing the loop
    // observed: a node that refused its own configuration is one whose probes must
    // all be absent, and a table reporting that as `missing` would put failure
    // words on the evidence the boot exists to produce.
    let forwarding = match &test.contract {
        BootContract::Routed | BootContract::Halted { .. } => Forwarding::UnderAPolicy,
        BootContract::FailedClosed { .. } => Forwarding::NothingCommitted,
        BootContract::Cryptography | BootContract::StoreIdentity => Forwarding::NotThisBootsSubject,
    };
    let traffic = TrafficReport::new(stations, &probes, &deliveries, broke, forwarding);

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
        started_at: start,
        serial: output,
        hardware_accelerated: test.hardware_accelerated,
        traffic,
        management: injected,
        management_tcp_isn: tcp_isn,
        dial_claim: observed_claim,
        management_replies: answered,
        scrapes,
        dataplane_frames,
        policy,
        recordings,
        carried_recordings: Vec::new(),
        handshakes,
        requests,
        installs,
        applied,
        revoked,
        onboard: onboarded,
        injected: probes
            .iter()
            .map(|probe| Injected {
                name: probe.name.clone(),
                frame: probe.frame.clone(),
                observed: probe.observed,
                // What the harness watched happen on the wire, turned into the
                // verdict a record of this probe must state.
                verdict: if probe.expectation.is_routed() {
                    recording_contract::VERDICT_FORWARDED
                } else {
                    recording_contract::VERDICT_DROPPED
                },
                event: probe.event,
            })
            .collect(),
    })
}

/// Push the settle window out to now — **and only where one is already running**.
///
/// The window is not a timer that anything may start. Its presence is the run's
/// phase: while it is `None` the harness is still putting frames on the wire —
/// re-injecting the dataplane probes, and releasing the management burst once
/// the routed ones have crossed and the ports have reported themselves up — and
/// both of those are guarded on it being `None`. It is started in one place, by
/// the pass that finds every management frame sent, and that is what makes those
/// phases finish before anything is judged.
///
/// What the events below own is the *end* of it: each is a frame that landed
/// late, and breaking out at that instant would race the record of it, so the
/// window is pushed out to give the appliance a whole one to report in. That is
/// a restart, and a restart of nothing is nothing.
///
/// Starting one here instead closed the injection phases for good. Two of the
/// three callers cannot reach that state — the client's exchange and the
/// onboarding session are both opened by this harness after the window has
/// begun — but the third is the connection the APPLIANCE opens, on a schedule
/// no part of this run drives. A boot whose dial completed its handshake before
/// the routed probes had crossed stopped re-injecting them and never released
/// the management burst at all, then spent its whole budget waiting for an ARP
/// reply to a request it had not sent. The appliance was healthy throughout and
/// had nothing left to answer, so its console fell quiet too, which read as a
/// node that had stopped.
fn restart_settling(settling_since: &mut Option<Instant>) {
    if settling_since.is_some() {
        *settling_since = Some(Instant::now());
    }
}

/// Whether every probe the filter admits that must be delivered has been.
///
/// Always asked of a *subset*, and there are two reasons for one predicate. A
/// stateful set has to ask it of its **immediate** probes alone, the deferred ones
/// being unable to arrive before they have been sent; and a reconfiguration set has
/// to ask it of the probes belonging to the policy **now in force**, a probe stated
/// against a document that has not been submitted yet being one nothing could
/// deliver.
fn all_routed_among(
    probes: &[Probe],
    deliveries: &[Option<Delivery>],
    admits: impl Fn(&Probe) -> bool,
) -> bool {
    probes
        .iter()
        .zip(deliveries)
        .filter(|(probe, _)| probe.expectation.is_routed() && admits(probe))
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
        if !probe.expectation.is_routed() {
            continue;
        }
        if seen.is_some() {
            arrived.push(probe.name.as_str());
        } else {
            missing.push(probe.name.as_str());
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
        // The whole transcript, including the clauses that are absences: what a
        // refused document may NOT have produced is only decidable once the
        // capture is complete.
        (BootContract::FailedClosed { transcript }, Ok(())) => transcript.judge(output, log_path),
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
    use crate::qemu::{DialContract, GuestNic};
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
            dial: crate::qemu::DialContract::Answered,
            onboard: crate::qemu::OnboardContract::Untouched,
            // These boots point no management server at the appliance and read
            // no record of one, so the contract that owes a console record is
            // the one this harness's own tests never take.
            channel: crate::channel_contract::ChannelContract::Untouched,
            contract: BootContract::Routed,
            // No client of this harness's own reaches for it: these boots run
            // no management server, so the workspace is named and never opened.
            root: Path::new("."),
            log_path: log,
            log_header: HEADER,
            topology,
            traffic: Traffic::Routed,
            // The harness's own boots are judged on what they forwarded, never
            // on what anything cost, so which way QEMU executed them decides
            // nothing here.
            hardware_accelerated: false,
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
                "</neighbours><rules/>",
                "<management mac=\"52:54:00:12:34:52\" address=\"10.0.2.15\" ",
                "prefix-length=\"24\" enabled=\"true\" gateway=\"10.0.2.2\"/>",
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
                "</neighbours><rules/>",
                "<management mac=\"52:54:00:12:34:52\" address=\"10.0.2.15\" ",
                "prefix-length=\"24\" enabled=\"true\" gateway=\"10.0.2.2\"/>",
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

    /// The three filter probes differ in exactly one field, and it is the field
    /// the policy decides on.
    ///
    /// That is the whole of what makes the scenario's three outcomes attributable
    /// to the document: if the probes differed anywhere else, a difference in
    /// their fates could be admission's or routing's.
    #[test]
    fn the_filter_probes_differ_only_in_the_port_the_policy_decides_on() {
        let topology = bench();
        let policy = topology
            .port_policy()
            .expect("the shipped document declares an accepting and a dropping port rule");
        let probes = policy_probes(&topology, policy);
        let [accepted, denied, unmatched] = probes.as_slice() else {
            panic!("one probe per outcome the filter can reach");
        };

        // One routed and two refused: the counts a policy scenario reports.
        assert!(matches!(accepted.expectation, Expectation::Routed { .. }));
        assert!(matches!(denied.expectation, Expectation::Dropped { .. }));
        assert!(matches!(unmatched.expectation, Expectation::Dropped { .. }));

        let ports: Vec<u16> = probes
            .iter()
            .map(|probe| {
                UdpPacket::decode(&probe.frame)
                    .expect("every filter probe is a well-formed datagram")
                    .destination_port
            })
            .collect();
        assert_eq!(
            ports,
            [
                policy.accepted.destination_port,
                policy.denied.destination_port,
                policy.unmatched,
            ],
            "a probe carries a port the document's policy does not decide"
        );

        // Every other field of the three datagrams is the same, so the port is
        // the only thing that can explain three different fates.
        for probe in &probes {
            let decoded = UdpPacket::decode(&probe.frame).expect("well formed");
            let base = UdpPacket::decode(&accepted.frame).expect("well formed");
            assert_eq!(
                UdpPacket {
                    destination_port: base.destination_port,
                    payload: base.payload.clone(),
                    ..decoded
                },
                base,
                "probe {} differs from the accepted one outside its port",
                probe.name
            );
        }
    }

    /// The filter probes are the document's too, so a policy scenario against the
    /// second document cannot pass on the first document's ports.
    #[test]
    fn a_filter_probe_carries_the_ports_and_ids_of_its_own_document() {
        let (shipped, alternate) = (bench(), alternate());
        let one = shipped.port_policy().expect("the shipped policy");
        let two = alternate.port_policy().expect("the alternate policy");
        // The ids differ, which is what makes a per-rule counter's label a thing
        // the appliance read rather than a thing the build carried.
        assert_ne!(one.accepted.id, two.accepted.id);
        assert_ne!(one.denied.id, two.denied.id);
        for probe in policy_probes(&shipped, one)
            .iter()
            .zip(policy_probes(&alternate, two))
        {
            let (first, second) = probe;
            assert_eq!(first.name, second.name);
            assert_ne!(
                first.frame, second.frame,
                "filter probe {} is the same on both benches",
                first.name
            );
        }
    }

    /// A witness is derived from the probe set, so the two cannot disagree about
    /// what was injected.
    #[test]
    fn each_probe_set_witnesses_what_it_puts_on_the_wire() {
        let topology = bench();
        let (routed, witness) =
            injected_probes(&topology, Traffic::Routed).expect("the shipped bench");
        assert_eq!(routed.len(), 6);
        // Not one of the six is about the filter: the four refusals are decided
        // before it and the two deliveries pass the accepting rule.
        assert!(!witness.probed_the_denying_rule);
        assert!(!witness.probed_the_fallthrough);

        let (policy, witness) =
            injected_probes(&topology, Traffic::Policy).expect("the shipped bench");
        assert_eq!(policy.len(), 3);
        assert!(witness.probed_the_denying_rule);
        assert!(witness.probed_the_fallthrough);
        assert_eq!(
            witness.policy,
            topology.port_policy().expect("the shipped policy")
        );

        let (lifecycle, witness) =
            injected_probes(&topology, Traffic::Lifecycle).expect("the shipped bench");
        assert_eq!(lifecycle.len(), 4);
        // The dropping rule and not the fallthrough: one segment carries that
        // rule's port and every other one the accepting rule's, so nothing here
        // falls past the last rule.
        assert!(witness.probed_the_denying_rule);
        assert!(!witness.probed_the_fallthrough);
    }

    /// **The lifecycle set, as the events it obliges.** Three segments on one
    /// conversation — an opening, a refusal that must not move it, and a close —
    /// and a fourth on a five-tuple a rule denies.
    ///
    /// Every claim here is what the recording contract then holds the appliance
    /// to, so a probe set that stopped obliging an event would weaken that
    /// contract silently rather than fail here.
    #[test]
    fn the_lifecycle_set_obliges_an_open_a_refusal_and_a_close() {
        let topology = bench();
        let policy = topology.port_policy().expect("the shipped policy");
        let probes = lifecycle_probes(&topology, policy);
        let named = |name: &str| {
            probes
                .iter()
                .find(|probe| probe.name == name)
                .unwrap_or_else(|| panic!("the set names {name}"))
        };

        let open = named("lifecycle-open");
        assert_eq!(open.event, Some(recording_contract::EVENT_FLOW_OPENED));
        assert!(open.expectation.is_routed(), "an opening is forwarded");
        assert!(!open.deferred, "nothing precedes the opening");

        let refused = named("lifecycle-out-of-window");
        assert_eq!(refused.event, Some(recording_contract::EVENT_FLOW_REFUSED));
        assert!(!refused.expectation.is_routed());
        assert!(
            refused.once,
            "a segment outside an open flow's window is a different refusal once the flow has \
             closed, so it goes out once"
        );

        let close = named("lifecycle-close");
        assert_eq!(close.event, Some(recording_contract::EVENT_FLOW_CLOSED));
        assert!(close.expectation.is_routed(), "a reset is forwarded");
        assert!(
            close.deferred,
            "a close must follow the opening it closes onto the wire"
        );

        // The fourth segment, which is the only probe in this harness a rule
        // refuses for its protocol. Its opening flags are the admitted opening's
        // exactly, so the one thing that separates their fates is the destination
        // port the two rules disagree about.
        let denied = named("lifecycle-denied");
        assert_eq!(denied.event, Some(recording_contract::EVENT_POLICY_DENIED));
        assert!(!denied.expectation.is_routed());
        assert!(
            !denied.once && !denied.deferred,
            "a rule refuses it the same way however often it arrives, and it waits on no flow"
        );

        let destination_port = |probe: &Probe| {
            let segment = &probe.frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..];
            u16::from_be_bytes([segment[2], segment[3]])
        };
        let flags = |probe: &Probe| probe.frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 13];
        assert_eq!(destination_port(denied), policy.denied.destination_port);
        assert_eq!(
            flags(denied),
            flags(open),
            "the denied segment must be an opening too, or the rule is not the only difference"
        );

        // The other three are the same five-tuple, so they are one conversation:
        // the difference between their fates is the connection table and nothing
        // else.
        for probe in [open, refused, close] {
            assert_eq!(
                destination_port(probe),
                policy.accepted.destination_port,
                "probe {} does not carry the accepting rule's port",
                probe.name
            );
        }
        // And the refused segment is the one whose sequence number is outside
        // anything the opening could have authorised.
        let sequence = |probe: &Probe| {
            let segment = &probe.frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..];
            u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]])
        };
        assert!(sequence(refused) > sequence(open).wrapping_add(u32::from(u16::MAX)));
        assert_eq!(sequence(close), sequence(open).wrapping_add(1));
    }

    /// **The flood set, as the burst it is.** Sixty-four distinct five-tuples that
    /// must all be refused, and one conversation that must survive them.
    ///
    /// Every claim here is what the run then rests on: a burst whose datagrams
    /// shared a five-tuple would be one conversation retransmitting rather than a
    /// flood, and a survivor addressed to a port some rule names would be carried by
    /// the policy rather than by its flow.
    #[test]
    fn the_flood_set_opens_one_conversation_and_floods_with_distinct_five_tuples() {
        let topology = bench();
        let policy = topology.port_policy().expect("the shipped policy");
        let probes = flood_probes(&topology, policy);
        assert_eq!(probes.len(), 2 + usize::from(FLOOD_TUPLES));

        let named = |name: &str| {
            probes
                .iter()
                .find(|probe| probe.name == name)
                .unwrap_or_else(|| panic!("the set names {name}"))
        };
        let request = named("flood-request");
        assert!(request.expectation.is_routed());
        assert!(!request.deferred, "the request opens the conversation");

        // The survivor is the reply, and it must go out after the request has been
        // observed crossing — by which time the burst has been arriving since the
        // first pass. That deferral is the whole of "the flow survived the flood".
        let survivor = named("flood-survivor");
        assert!(survivor.expectation.is_routed());
        assert!(survivor.deferred, "the survivor must follow the request");
        assert_eq!(
            survivor.event,
            Some(recording_contract::EVENT_FLOW_ADVANCED),
            "a reply advances the conversation the request opened rather than opening one"
        );
        // And no rule of the document is about the port it is addressed to, so only
        // its flow could carry it.
        let port_of = |probe: &Probe| {
            let datagram = &probe.frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..];
            u16::from_be_bytes([datagram[2], datagram[3]])
        };
        assert_ne!(port_of(survivor), policy.accepted.destination_port);
        assert_ne!(port_of(survivor), policy.denied.destination_port);

        // The burst: every datagram refused by the default deny, every one of them a
        // five-tuple of its own, and none of them the conversation's.
        let burst: Vec<&Probe> = probes
            .iter()
            .filter(|probe| probe.name.starts_with("flood-0"))
            .collect();
        assert_eq!(burst.len(), usize::from(FLOOD_TUPLES));
        let mut sources = BTreeSet::new();
        for probe in &burst {
            assert!(!probe.expectation.is_routed());
            assert_eq!(probe.event, Some(recording_contract::EVENT_POLICY_NO_MATCH));
            assert_eq!(
                port_of(probe),
                policy.unmatched,
                "a flood datagram must fall past every rule rather than match one"
            );
            let datagram = &probe.frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..];
            let source = u16::from_be_bytes([datagram[0], datagram[1]]);
            assert!(
                sources.insert(source),
                "two flood datagrams share source port {source}, so they are one conversation \
                 retransmitting rather than two"
            );
            assert_ne!(
                source, SOURCE_PORT,
                "a flood datagram must not open the conversation the survivor is carried by"
            );
        }
        // Distinct as *frames* too, which is what the capture recording holds each of
        // them to: one block per probe, byte for byte.
        let frames: BTreeSet<&Vec<u8>> = burst.iter().map(|probe| &probe.frame).collect();
        assert_eq!(frames.len(), burst.len());
    }

    /// A frame this harness does not model field by field is still judged as
    /// bytes, and the hop it must have taken is derived from the injection.
    #[test]
    fn a_routed_frame_is_judged_against_the_hop_it_must_have_taken() {
        let topology = bench();
        let [a, b] = topology.endpoints();
        let probe = &lifecycle_probes(&topology, topology.port_policy().expect("a policy"))[0];
        let Expectation::Routed {
            delivered,
            datagram,
            ..
        } = &probe.expectation
        else {
            panic!("the opening must be routed");
        };
        assert!(
            datagram.is_none(),
            "a TCP segment is not a datagram this harness models"
        );
        // Exactly the three changes a hop makes, and nothing else.
        assert_eq!(delivered.len(), probe.frame.len());
        assert_eq!(&delivered[..6], &b.mac);
        assert_eq!(&delivered[6..12], &b.gateway_mac);
        let at = ETHERNET_HEADER_LEN;
        assert_eq!(delivered[at + 8], probe.frame[at + 8] - 1, "the TTL");
        assert_eq!(
            &delivered[at + 12..at + 20],
            &probe.frame[at + 12..at + 20],
            "the addresses are untouched"
        );
        assert_eq!(
            &delivered[at + IPV4_HEADER_LEN..],
            &probe.frame[at + IPV4_HEADER_LEN..],
            "and so is everything behind the IPv4 header"
        );
        // The delivery the matcher accepts is the one the contract names.
        assert_eq!(probe.from, a);
        probe
            .judge(b.port, delivered)
            .expect("the frame a hop produces is the one the matcher accepts");
        // And one byte off it is not.
        let mut spoiled = delivered.clone();
        spoiled[at + IPV4_HEADER_LEN + 4] ^= 0xff;
        let error = probe
            .judge(b.port, &spoiled)
            .expect_err("a changed sequence number is not the frame a hop produces");
        assert!(
            error.contains("is not the frame the routed contract names"),
            "{error}"
        );
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

    /// [`Traffic::ALL`] is every probe set, and this is what makes that true rather
    /// than a claim: [`Traffic::position`] is an exhaustive match, so a set added to
    /// the enum must be given a position, and a position outside the array — or one
    /// that collides with another set's — fails here. Every check stated over
    /// `Traffic::ALL` therefore reaches every set there is.
    #[test]
    fn the_list_of_every_probe_set_holds_every_one_of_them() {
        for (at, traffic) in Traffic::ALL.iter().enumerate() {
            assert_eq!(
                traffic.position(),
                at,
                "{traffic:?} is at {at} in the list and claims position {}",
                traffic.position()
            );
        }
    }

    /// **Attribution is by substring, so a marker may not appear in a frame that
    /// is not its own.** Over every probe set and both benches, because a set that
    /// gets this wrong fails at its own boot with the appliance in the right and the
    /// harness in the wrong — which is exactly what happened when a flood's marker
    /// was made a prefix of the marker on the conversation beside it.
    ///
    /// Stated marker by marker rather than probe by probe, because a marker is what
    /// identifies a *group*: a flood is sixty-four probes sharing one, every frame of
    /// which must be refused, so two probes carrying one marker is correct and two
    /// markers one frame answers to never is.
    ///
    /// The management wire's own two markers are held to the same rule, and for the
    /// same reason: the endpoint refuses any frame carrying a dataplane probe's
    /// marker, so a probe marker appearing in one of those would make a legitimate
    /// reply read as a leak across the isolation boundary.
    #[test]
    fn every_probe_set_is_attributable_marker_by_marker() {
        for topology in [bench(), alternate()] {
            for traffic in Traffic::ALL {
                let (probes, _) = injected_probes(&topology, traffic)
                    .unwrap_or_else(|error| panic!("{traffic:?} on this bench: {error}"));
                for probe in &probes {
                    assert!(
                        contains(&probe.frame, probe.marker),
                        "{traffic:?}: probe {} does not carry its own marker",
                        probe.name
                    );
                    for other in &probes {
                        if other.marker == probe.marker {
                            continue;
                        }
                        assert!(
                            !contains(&other.frame, probe.marker),
                            "{traffic:?}: probe {}'s marker also appears in {}'s frame, so a \
                             delivery of one would be attributed to the other",
                            probe.name,
                            other.name
                        );
                    }
                    for (what, marker) in [
                        ("the opaque management frame", MANAGEMENT_MARKER),
                        ("the echo request payload", ECHO_PAYLOAD),
                    ] {
                        assert!(
                            !contains(&probe.frame, marker) && !contains(marker, probe.marker),
                            "{traffic:?}: probe {}'s marker and {what}'s are confusable, so a \
                             reply the management port owes would read as a dataplane frame that \
                             crossed the isolation boundary",
                            probe.name
                        );
                    }
                }
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
                    verdict.contains(probe.name.as_str()) && verdict.contains(because),
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
        assert!(!all_routed_among(&probes, &deliveries, |_| true));

        deliveries = vec![None; probes.len()];
        deliveries[at("routed-0-to-1")] = Some(arrived);
        assert!(!all_routed_among(&probes, &deliveries, |_| true));
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
        assert!(all_routed_among(&probes, &deliveries, |_| true));
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
            .judge(to.port, delivered)
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
        let report = TrafficReport::new(
            endpoints(),
            &probes,
            &deliveries,
            None,
            Forwarding::UnderAPolicy,
        );
        let rendered = report.render();

        assert_eq!(report.summary(), "2 routed, 4 dropped");
        assert!(
            !rendered.contains("unfinished"),
            "every probe reached an end state: {rendered}"
        );
        for probe in &probes {
            assert!(
                rendered.contains(probe.name.as_str()),
                "{}\n{rendered}",
                probe.name
            );
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
                .find(|line| line.contains(probe.name.as_str()))
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

        let report = TrafficReport::new(
            endpoints(),
            &probes,
            &deliveries,
            Some(at("routed-1-to-0")),
            Forwarding::UnderAPolicy,
        );
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
        let outstanding = TrafficReport::new(
            endpoints(),
            &probes,
            &nothing,
            None,
            Forwarding::UnderAPolicy,
        );
        assert!(
            outstanding.render().contains("missing"),
            "{}",
            outstanding.render()
        );
        assert_eq!(outstanding.summary(), "0 routed, 4 dropped");
    }

    /// **A node that committed nothing reports its absences as the contract, not as
    /// failures.** The same probes and the same empty deliveries, read under the two
    /// forwardings, must produce two different tables: on a routed boot every routed
    /// probe is outstanding and the run is unfinished, and on a fail-closed one every
    /// one of them is a refusal and the table is complete.
    ///
    /// Worth a case of its own because the evidence a reader looks at *is* the table:
    /// a fail-closed boot whose rows read `missing` and whose heading read
    /// `unfinished` would present the thing it proved as the thing that went wrong.
    #[test]
    fn a_node_that_committed_nothing_reports_every_absence_as_the_contract() {
        let probes = probes(&bench()).expect("the shipped bench");
        let nothing: Vec<Option<Delivery>> = vec![None; probes.len()];
        let routed = probes
            .iter()
            .filter(|probe| probe.expectation.is_routed())
            .count();
        assert!(routed > 0, "the routed set forwards something");

        let fail_closed = TrafficReport::new(
            endpoints(),
            &probes,
            &nothing,
            None,
            Forwarding::NothingCommitted,
        );
        let rendered = fail_closed.render();
        assert!(
            !rendered.contains("missing"),
            "an absence is the contract on this boot: {rendered}"
        );
        assert!(
            !rendered.contains("unfinished"),
            "every probe reached the end state this contract defines: {rendered}"
        );
        assert!(
            rendered.contains("committed no generation"),
            "a row must say why nothing crossed: {rendered}"
        );
        // Every probe is a refusal, the ones the document forwards included.
        assert_eq!(
            fail_closed.summary(),
            format!("0 routed, {} dropped", probes.len())
        );

        // And the same inputs under a committed policy, which is the contrast that
        // makes the above a decision rather than a rename.
        let under_a_policy = TrafficReport::new(
            endpoints(),
            &probes,
            &nothing,
            None,
            Forwarding::UnderAPolicy,
        );
        assert!(under_a_policy.render().contains("missing"));
        assert!(under_a_policy.render().contains("unfinished"));
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

        let report = TrafficReport::new(
            endpoints(),
            &probes,
            &deliveries,
            None,
            Forwarding::UnderAPolicy,
        );
        let line = report
            .render()
            .lines()
            .find(|line| line.contains(probes[refused].name.as_str()))
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
                &mut TcpClient::new(),
                &mut DialStation::new(DialMisbehaviour::Answers),
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            ),
            Ok(ManagementReply::Arp)
        );
        assert_eq!(
            probe.judge(
                &echo_reply(&management, |_| {}),
                &probes,
                &mut TcpClient::new(),
                &mut DialStation::new(DialMisbehaviour::Answers),
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            ),
            Ok(ManagementReply::Echo)
        );

        let arp_mutations: [ArpMutation; 5] = [
            ("destination MAC", |reply| reply.destination_mac = [1; 6]),
            ("source MAC", |reply| reply.source_mac = [2; 6]),
            ("target MAC", |reply| reply.target_mac = [3; 6]),
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
                    &mut DialStation::new(DialMisbehaviour::Answers),
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
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
                    &mut DialStation::new(DialMisbehaviour::Answers),
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
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

        // A dataplane probe: the required management/dataplane isolation, in the
        // direction a leak would be silent.
        let leaked = &probes[0].frame;
        let verdict = probe
            .judge(
                leaked,
                &probes,
                &mut TcpClient::new(),
                &mut DialStation::new(DialMisbehaviour::Answers),
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("a dataplane probe on the management wire");
        assert!(verdict.contains(probes[0].name.as_str()), "{verdict}");
        assert!(verdict.contains("isolates that port"), "{verdict}");

        // One of the opaque frames coming back: the endpoint answers nothing for
        // that EtherType, so it must count it and stay silent.
        let verdict = probe
            .judge(
                &probe.frames[0],
                &probes,
                &mut TcpClient::new(),
                &mut DialStation::new(DialMisbehaviour::Answers),
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("an opaque frame must never be answered");
        assert!(verdict.contains("say nothing"), "{verdict}");

        // A protocol the endpoint does not speak, and a frame too short to name
        // one at all.
        for frame in [legacy_broadcast_frame(b"unrelated"), vec![0u8; 4]] {
            let verdict = probe
                .judge(
                    &frame,
                    &probes,
                    &mut TcpClient::new(),
                    &mut DialStation::new(DialMisbehaviour::Answers),
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
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
            .judge(
                &corrupt,
                &probes,
                &mut TcpClient::new(),
                &mut DialStation::new(DialMisbehaviour::Answers),
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("a stale checksum");
        assert!(verdict.contains("IPv4 checksum"), "{verdict}");

        let mut short_arp = arp_reply(&management, |_| {});
        short_arp.truncate(ARP_FRAME_LEN - 1);
        let verdict = probe
            .judge(
                &short_arp,
                &probes,
                &mut TcpClient::new(),
                &mut DialStation::new(DialMisbehaviour::Answers),
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
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

    /// The appliance's own initial sequence number for the onboarding
    /// connection, chosen here so the arithmetic the reset step does is visible.
    const ONBOARD_PEER_ISN: u32 = 0x7f00_0000;

    /// A segment the appliance sends on the onboarding connection, composed as
    /// it must compose one so a step can be driven and then moved a field at a
    /// time.
    fn onboard_answer(management: &ManagementPort, numbers: Numbers, flags: u8) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&pd_runtime::ONBOARDING_PORT.to_be_bytes());
        segment.extend_from_slice(&ONBOARD_STATION_PORT.to_be_bytes());
        segment.extend_from_slice(&numbers.sequence.to_be_bytes());
        segment.extend_from_slice(&numbers.acknowledgement.to_be_bytes());
        segment.push(5 << 4);
        segment.push(flags);
        segment.extend_from_slice(&8192u16.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
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

    /// A station driven to the step where it has abandoned the connection: the
    /// handshake, the payload, the acknowledgement covering it, and the reset
    /// this end answers that with.
    fn abandoned(probe: &ManagementProbe) -> OnboardStation {
        let mut station = OnboardStation::new(OnboardBehaviour::Abandons);
        station.open(&probe.port);
        station.step = probe
            .judge_onboard_tcp(
                &onboard_answer(
                    &probe.port,
                    Numbers {
                        sequence: ONBOARD_PEER_ISN,
                        acknowledgement: ONBOARD_STATION_ISN.wrapping_add(1),
                    },
                    TCP_SYN | TCP_ACK,
                ),
                &mut station,
            )
            .expect("the passive open");
        assert_eq!(station.step, OnboardStep::AwaitAck);
        station.step = probe
            .judge_onboard_tcp(
                &onboard_answer(
                    &probe.port,
                    Numbers {
                        sequence: ONBOARD_PEER_ISN.wrapping_add(1),
                        acknowledgement: station.sequence,
                    },
                    TCP_ACK,
                ),
                &mut station,
            )
            .expect("the acknowledgement of the payload");
        assert_eq!(station.step, OnboardStep::Reset);
        station
    }

    /// A reset does not overtake what the peer already put on the wire, so the
    /// close it had decided on for itself crosses it — and this station used to
    /// call that segment the appliance answering a connection it had been told
    /// to forget, which failed a boot on a peer behaving correctly.
    #[test]
    fn a_segment_already_travelling_when_the_onboarding_reset_went_out_is_not_misbehaviour() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut station = abandoned(&probe);

        // The FIN the appliance had composed for its own half, and a repeat of
        // the acknowledgement it already sent. Both carry numbers it had
        // reached, and neither may move the step or draw an answer.
        for flags in [TCP_FIN | TCP_ACK, TCP_ACK] {
            let owed = station.owed.len();
            let step = probe
                .judge_onboard_tcp(
                    &onboard_answer(
                        &probe.port,
                        Numbers {
                            sequence: ONBOARD_PEER_ISN.wrapping_add(1),
                            acknowledgement: station.sequence,
                        },
                        flags,
                    ),
                    &mut station,
                )
                .expect("a segment already travelling");
            assert_eq!(step, OnboardStep::Reset);
            assert_eq!(station.owed.len(), owed, "a reset station answers nothing");
        }
    }

    /// And the two shapes that are: a connection offered again, and sequence
    /// space the appliance had not reached when it was told to forget it.
    #[test]
    fn a_segment_the_appliance_composed_after_the_onboarding_reset_still_fails_the_boot() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);

        let mut station = abandoned(&probe);
        let verdict = probe
            .judge_onboard_tcp(
                &onboard_answer(
                    &probe.port,
                    Numbers {
                        sequence: ONBOARD_PEER_ISN,
                        acknowledgement: station.sequence,
                    },
                    TCP_SYN | TCP_ACK,
                ),
                &mut station,
            )
            .expect_err("a connection offered again");
        assert!(
            verdict.contains("offered the onboarding connection again"),
            "{verdict}"
        );

        let mut station = abandoned(&probe);
        let beyond = station.expect.wrapping_add(1);
        let verdict = probe
            .judge_onboard_tcp(
                &onboard_answer(
                    &probe.port,
                    Numbers {
                        sequence: beyond,
                        acknowledgement: station.sequence,
                    },
                    TCP_ACK,
                ),
                &mut station,
            )
            .expect_err("sequence space the appliance had not reached");
        assert!(verdict.contains("composed no further"), "{verdict}");
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
            station: DialStation::new(DialMisbehaviour::Answers),
            onboard: OnboardStation::new(OnboardBehaviour::Untouched),
            injected: ManagementInjection::default(),
        };
        let answered = DialContract::Answered;
        let judged = DialContract::Judged;
        let misbehaving = DialContract::Misbehaves(DialMisbehaviour::SilentToTheDial);
        assert!(!wire.answered(answered, false, false));
        assert!(!wire.stateless_replies_in());
        assert!(wire.outstanding().contains("ARP") && wire.outstanding().contains("echo"));

        wire.accept(ManagementReply::Arp).expect("the first");
        assert!(!wire.answered(answered, false, false));
        assert!(wire.outstanding().contains("ICMP echo reply"));
        let verdict = wire
            .accept(ManagementReply::Arp)
            .expect_err("one request is one reply");
        assert!(verdict.contains("a second"), "{verdict}");

        wire.accept(ManagementReply::Echo).expect("the second");
        // Both stateless replies are in, and the connection is still owed: that is
        // the point at which the client opens one.
        assert!(wire.stateless_replies_in());
        assert!(!wire.answered(answered, false, false));
        assert!(
            wire.outstanding()
                .contains("the TCP exchange has not been started")
        );

        // A TCP step is not a reply that may arrive twice: the connection's own
        // state machine orders its segments, so `accept` has nothing to refuse.
        wire.accept(ManagementReply::Tcp(TcpStep::AwaitSynAck))
            .expect("a step is not a reply");
        wire.client.step = TcpStep::Closed;
        // The dial is answered on every socket-backed wire and required on one
        // scenario, so a boot that does not judge it has met its contract here
        // and one that does still owes the whole exchange.
        assert!(wire.answered(answered, false, false));
        assert!(!wire.answered(judged, false, false));
        assert_eq!(
            wire.outstanding(),
            "the ARP request for the station it dials through"
        );
        // And a boot whose station misbehaves waits on neither: the exchange it
        // watches never closes, so what says the appliance has finished is the
        // appliance's own record of the channel.
        assert!(!wire.answered(misbehaving, false, false));
        assert!(wire.answered(misbehaving, true, false));
        wire.station.step = DialStep::Handshaken;
        assert!(wire.answered(judged, false, false));
        assert_eq!(wire.outstanding(), "none");
    }

    /// One segment of the connection the appliance dials, as this harness builds
    /// it to drive its own station: from the port's own pair at both layers, to
    /// the address the appliance is contracted to dial.
    fn dial_segment(
        management: &ManagementPort,
        peer_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut segment = Vec::with_capacity(TCP_HEADER_LEN + payload.len());
        segment.extend_from_slice(&peer_port.to_be_bytes());
        segment.extend_from_slice(&DIAL_PORT.to_be_bytes());
        segment.extend_from_slice(&sequence.to_be_bytes());
        segment.extend_from_slice(&acknowledgement.to_be_bytes());
        segment.push(5 << 4);
        segment.push(flags);
        segment.extend_from_slice(&CLIENT_WINDOW.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        segment.extend_from_slice(payload);
        let checksum = tcp_checksum(&management.address, &DIAL_DESTINATION, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + segment.len());
        frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
        frame.extend_from_slice(&management.mac);
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + segment.len()) as u16).to_be_bytes());
        ip[8] = INJECTED_TTL;
        ip[9] = TCP_PROTOCOL;
        ip[12..16].copy_from_slice(&management.address);
        ip[16..20].copy_from_slice(&DIAL_DESTINATION);
        let checksum = header_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&segment);
        frame
    }

    /// The ARP request the appliance asks its next hop with, as this harness
    /// builds it: broadcast at L2, from the port's own pair, asking about the
    /// station.
    fn dial_arp_request(management: &ManagementPort) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&management.mac);
        frame.extend_from_slice(&ARP_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&ARP_REQUEST.to_be_bytes());
        frame.extend_from_slice(&management.mac);
        frame.extend_from_slice(&management.address);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&management.station);
        frame
    }

    /// The whole of the station's side of a dial: the resolution, the handshake,
    /// the probe and both closes, each step asserting what came in and composing
    /// what goes back.
    ///
    /// The harness's own logic rather than the appliance's, which is what makes
    /// it worth a host test: a station that answered the wrong sequence number
    /// would fail a boot as an appliance defect, and the defect would be here.
    #[test]
    fn the_station_answers_a_dial_step_by_step_and_closes_it() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let probes: Vec<Probe> = Vec::new();
        let mut client = TcpClient::new();
        let mut station = DialStation::new(DialMisbehaviour::Answers);
        let peer_port = 0xabcd;
        let peer_isn = 0x1234_5678;

        assert_eq!(
            probe
                .judge(
                    &dial_arp_request(&management),
                    &probes,
                    &mut client,
                    &mut station,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("the appliance may ask about its next hop"),
            ManagementReply::Dial(DialStep::Resolved)
        );
        station.step = DialStep::Resolved;
        let reply = decode_arp(&station.owed.pop_front().expect("the station answers"))
            .expect("a well-formed ARP");
        assert_eq!(reply.operation, ARP_REPLY);
        assert_eq!(reply.sender_address, management.station);
        assert_eq!(reply.sender_mac, MANAGEMENT_STATION_MAC);
        assert_eq!(reply.target_address, management.address);

        assert_eq!(
            probe
                .judge(
                    &dial_segment(&management, peer_port, peer_isn, 0, TCP_SYN, &[]),
                    &probes,
                    &mut client,
                    &mut station,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("a SYN opens it"),
            ManagementReply::Dial(DialStep::Handshaken)
        );
        station.step = DialStep::Handshaken;
        let syn_ack = decode_tcp_to(
            &station.owed.pop_front().expect("the station answers"),
            &management,
            DIAL_DESTINATION,
        )
        .expect("a well-formed segment");
        assert!(syn_ack.carries(TCP_SYN | TCP_ACK, TCP_FIN));
        assert_eq!(syn_ack.acknowledgement, peer_isn.wrapping_add(1));
        assert_eq!(syn_ack.sequence, STATION_ISN);
        assert_eq!(syn_ack.destination_port, peer_port);

        // The handshake's third segment completes it and **nothing follows**:
        // the channel is a stream this appliance has nothing to put on, so the
        // connection is held from here. The station owes nothing back and its
        // step does not move.
        assert_eq!(
            probe
                .judge(
                    &dial_segment(
                        &management,
                        peer_port,
                        peer_isn.wrapping_add(1),
                        STATION_ISN.wrapping_add(1),
                        TCP_ACK,
                        &[]
                    ),
                    &probes,
                    &mut client,
                    &mut station,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("the acknowledgement completes the handshake"),
            ManagementReply::Dial(DialStep::Handshaken)
        );
        assert!(
            station.owed.is_empty(),
            "the station answered a connection it should merely hold"
        );
        assert!(station.completed());

        // And a byte on it is **taken and acknowledged**: the appliance speaks
        // first over the channel, so what arrives here is a TLS client hello and
        // this station's whole part is to keep the transport honest under a
        // session that waits for a server which never answers.
        let before = station.expect;
        probe
            .judge(
                &dial_segment(
                    &management,
                    peer_port,
                    peer_isn.wrapping_add(1),
                    STATION_ISN.wrapping_add(1),
                    TCP_ACK | TCP_PSH,
                    b"anything",
                ),
                &probes,
                &mut client,
                &mut station,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect("bytes on the channel are taken");
        assert_eq!(
            station.expect,
            before.wrapping_add(b"anything".len() as u32),
            "the station advanced over what it acknowledged"
        );
        assert_eq!(station.offered, b"anything".len());
        assert_eq!(
            station.owed.len(),
            1,
            "and answered with an acknowledgement"
        );
    }

    /// This station is exactly the peer that provokes a re-send: it answers on
    /// the run loop's schedule, one queued frame a pass, so the appliance's
    /// timer fires on a flight whose acknowledgement is still in this end's
    /// queue. It used to call the segment that comes back a stream out of place
    /// and fail the boot on it.
    #[test]
    fn a_re_sent_segment_of_the_dial_is_acknowledged_again_and_taken_once() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut station = DialStation::new(DialMisbehaviour::Answers);
        let peer_port = 0xabcd;
        // Close enough to the wrap that every offset the re-send rule takes
        // crosses it: raw comparison passes none of what follows.
        let peer_isn = 0xffff_ff00;
        let hello: &[u8] = b"a client hello";

        station.step = DialStep::Resolved;
        station.step = probe
            .judge_dial_tcp(
                &dial_segment(&management, peer_port, peer_isn, 0, TCP_SYN, &[]),
                &mut station,
            )
            .expect("a SYN opens it");
        let flight = dial_segment(
            &management,
            peer_port,
            peer_isn.wrapping_add(1),
            STATION_ISN.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            hello,
        );
        station.step = probe
            .judge_dial_tcp(&flight, &mut station)
            .expect("the session's first flight");
        let taken = station.expect;
        station.owed.clear();

        assert_eq!(
            probe.judge_dial_tcp(&flight, &mut station),
            Ok(DialStep::Handshaken)
        );
        assert_eq!(station.expect, taken, "a re-send moved the stream");
        assert_eq!(
            station.offered,
            hello.len(),
            "a re-send was counted as bytes offered"
        );
        assert_eq!(station.repeats, 1);
        let answer = decode_tcp_to(
            &station.owed.pop_front().expect("acknowledged again"),
            &management,
            DIAL_DESTINATION,
        )
        .expect("a well-formed segment");
        assert!(answer.carries(TCP_ACK, TCP_SYN | TCP_FIN));
        assert_eq!(answer.acknowledgement, taken);

        // And the tolerance is bounded on a count, which is what a peer that
        // never gets its flight across is.
        for _ in 1..DIAL_REPEAT_LIMIT {
            probe
                .judge_dial_tcp(&flight, &mut station)
                .expect("a re-send inside the bound");
        }
        let verdict = probe
            .judge_dial_tcp(&flight, &mut station)
            .expect_err("a peer that only repeats itself");
        assert!(
            verdict.contains("never gets its flight across"),
            "{verdict}"
        );
    }

    /// What the station refuses: a dial that never asked, a probe that is not
    /// the one the appliance is contracted to carry, and a resolution asked
    /// twice.
    #[test]
    fn the_station_refuses_a_dial_that_departs_from_the_contract() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let probes: Vec<Probe> = Vec::new();
        let mut client = TcpClient::new();

        let mut unasked = DialStation::new(DialMisbehaviour::Answers);
        let verdict = probe
            .judge(
                &dial_segment(&management, 0xabcd, 1, 0, TCP_SYN, &[]),
                &probes,
                &mut client,
                &mut unasked,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("a dial before the resolution is refused");
        assert!(verdict.contains("dialled before asking"), "{verdict}");

        let mut station = DialStation::new(DialMisbehaviour::Answers);
        probe
            .judge(
                &dial_arp_request(&management),
                &probes,
                &mut client,
                &mut station,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect("the request");
        station.step = DialStep::Resolved;
        // A next hop asked about again is answered again — an entry expires, and
        // a station that refused to answer would be the harness refusing what a
        // station is for. What is refused is asking without end.
        for _ in 0..DIAL_RESTART_LIMIT - 1 {
            probe
                .judge(
                    &dial_arp_request(&management),
                    &probes,
                    &mut client,
                    &mut station,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("a station answers for its own address whoever asks");
        }
        let verdict = probe
            .judge(
                &dial_arp_request(&management),
                &probes,
                &mut client,
                &mut station,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("asking without end is refused");
        assert!(verdict.contains("times"), "{verdict}");
        station.resolutions = 1;
        station.owed.clear();

        probe
            .judge(
                &dial_segment(&management, 0xabcd, 1, 0, TCP_SYN, &[]),
                &probes,
                &mut client,
                &mut station,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect("the SYN");
        station.step = DialStep::Handshaken;
        station.owed.clear();
        // A payload past the appliance's own outbound window, accumulated across
        // a boot's worth of attempts, is a node composing without end — which is
        // the one thing about the bytes on this channel a station that answers
        // nothing can still catch.
        station.offered = DIAL_OFFER_LIMIT;
        let verdict = probe
            .judge(
                &dial_segment(
                    &management,
                    0xabcd,
                    2,
                    STATION_ISN.wrapping_add(1),
                    TCP_ACK | TCP_PSH,
                    b"one byte past the window",
                ),
                &probes,
                &mut client,
                &mut station,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("a payload past the appliance's own window is refused");
        assert!(verdict.contains("composing without end"), "{verdict}");
    }

    /// Each misbehaviour puts the frame it is named for on the wire, and none of
    /// them moves the step.
    ///
    /// The harness's own logic again, and worth a host test for the reason the
    /// answering station's is: a mode that composed the wrong segment would fail
    /// a boot as an appliance defect, and the defect would be here — at the cost
    /// of a boot that spends minutes on a channel before saying so.
    #[test]
    fn each_misbehaviour_answers_a_dial_with_the_frame_it_is_named_for() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let probes: Vec<Probe> = Vec::new();
        let mut client = TcpClient::new();
        let peer_port = 0xabcd;
        let peer_isn = 0x1234_5678;

        // A station that answers the resolution and never the SYN owes nothing
        // at all, and leaves the appliance where it was.
        let mut silent = DialStation::new(DialMisbehaviour::SilentToTheDial);
        silent.step = DialStep::Resolved;
        assert_eq!(
            probe
                .judge(
                    &dial_segment(&management, peer_port, peer_isn, 0, TCP_SYN, &[]),
                    &probes,
                    &mut client,
                    &mut silent,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("the SYN is seen and not answered"),
            ManagementReply::Dial(DialStep::Resolved)
        );
        assert!(silent.owed.is_empty());
        assert_eq!(silent.dials, 1);

        // A station with nothing bound to that port answers with a reset that
        // acknowledges the SYN it really did receive — the one shape a peer must
        // believe.
        let mut refusing = DialStation::new(DialMisbehaviour::ResetsTheDial);
        refusing.step = DialStep::Resolved;
        assert_eq!(
            probe
                .judge(
                    &dial_segment(&management, peer_port, peer_isn, 0, TCP_SYN, &[]),
                    &probes,
                    &mut client,
                    &mut refusing,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("the SYN is refused"),
            ManagementReply::Dial(DialStep::Resolved)
        );
        let reset = decode_tcp_to(
            &refusing.owed.pop_front().expect("the station refuses"),
            &management,
            DIAL_DESTINATION,
        )
        .expect("a well-formed segment");
        assert!(reset.carries(TCP_RST | TCP_ACK, TCP_SYN | TCP_FIN));
        assert_eq!(reset.acknowledgement, peer_isn.wrapping_add(1));

        // A station that acknowledges a number this connection never occupied.
        let mut lying = DialStation::new(DialMisbehaviour::AcknowledgesTheWrongSequence);
        lying.step = DialStep::Resolved;
        assert_eq!(
            probe
                .judge(
                    &dial_segment(&management, peer_port, peer_isn, 0, TCP_SYN, &[]),
                    &probes,
                    &mut client,
                    &mut lying,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("the SYN is answered badly"),
            ManagementReply::Dial(DialStep::Resolved)
        );
        let handshake = decode_tcp_to(
            &lying.owed.pop_front().expect("the station answers"),
            &management,
            DIAL_DESTINATION,
        )
        .expect("a well-formed segment");
        assert!(handshake.carries(TCP_SYN | TCP_ACK, TCP_RST | TCP_FIN));
        assert_eq!(handshake.acknowledgement, UNSENT_ACKNOWLEDGEMENT);
        assert_ne!(handshake.acknowledgement, peer_isn.wrapping_add(1));

        // And a station that answers for somebody else resolves nothing: the
        // step stays where it was, so a SYN after it would be refused as one
        // addressed from an entry nothing on this link supplied.
        let mut impostor = DialStation::new(DialMisbehaviour::AnswersForAnotherAddress);
        assert_eq!(
            probe
                .judge(
                    &dial_arp_request(&management),
                    &probes,
                    &mut client,
                    &mut impostor,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("the request is answered by the wrong sender"),
            ManagementReply::Dial(DialStep::Unasked)
        );
        let reply = decode_arp(&impostor.owed.pop_front().expect("the station answers"))
            .expect("a well-formed ARP");
        assert_eq!(reply.operation, ARP_REPLY);
        assert_eq!(reply.sender_address, IMPOSTOR_ADDRESS);
        assert_eq!(reply.sender_mac, IMPOSTOR_MAC);
        assert_eq!(reply.source_mac, IMPOSTOR_MAC);
        assert_ne!(reply.sender_address, management.station);
        assert_eq!(reply.target_address, management.address);
    }

    /// The reset the appliance owes an acknowledgement of what it never sent is
    /// required where it is provoked, held to the number that was claimed, and
    /// refused everywhere else.
    #[test]
    fn the_appliances_reset_is_owed_by_one_station_and_refused_by_the_others() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let probes: Vec<Probe> = Vec::new();
        let mut client = TcpClient::new();
        let peer_port = 0xabcd;
        let reset = |sequence: u32, flags: u8| {
            dial_segment(&management, peer_port, sequence, 0, flags, &[])
        };

        let mut lying = DialStation::new(DialMisbehaviour::AcknowledgesTheWrongSequence);
        lying.step = DialStep::Resolved;
        lying.peer_port = Some(peer_port);
        assert_eq!(
            probe
                .judge(
                    &reset(UNSENT_ACKNOWLEDGEMENT, TCP_RST),
                    &probes,
                    &mut client,
                    &mut lying,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("the reset RFC 793 owes"),
            ManagementReply::Dial(DialStep::Resolved)
        );
        assert_eq!(lying.resets, 1);
        // Carrying some other number, which would be this end answering about a
        // connection nobody described.
        let verdict = probe
            .judge(
                &reset(UNSENT_ACKNOWLEDGEMENT.wrapping_add(1), TCP_RST),
                &probes,
                &mut client,
                &mut lying,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("a reset naming another number");
        assert!(
            verdict.contains("carries the number that was claimed"),
            "{verdict}"
        );
        // And conceding a sequence space it never entered.
        let verdict = probe
            .judge(
                &reset(UNSENT_ACKNOWLEDGEMENT, TCP_RST | TCP_ACK),
                &probes,
                &mut client,
                &mut lying,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("a reset that acknowledges");
        assert!(verdict.contains("acknowledges nothing"), "{verdict}");

        // Every other station is entitled to none: a reset there is a connection
        // the appliance tore down, including where a dial was abandoned — the
        // transport composes none for a handshake that never completed.
        for misbehaviour in [
            DialMisbehaviour::Answers,
            DialMisbehaviour::SilentToTheDial,
            DialMisbehaviour::ResetsTheDial,
            DialMisbehaviour::AnswersForAnotherAddress,
        ] {
            let mut station = DialStation::new(misbehaviour);
            station.step = DialStep::Resolved;
            let verdict = probe
                .judge(
                    &reset(UNSENT_ACKNOWLEDGEMENT, TCP_RST),
                    &probes,
                    &mut client,
                    &mut station,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect_err("no station but one is owed a reset");
            assert!(
                verdict.contains("reset the connection it dialled"),
                "{verdict}"
            );
        }
    }

    /// Each misbehaviour bounds the appliance by the arithmetic of the
    /// appliance's own constants, and a node past that bound is reported.
    #[test]
    fn a_misbehaving_station_bounds_what_the_appliance_may_spend() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let probes: Vec<Probe> = Vec::new();
        let mut client = TcpClient::new();

        // Three sessions, each with a SYN and five re-sends of it, is every SYN
        // that may ever cross this wire.
        let mut silent = DialStation::new(DialMisbehaviour::SilentToTheDial);
        silent.step = DialStep::Resolved;
        for _ in 0..DIAL_SYNS_WHILE_UNANSWERED {
            probe
                .judge(
                    &dial_segment(&management, 0xabcd, 1, 0, TCP_SYN, &[]),
                    &probes,
                    &mut client,
                    &mut silent,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("a SYN under the appliance's own bounds");
        }
        let verdict = probe
            .judge(
                &dial_segment(&management, 0xabcd, 1, 0, TCP_SYN, &[]),
                &probes,
                &mut client,
                &mut silent,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("one more is a bound not holding");
        assert!(
            verdict.contains("SYNs have reached this station"),
            "{verdict}"
        );

        // Three sessions, each asking about the next hop three times, is every
        // request the neighbour cache may make of an address nothing claims.
        let mut impostor = DialStation::new(DialMisbehaviour::AnswersForAnotherAddress);
        for _ in 0..DIAL_REQUESTS_WHILE_UNRESOLVED {
            probe
                .judge(
                    &dial_arp_request(&management),
                    &probes,
                    &mut client,
                    &mut impostor,
                    &mut OnboardStation::new(OnboardBehaviour::Untouched),
                )
                .expect("a request under the cache's own bound");
        }
        let verdict = probe
            .judge(
                &dial_arp_request(&management),
                &probes,
                &mut client,
                &mut impostor,
                &mut OnboardStation::new(OnboardBehaviour::Untouched),
            )
            .expect_err("one more is a cache that is not giving up");
        assert!(verdict.contains("times"), "{verdict}");
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

    /// The appliance's own initial sequence number for the scrape connection,
    /// chosen so close to the wrap that every offset the repeat rule takes
    /// crosses it: an implementation comparing raw sequence numbers with `<`
    /// passes none of the tests below.
    const SCRAPE_PEER_ISN: u32 = 0xffff_ff00;

    /// A client driven to the step where its request is out and the appliance
    /// owes the response: the open, the passive open answering it, and the
    /// acknowledgement that carries the request.
    fn handshaken(probe: &ManagementProbe, management: &ManagementPort) -> TcpClient {
        let mut client = TcpClient::new();
        probe.advance(&mut client).expect("the client's own SYN");
        let syn_ack = appliance_segment(
            management,
            SCRAPE_PEER_ISN,
            CLIENT_ISN.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            &[],
        );
        client.step = probe
            .judge_tcp(&syn_ack, &mut client)
            .expect("the passive open");
        probe.advance(&mut client).expect("the request");
        assert_eq!(client.step, TcpStep::AwaitResponse);
        client
    }

    /// The passive open this appliance re-sends because this end's
    /// acknowledgement has not reached it yet.
    fn passive_open_again(management: &ManagementPort) -> Vec<u8> {
        appliance_segment(
            management,
            SCRAPE_PEER_ISN,
            CLIENT_ISN.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            &[],
        )
    }

    /// An appliance whose retransmission timer fires before this end's
    /// acknowledgement reaches it re-sends its passive open, and that is a peer
    /// working — this step used to call it a peer answering an established
    /// connection with an offer to establish it, and fail the boot on it.
    #[test]
    fn a_re_sent_passive_open_is_answered_with_the_request_again() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut client = handshaken(&probe, &management);

        let again = passive_open_again(&management);
        assert_eq!(
            probe.judge_tcp(&again, &mut client),
            Ok(TcpStep::AwaitResponse)
        );
        assert_eq!(
            client.expect,
            SCRAPE_PEER_ISN.wrapping_add(1),
            "a segment carrying nothing new moved the stream"
        );
        assert!(client.response.is_empty());
        assert_eq!(client.repeats, 1);

        // And what goes back is the request again rather than a bare
        // acknowledgement: the appliance never took it, so a client that only
        // completed the handshake would wait out its whole budget for a
        // response to a request nobody has.
        let answer = probe.advance(&mut client).expect("the request again");
        let sent = decode_tcp(&answer, &management).expect("it re-parses");
        assert_eq!(sent.payload, TCP_REQUEST);
        assert_eq!(sent.acknowledgement, SCRAPE_PEER_ISN.wrapping_add(1));
        assert_eq!(client.step, TcpStep::AwaitResponse);
    }

    /// And the four shapes that are not the passive open re-sent, each of which
    /// is an appliance offering to establish a connection it is already
    /// carrying. This is what the check at this step exists for, and it still
    /// catches every one of them.
    #[test]
    fn a_passive_open_that_is_not_the_one_already_seen_still_fails_the_boot() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let head = response_of(64);

        // A second passive open at a number of its own, before anything of the
        // response has arrived: it is not a re-send of the one already seen.
        let mut client = handshaken(&probe, &management);
        let verdict = probe
            .judge_tcp(
                &appliance_segment(
                    &management,
                    SCRAPE_PEER_ISN.wrapping_add(3),
                    CLIENT_ISN.wrapping_add(1),
                    TCP_SYN | TCP_ACK,
                    &[],
                ),
                &mut client,
            )
            .expect_err("a passive open at a new number");
        assert!(verdict.contains("owes an ACK with no SYN"), "{verdict}");

        // A re-send claiming to have taken more than the client's own `SYN`,
        // which an appliance still owed a passive open cannot have.
        let mut client = handshaken(&probe, &management);
        let verdict = probe
            .judge_tcp(
                &appliance_segment(
                    &management,
                    SCRAPE_PEER_ISN,
                    TcpClient::sent_through_request(),
                    TCP_SYN | TCP_ACK,
                    &[],
                ),
                &mut client,
            )
            .expect_err("a re-send acknowledging the request");
        assert!(
            verdict.contains("still offering the handshake"),
            "{verdict}"
        );

        // The two that need the connection to have gone past the handshake: a
        // byte of the response proves this end's acknowledgement arrived.
        for (sequence, expected) in [
            (SCRAPE_PEER_ISN, "already answered up to"),
            (
                SCRAPE_PEER_ISN.wrapping_add(5),
                "initial sequence number was",
            ),
        ] {
            let mut client = handshaken(&probe, &management);
            client.step = probe
                .judge_tcp(
                    &appliance_segment(
                        &management,
                        SCRAPE_PEER_ISN.wrapping_add(1),
                        TcpClient::sent_through_request(),
                        TCP_ACK | TCP_PSH,
                        &head,
                    ),
                    &mut client,
                )
                .expect("the response opening");
            let verdict = probe
                .judge_tcp(
                    &appliance_segment(
                        &management,
                        sequence,
                        CLIENT_ISN.wrapping_add(1),
                        TCP_SYN | TCP_ACK,
                        &[],
                    ),
                    &mut client,
                )
                .expect_err("a SYN on a connection that completed its handshake");
            assert!(verdict.contains(expected), "{verdict}");
        }
    }

    /// A response segment and a close re-sent because their acknowledgement had
    /// not reached the appliance are taken once, not twice: the stream is what
    /// it was, and neither step moves.
    #[test]
    fn a_re_sent_response_segment_and_close_are_taken_once() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut client = handshaken(&probe, &management);
        let response = response_of(200);
        let owed = TcpClient::sent_through_request();
        let (head, tail) = response.split_at(80);
        let tail_at = SCRAPE_PEER_ISN.wrapping_add(1 + head.len() as u32);

        let opening = appliance_segment(
            &management,
            SCRAPE_PEER_ISN.wrapping_add(1),
            owed,
            TCP_ACK | TCP_PSH,
            head,
        );
        client.step = probe
            .judge_tcp(&opening, &mut client)
            .expect("the response opening");

        // The same segment again, its acknowledgement still in the queue.
        assert_eq!(
            probe.judge_tcp(&opening, &mut client),
            Ok(TcpStep::AwaitResponse)
        );
        assert_eq!(client.response, head, "a re-send was taken twice");
        assert_eq!(client.expect, tail_at, "a re-send moved the stream");

        // The rest of it and the close, then the whole of that segment again.
        let closing = appliance_segment(
            &management,
            tail_at,
            owed,
            TCP_ACK | TCP_PSH | TCP_FIN,
            tail,
        );
        client.step = probe.judge_tcp(&closing, &mut client).expect("the close");
        probe.advance(&mut client).expect("the client's own FIN");
        assert_eq!(client.step, TcpStep::AwaitLastAck);
        assert_eq!(
            probe.judge_tcp(&closing, &mut client),
            Ok(TcpStep::AwaitLastAck),
            "a close re-sent after this end answered it is not a second close"
        );
        assert_eq!(client.response, response, "a re-send was taken twice");
        assert_eq!(client.repeats, 2);
        assert_eq!(
            probe.advance(&mut client),
            None,
            "a station that has answered a close owes nothing more"
        );

        // The final acknowledgement still closes the exchange over it.
        let last_ack = appliance_segment(
            &management,
            client.expect,
            owed.wrapping_add(1),
            TCP_ACK,
            &[],
        );
        assert_eq!(probe.judge_tcp(&last_ack, &mut client), Ok(TcpStep::Closed));
    }

    /// A peer answering one sequence number with two different bytes has not
    /// re-sent a segment, it has sent a second stream — and a stream is what
    /// this connection is judged as.
    #[test]
    fn a_re_send_whose_bytes_differ_still_fails_the_boot() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut client = handshaken(&probe, &management);
        let head = response_of(64);
        let owed = TcpClient::sent_through_request();

        client.step = probe
            .judge_tcp(
                &appliance_segment(
                    &management,
                    SCRAPE_PEER_ISN.wrapping_add(1),
                    owed,
                    TCP_ACK | TCP_PSH,
                    &head,
                ),
                &mut client,
            )
            .expect("the response opening");

        let mut altered = head.clone();
        altered.splice(9..12, b"503".iter().copied());
        let verdict = probe
            .judge_tcp(
                &appliance_segment(
                    &management,
                    SCRAPE_PEER_ISN.wrapping_add(1),
                    owed,
                    TCP_ACK | TCP_PSH,
                    &altered,
                ),
                &mut client,
            )
            .expect_err("a second stream at the same numbers");
        assert!(verdict.contains("not the bytes it sent there"), "{verdict}");

        // The acknowledgement is the one field a re-send composes afresh, and
        // it is held to what this client has actually sent here as it is at
        // every step.
        let verdict = probe
            .judge_tcp(
                &appliance_segment(
                    &management,
                    SCRAPE_PEER_ISN.wrapping_add(1),
                    owed.wrapping_add(9),
                    TCP_ACK | TCP_PSH,
                    &head,
                ),
                &mut client,
            )
            .expect_err("a re-send acknowledging bytes nobody sent");
        assert!(verdict.contains("bytes nobody sent"), "{verdict}");
    }

    /// The tolerance is bounded on a count, which is what a peer that only ever
    /// repeats itself is: it never finishes the exchange, and a client that
    /// simply went on answering could not tell that from a slow machine.
    #[test]
    fn an_appliance_that_only_re_sends_fails_on_the_count() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut client = handshaken(&probe, &management);
        let again = passive_open_again(&management);

        for _ in 0..CLIENT_REPEAT_LIMIT {
            probe
                .judge_tcp(&again, &mut client)
                .expect("a re-send inside the bound");
        }
        let verdict = probe
            .judge_tcp(&again, &mut client)
            .expect_err("a peer that only repeats itself");
        assert!(verdict.contains("never finishes"), "{verdict}");
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

    /// A repeat between boots that are not neighbours, which is the same
    /// injection primitive and passed a comparison of adjacent pairs alone.
    #[test]
    fn a_repeated_sequence_number_between_non_adjacent_boots_is_refused() {
        let verdict = crate::qemu::judge_sequence_numbers(&[("a", 9), ("b", 4), ("c", 9)])
            .expect_err("the first and last boots agreed");
        assert!(verdict.contains("scenarios a and c"), "{verdict}");
        assert!(verdict.contains('9'), "{verdict}");
    }

    /// The count reported is of *values*: naming boots under the word
    /// "distinct" is the claim that outlived the comparison behind it.
    #[test]
    fn the_reported_count_is_of_distinct_values_not_of_boots() {
        let four = crate::qemu::judge_sequence_numbers(&[("a", 1), ("b", 2), ("c", 3), ("d", 4)])
            .expect("four distinct numbers");
        assert!(four.contains("4 distinct"), "{four}");
        assert!(four.contains("4 boot(s)"), "{four}");
        let one = crate::qemu::judge_sequence_numbers(&[("a", 5)]).expect("one boot, one number");
        assert!(one.contains("1 distinct"), "{one}");
    }

    /// One segment the appliance's onboarding port sends back to this harness's
    /// station, as the appliance would compose it.
    fn onboard_reply(
        management: &ManagementPort,
        destination: u16,
        numbers: Numbers,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut segment = Vec::with_capacity(TCP_HEADER_LEN + payload.len());
        segment.extend_from_slice(&pd_runtime::ONBOARDING_PORT.to_be_bytes());
        segment.extend_from_slice(&destination.to_be_bytes());
        segment.extend_from_slice(&numbers.sequence.to_be_bytes());
        segment.extend_from_slice(&numbers.acknowledgement.to_be_bytes());
        segment.push(5 << 4);
        segment.push(flags);
        segment.extend_from_slice(&STATION_WINDOW.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        segment.extend_from_slice(payload);
        let checksum = tcp_checksum(&management.address, &management.station, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + segment.len());
        frame.extend_from_slice(&MANAGEMENT_STATION_MAC);
        frame.extend_from_slice(&management.mac);
        frame.extend_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + segment.len()) as u16).to_be_bytes());
        ip[8] = INJECTED_TTL;
        ip[9] = TCP_PROTOCOL;
        ip[12..16].copy_from_slice(&management.address);
        ip[16..20].copy_from_slice(&management.station);
        let checksum = header_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&segment);
        frame
    }

    /// The appliance's initial sequence number for the onboarding connection in
    /// these tests. Arbitrary, and read off the wire by the station exactly as a
    /// real one is.
    const PORT_ISN: u32 = 0x77aa_0031;

    /// Drive one station through the handshake and its payload, answering as the
    /// appliance's port would, and hand back what it owes the wire after the
    /// payload has been acknowledged.
    fn onboard_through_the_payload(
        probe: &ManagementProbe,
        management: &ManagementPort,
        station: &mut OnboardStation,
    ) {
        station.open(management);
        let syn = decode_tcp(
            &station.owed.pop_front().expect("the station opens"),
            management,
        )
        .expect("a well-formed segment");
        assert!(syn.carries(TCP_SYN, TCP_ACK | TCP_RST | TCP_FIN));
        assert_eq!(syn.source_port, ONBOARD_STATION_PORT);
        assert_eq!(syn.destination_port, pd_runtime::ONBOARDING_PORT);
        assert_eq!(syn.sequence, ONBOARD_STATION_ISN);

        let step = probe
            .judge_onboard_tcp(
                &onboard_reply(
                    management,
                    ONBOARD_STATION_PORT,
                    Numbers {
                        sequence: PORT_ISN,
                        acknowledgement: ONBOARD_STATION_ISN.wrapping_add(1),
                    },
                    TCP_SYN | TCP_ACK,
                    &[],
                ),
                station,
            )
            .expect("the port answers the open");
        assert_eq!(step, OnboardStep::AwaitAck);
        station.step = step;
        let payload = decode_tcp(
            &station.owed.pop_front().expect("the station delivers"),
            management,
        )
        .expect("a well-formed segment");
        // One segment carrying the whole payload, which is what makes the
        // length both domains report a number this end decided.
        assert!(payload.carries(TCP_ACK | TCP_PSH, TCP_SYN | TCP_RST | TCP_FIN));
        assert_eq!(payload.payload, ONBOARD_PAYLOAD);
        assert_eq!(payload.acknowledgement, PORT_ISN.wrapping_add(1));
        assert_eq!(station.delivered, ONBOARD_PAYLOAD.len() as u64);

        let acknowledged = ONBOARD_STATION_ISN
            .wrapping_add(1)
            .wrapping_add(ONBOARD_PAYLOAD.len() as u32);
        let step = probe
            .judge_onboard_tcp(
                &onboard_reply(
                    management,
                    ONBOARD_STATION_PORT,
                    Numbers {
                        sequence: PORT_ISN.wrapping_add(1),
                        acknowledgement: acknowledged,
                    },
                    TCP_ACK,
                    &[],
                ),
                station,
            )
            .expect("the port acknowledges the payload");
        station.step = step;
    }

    /// Each station ends its session with the segment it is named for, and the
    /// crowding one opens its second connection before it does.
    ///
    /// The harness's own logic, and worth a host test for the reason the dial
    /// station's modes are: a station composing the wrong segment would fail a
    /// boot as an appliance defect, and the defect would be here — at the cost of
    /// a whole boot to find out.
    #[test]
    fn each_onboarding_station_ends_its_session_with_the_segment_it_is_named_for() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let acknowledged = ONBOARD_STATION_ISN
            .wrapping_add(1)
            .wrapping_add(ONBOARD_PAYLOAD.len() as u32);

        // The station that closes: a `FIN` carrying an acknowledgement, and
        // nothing else owed.
        let mut completing = OnboardStation::new(OnboardBehaviour::Completes);
        onboard_through_the_payload(&probe, &management, &mut completing);
        assert_eq!(completing.step, OnboardStep::AwaitFin);
        let fin = decode_tcp(
            &completing.owed.pop_front().expect("the station closes"),
            &management,
        )
        .expect("a well-formed segment");
        assert!(fin.carries(TCP_FIN | TCP_ACK, TCP_SYN | TCP_RST));
        assert_eq!(fin.sequence, acknowledged);
        assert!(completing.owed.is_empty());
        assert!(!completing.crowded);

        // The station that resets: a bare `RST` at the number the appliance
        // expects next, carrying no acknowledgement — this end is abandoning a
        // connection rather than agreeing anything about it.
        let mut abandoning = OnboardStation::new(OnboardBehaviour::Abandons);
        onboard_through_the_payload(&probe, &management, &mut abandoning);
        assert_eq!(abandoning.step, OnboardStep::Reset);
        let reset = decode_tcp(
            &abandoning.owed.pop_front().expect("the station resets"),
            &management,
        )
        .expect("a well-formed segment");
        assert!(reset.carries(TCP_RST, TCP_ACK | TCP_SYN | TCP_FIN));
        assert_eq!(reset.sequence, acknowledged);
        assert!(abandoning.owed.is_empty());

        // And the station that crowds: the second connection's `SYN` from a port
        // of its own, ahead of the close, so the connection it crowds is one the
        // appliance has certainly established — it has just answered on it.
        let mut crowding = OnboardStation::new(OnboardBehaviour::Crowds);
        onboard_through_the_payload(&probe, &management, &mut crowding);
        assert_eq!(crowding.step, OnboardStep::AwaitFin);
        assert!(crowding.crowded);
        let second = decode_tcp(
            &crowding.owed.pop_front().expect("the station crowds"),
            &management,
        )
        .expect("a well-formed segment");
        assert!(second.carries(TCP_SYN, TCP_ACK | TCP_RST | TCP_FIN));
        assert_eq!(second.source_port, ONBOARD_CROWD_PORT);
        assert_ne!(second.source_port, ONBOARD_STATION_PORT);
        assert_eq!(second.sequence, ONBOARD_CROWD_ISN);
        let closing = decode_tcp(
            &crowding.owed.pop_front().expect("and then closes"),
            &management,
        )
        .expect("a well-formed segment");
        assert!(closing.carries(TCP_FIN | TCP_ACK, TCP_SYN | TCP_RST));
        assert!(crowding.owed.is_empty());
    }

    /// Any answer at all to the second connection is refused and counted, which
    /// is the crowding scenario's whole claim.
    #[test]
    fn every_shape_of_answer_to_the_second_connection_is_refused() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        // A handshake, a reset acknowledging the `SYN`, and a bare
        // acknowledgement: three different things a port with no slot might say,
        // and it owes none of them.
        for (flags, named) in [
            (TCP_SYN | TCP_ACK, "a handshake"),
            (TCP_RST | TCP_ACK, "a refusal"),
            (TCP_ACK, "an acknowledgement"),
        ] {
            let mut station = OnboardStation::new(OnboardBehaviour::Crowds);
            onboard_through_the_payload(&probe, &management, &mut station);
            let verdict = probe
                .judge_onboard_tcp(
                    &onboard_reply(
                        &management,
                        ONBOARD_CROWD_PORT,
                        Numbers {
                            sequence: 0,
                            acknowledgement: ONBOARD_CROWD_ISN.wrapping_add(1),
                        },
                        flags,
                        &[],
                    ),
                    &mut station,
                )
                .expect_err(named);
            assert!(verdict.contains("second connection's SYN"), "{verdict}");
            // And it is counted as well as refused, so the station's own account
            // can state the zero rather than leaving it to be inferred.
            assert_eq!(station.crowd_answers, 1);
        }
    }

    /// The whole close: the appliance's own `FIN` is acknowledged and the
    /// exchange is complete, and a byte back on the connection is refused —
    /// which is what makes both accounts' `sent` a fact rather than a
    /// placeholder.
    #[test]
    fn the_appliance_close_is_acknowledged_and_a_byte_back_is_refused() {
        let management = bench().management();
        let (probe, _) = ManagementProbe::new(management);
        let mut station = OnboardStation::new(OnboardBehaviour::Completes);
        onboard_through_the_payload(&probe, &management, &mut station);
        station.owed.clear();
        let acknowledged = ONBOARD_STATION_ISN
            .wrapping_add(1)
            .wrapping_add(ONBOARD_PAYLOAD.len() as u32)
            .wrapping_add(1);

        // A byte on this port is a byte nothing above it composed.
        let verdict = probe
            .judge_onboard_tcp(
                &onboard_reply(
                    &management,
                    ONBOARD_STATION_PORT,
                    Numbers {
                        sequence: PORT_ISN.wrapping_add(1),
                        acknowledgement: acknowledged,
                    },
                    TCP_ACK,
                    b"hello",
                ),
                &mut station,
            )
            .expect_err("a byte the terminating domain never answered with");
        assert!(verdict.contains("5 byte(s)"), "{verdict}");

        // And the close itself, acknowledged.
        let step = probe
            .judge_onboard_tcp(
                &onboard_reply(
                    &management,
                    ONBOARD_STATION_PORT,
                    Numbers {
                        sequence: PORT_ISN.wrapping_add(1),
                        acknowledgement: acknowledged,
                    },
                    TCP_FIN | TCP_ACK,
                    &[],
                ),
                &mut station,
            )
            .expect("the appliance closes");
        assert_eq!(step, OnboardStep::Closed);
        station.step = step;
        assert!(station.completed());
        let last = decode_tcp(
            &station.owed.pop_front().expect("the station acknowledges"),
            &management,
        )
        .expect("a well-formed segment");
        assert!(last.carries(TCP_ACK, TCP_SYN | TCP_RST | TCP_FIN));
        assert_eq!(last.acknowledgement, PORT_ISN.wrapping_add(2));
    }

    /// A boot that opens nothing on that port owes nothing there, which is what
    /// keeps every other scenario byte-for-byte unaffected.
    #[test]
    fn a_station_that_opens_nothing_puts_no_frame_on_the_wire() {
        let management = bench().management();
        let mut station = OnboardStation::new(OnboardBehaviour::Untouched);
        station.open(&management);
        assert!(station.owed.is_empty());
        assert_eq!(station.step, OnboardStep::Unopened);
        assert!(station.completed());

        assert!(station.seen().contains("opens no onboarding session"));
    }
}
