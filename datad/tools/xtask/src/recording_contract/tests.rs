use super::*;

/// Compose one pcapng block: type, total length, body, total length again.
///
/// Reachable beyond this module because [`crate::data_disk`] composes the same
/// bytes onto a synthetic disk image, and two composers would be two statements
/// of one format.
pub(crate) fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let len = BLOCK_FRAMING_LEN + body.len();
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out
}

pub(crate) fn section_header() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&u64::MAX.to_le_bytes());
    block(SECTION_HEADER_BLOCK, &body)
}

pub(crate) fn interface_description() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&2048u32.to_le_bytes());
    block(INTERFACE_DESCRIPTION_BLOCK, &body)
}

pub(crate) fn enhanced_packet(captured: usize) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&(captured as u32).to_le_bytes());
    body.extend_from_slice(&(captured as u32).to_le_bytes());
    body.resize(body.len() + captured.next_multiple_of(4), 0);
    block(ENHANCED_PACKET_BLOCK, &body)
}

pub(crate) fn recording(packets: usize, captured: usize) -> Vec<u8> {
    let mut bytes = section_header();
    bytes.extend_from_slice(&interface_description());
    for _ in 0..packets {
        bytes.extend_from_slice(&enhanced_packet(captured));
    }
    bytes
}

fn answered(body: Vec<u8>) -> Download {
    Download {
        target: TARGET,
        command: String::from("curl (synthetic)"),
        status_line: String::from("HTTP/1.1 200 OK"),
        headers: vec![format!("Content-Length: {}", body.len())],
        body,
    }
}

/// The recording every case here stands for, named once so a download and the
/// contract it is judged against cannot drift apart.
const TARGET: &str = "/logs.pcapng";

fn expectation() -> Expectation {
    Expectation {
        target: TARGET,
        snap_len: 128,
        least_packets: 3,
    }
}

/// One Enhanced Packet Block carrying the two options a decision travels in: the
/// standard verdict, and the PEN-tagged annotation.
fn annotated_packet(captured: usize, verdict: u8, annotation: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&(captured as u32).to_le_bytes());
    body.extend_from_slice(&(captured as u32).to_le_bytes());
    body.resize(body.len() + captured.next_multiple_of(4), 0);
    // `epb_packetid`, so the block is one a reader can relate.
    body.extend_from_slice(&EPB_PACKETID.to_le_bytes());
    body.extend_from_slice(&8u16.to_le_bytes());
    body.extend_from_slice(&7u64.to_le_bytes());
    // `epb_verdict`: the kind octet, then what that kind means.
    body.extend_from_slice(&EPB_VERDICT.to_le_bytes());
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&[VERDICT_KIND, verdict, 0, 0]);
    // The custom option: the enterprise number, then the annotation.
    body.extend_from_slice(&CUSTOM_BINARY_COPYABLE.to_le_bytes());
    body.extend_from_slice(&((4 + annotation.len()) as u16).to_le_bytes());
    body.extend_from_slice(&UNREGISTERED_PEN.to_le_bytes());
    body.extend_from_slice(annotation);
    body.extend_from_slice(&OPT_END_OF_OPT.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    block(ENHANCED_PACKET_BLOCK, &body)
}

/// The 24 octets of a sound annotation, written out here rather than composed
/// through the encoder's own constants: this walk is a *reader*, and one that
/// shared the writer's layout could not tell a shifted field from a correct file.
fn annotation_bytes() -> Vec<u8> {
    let mut bytes = vec![
        ANNOTATION_VERSION,
        VERDICT_FORWARDED,
        0,
        1,
        0,
        CLASSIFICATION_ESTABLISHED,
        EVENT_FLOW_CLOSED,
        STATE_TIME_WAIT,
    ];
    bytes.extend_from_slice(&9u32.to_le_bytes());
    bytes.extend_from_slice(&4_321u32.to_le_bytes());
    bytes.extend_from_slice(&17u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

/// **Every field of the decision, read back off the bytes.** This is the whole of
/// what makes a record say why rather than only what, so it is read at the
/// offsets a reader outside the appliance navigates by.
#[test]
fn a_decision_is_read_back_out_of_the_block_it_rides_in() {
    let annotation = annotation_bytes();
    assert_eq!(annotation.len(), ANNOTATION_LEN);
    let mut body = section_header();
    body.extend_from_slice(&interface_description());
    body.extend_from_slice(&annotated_packet(64, VERDICT_FORWARDED, &annotation));

    let parsed = parse(&body).expect("a well-formed file");
    assert_eq!(parsed.consumed, body.len());
    let packet = parsed.packets.first().expect("one packet block");
    assert_eq!(
        packet.verdict.as_deref(),
        Some([VERDICT_KIND, 0].as_slice())
    );
    let found = packet.annotation.expect("the annotation option");
    assert_eq!(found.version, ANNOTATION_VERSION);
    assert_eq!(found.verdict, VERDICT_FORWARDED);
    assert_eq!(found.drop_reason, 0);
    assert_eq!(found.interface_id, 1);
    assert_eq!(found.direction, 0);
    assert_eq!(found.classification, CLASSIFICATION_ESTABLISHED);
    assert_eq!(found.event, EVENT_FLOW_CLOSED);
    assert_eq!(found.flow_state, STATE_TIME_WAIT);
    assert_eq!(found.configuration_generation, 9);
    assert_eq!(found.identity(), (4_321, 17));
    assert!(found.names_a_flow());
    assert_eq!(found.rule_position(), None, "zero names no rule");
    assert_eq!(event_name(found.event), "flow-closed");
    assert_eq!(classification_name(found.classification), "established");
}

/// A rule is carried one higher than its position, so the first rule of a
/// generation is distinguishable from no rule at all.
#[test]
fn a_rule_is_read_back_as_its_position_and_zero_as_no_rule() {
    for (encoded, position) in [(0u16, None), (1, Some(0)), (2, Some(1)), (256, Some(255))] {
        let mut annotation = annotation_bytes();
        annotation[20..22].copy_from_slice(&encoded.to_le_bytes());
        let mut body = section_header();
        body.extend_from_slice(&interface_description());
        body.extend_from_slice(&annotated_packet(64, VERDICT_FORWARDED, &annotation));
        let parsed = parse(&body).expect("a well-formed file");
        let found = parsed.packets[0].annotation.expect("the annotation");
        assert_eq!(found.rule_position(), position);
    }
}

/// An annotation under somebody else's enterprise number is not this layout, and
/// reading it as one would decode another organisation's bytes as a verdict.
#[test]
fn a_custom_option_under_another_enterprise_number_is_not_read() {
    let annotation = annotation_bytes();
    let mut body = section_header();
    body.extend_from_slice(&interface_description());
    let mut packet = annotated_packet(64, VERDICT_FORWARDED, &annotation);
    // The PEN sits at the option's own first four octets; find it and change it.
    let at = packet
        .windows(4)
        .position(|window| window == UNREGISTERED_PEN.to_le_bytes())
        .expect("the option carries the enterprise number");
    packet[at..at + 4].copy_from_slice(&32_473u32.to_le_bytes());
    body.extend_from_slice(&packet);

    let parsed = parse(&body).expect("a well-formed file");
    assert_eq!(parsed.packets[0].annotation, None);
}

/// An annotation of a length this layout version does not carry, which is what a
/// reader must refuse rather than pad or truncate into a plausible decision.
#[test]
fn an_annotation_of_the_wrong_length_is_not_read_as_this_layout() {
    for len in [ANNOTATION_LEN - 4, ANNOTATION_LEN + 4] {
        let mut annotation = annotation_bytes();
        annotation.resize(len, 0);
        let mut body = section_header();
        body.extend_from_slice(&interface_description());
        body.extend_from_slice(&annotated_packet(64, VERDICT_FORWARDED, &annotation));
        let parsed = parse(&body).expect("a well-formed file");
        assert_eq!(parsed.packets[0].annotation, None, "at {len} octets");
    }
}

/// **The connection history's snap length is derived, not chosen.** It holds the
/// largest L2–L4 header chain this appliance ever reaches a decision on and
/// nothing of the payload, and this is where that number is held to the widths it
/// is derived from.
#[test]
fn the_connection_historys_snap_length_holds_the_longest_header_chain_whole() {
    // An Ethernet header, an 802.1Q tag, an IPv4 header with no options — the
    // parser refuses one that carries them — and a TCP header with a full option
    // area, which is the most a data offset of fifteen words can name.
    let longest = net_headers::ETHERNET_HEADER_LEN
        + net_headers::VLAN_TAG_LEN
        + net_headers::IPV4_HEADER_LEN
        + 15 * 4;
    assert_eq!(longest, 98);
    assert!(
        lfw_recorder::deck::LOG_SNAP_LEN as usize >= longest,
        "the connection history keeps {} bytes and the longest header chain the appliance \
         decides on is {longest}, so a record could carry a decision taken on bytes it does not \
         hold",
        lfw_recorder::deck::LOG_SNAP_LEN
    );
    // And it holds nothing of a payload: the capture is what carries traffic, and
    // widening the payload exception past it is a design change. A `const` block
    // rather than an assertion, both being build-time constants.
    const _: () = assert!(
        lfw_recorder::deck::LOG_SNAP_LEN < lfw_recorder::deck::CAPTURE_SNAP_LEN,
        "the two recordings would keep the same bytes"
    );
}

#[test]
fn a_whole_recording_is_walked_to_its_last_byte() {
    let body = recording(4, 64);
    let parsed = parse(&body).expect("a well-formed file");
    assert_eq!(parsed.sections, 1);
    assert_eq!(parsed.interfaces.len(), 1);
    assert_eq!(parsed.packets.len(), 4);
    assert_eq!(parsed.longest_capture(), 64);
    assert_eq!(parsed.consumed, body.len());
    assert!(judge(&answered(body), &expectation()).is_ok());
}

#[test]
fn a_block_whose_trailing_length_disagrees_stops_the_walk() {
    // The failure a reader would hit, and the reason the walk follows lengths
    // rather than searching for magic bytes.
    let mut body = recording(3, 32);
    let at = body.len() - 4;
    body[at] ^= 0xFF;
    let parsed = parse(&body).expect("the header is still there");
    assert!(parsed.consumed < body.len());
    let error = judge(&answered(body), &expectation()).expect_err("a truncated walk is a finding");
    assert!(error.contains("block walk consumed"), "{error}");
}

#[test]
fn bytes_that_are_not_pcapng_at_all_are_refused_by_name() {
    let error = parse(&[0u8; 64]).expect_err("zeroes are not a file");
    assert!(error.contains("not a pcapng file"), "{error}");
    let error = parse(&[]).expect_err("nor is nothing");
    assert!(error.contains("not a pcapng file"), "{error}");
}

#[test]
fn a_section_header_in_the_wrong_byte_order_is_refused() {
    let mut body = section_header();
    body[8..12].copy_from_slice(&0x4D3C_2B1Au32.to_le_bytes());
    let error = parse(&body).expect_err("a big-endian section is not what this appliance writes");
    assert!(error.contains("byte-order magic"), "{error}");
}

#[test]
fn a_response_that_is_not_two_hundred_is_a_finding() {
    let mut download = answered(recording(4, 64));
    download.status_line = String::from("HTTP/1.1 503 Service Unavailable");
    let error = judge(&download, &expectation()).expect_err("503 is not a recording");
    assert!(error.contains("503"), "{error}");
}

#[test]
fn a_declared_length_that_disagrees_with_the_body_is_a_finding() {
    let mut download = answered(recording(4, 64));
    download.headers = vec![String::from("Content-Length: 7")];
    let error = judge(&download, &expectation()).expect_err("a short body is a truncated download");
    assert!(error.contains("Content-Length"), "{error}");
}

#[test]
fn a_response_that_declares_no_length_is_a_finding() {
    // The absent header is the case a conditional check waves through: `curl`
    // reads to close, the body still parses, and the endpoint's stated
    // contract — an exact length — has quietly stopped being kept.
    let mut download = answered(recording(4, 64));
    download.headers = vec![String::from("Content-Type: application/octet-stream")];
    let error =
        judge(&download, &expectation()).expect_err("a recording without a length is a finding");
    assert!(error.contains("no Content-Length"), "{error}");
}

#[test]
fn a_recording_with_fewer_packets_than_were_injected_is_a_finding() {
    let error = judge(&answered(recording(2, 64)), &expectation())
        .expect_err("two packets for three frames is a gap");
    assert!(error.contains("missing observations"), "{error}");
}

#[test]
fn a_capture_longer_than_the_sinks_snap_length_is_a_finding() {
    let error = judge(&answered(recording(4, 4096)), &expectation())
        .expect_err("a log sink keeps 128 bytes");
    assert!(error.contains("snap length"), "{error}");
}

#[test]
fn a_recording_with_no_interface_block_names_no_interface() {
    let mut body = section_header();
    for _ in 0..4 {
        body.extend_from_slice(&enhanced_packet(16));
    }
    let error = judge(&answered(body), &expectation())
        .expect_err("a packet naming an interface nothing describes is unreadable");
    assert!(error.contains("Interface Description Block"), "{error}");
}

#[test]
fn a_block_a_reader_does_not_recognise_is_skipped_by_its_length() {
    // The padding the recorder writes to keep every device write a whole sector
    // is exactly this case, so a walk that stopped at one would find no
    // recording past the first sector.
    let mut body = section_header();
    body.extend_from_slice(&interface_description());
    body.extend_from_slice(&block(0x0000_0BAD, &[0u8; 32]));
    for _ in 0..4 {
        body.extend_from_slice(&enhanced_packet(16));
    }
    let parsed = parse(&body).expect("padding is skipped, not refused");
    assert_eq!(parsed.packets.len(), 4);
    assert_eq!(parsed.consumed, body.len());
}
