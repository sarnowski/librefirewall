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
