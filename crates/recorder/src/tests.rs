//! The sink is judged the way an operator judges it: what reaches the device is
//! parsed back by a reader written here, independent of the encoder, and every
//! field is compared. A test that used the encoder to check the encoder would
//! agree with its own mistakes.

use super::*;

use lfw_capture_ring::SUPERBLOCK_COPY_BYTES;
use wire::{TapClassification, TapEvent, TapFlow, TapFlowState, TapRule};

const SEGMENT: usize = 8 * 1024;
const STAGING: usize = 16 * 1024;
const CAPACITY_SECTORS: u64 = 512;

/// A block device that remembers every sector ever written, and refuses a
/// second write to one — the property the sink claims and the one whose failure
/// would silently corrupt a recording.
struct Device {
    bytes: Vec<u8>,
    /// The segment sequence each sector was last written under. A ring rewrites
    /// a sector on every wrap, so the invariant is not "never twice" but "never
    /// twice under one sequence" — a sector rewritten without the sequence
    /// advancing is a placement bug that would corrupt a recording.
    written: Vec<Option<u64>>,
}

impl Device {
    fn new() -> Self {
        Self {
            bytes: vec![0; CAPACITY_SECTORS as usize * SECTOR_SIZE],
            written: vec![None; CAPACITY_SECTORS as usize],
        }
    }

    fn apply(&mut self, flush: &Flush, sequence: u64, staging: &[u8]) {
        assert!(flush.len().is_multiple_of(SECTOR_SIZE), "partial sector");
        let start = flush.sector() as usize * SECTOR_SIZE;
        let end = start + flush.len();
        assert!(end <= self.bytes.len(), "write past the device");
        for sector in flush.sector()..flush.sector() + (flush.len() / SECTOR_SIZE) as u64 {
            let slot = &mut self.written[sector as usize];
            if let Some(previous) = *slot {
                assert!(
                    sequence > previous,
                    "sector {sector} written twice under sequence {sequence}"
                );
            }
            *slot = Some(sequence);
        }
        self.bytes[start..end].copy_from_slice(&staging[..flush.len()]);
    }

    fn read(&self, sector: u64, len: usize) -> &[u8] {
        let start = sector as usize * SECTOR_SIZE;
        &self.bytes[start..start + len]
    }
}

fn geometry(segments: u64) -> Geometry {
    Geometry::new(
        0,
        segments * (SEGMENT / SECTOR_SIZE) as u64,
        SEGMENT,
        CAPACITY_SECTORS,
    )
    .expect("a legal geometry")
}

fn config(snap_len: u32, segments: u64) -> SinkConfig {
    let mut interfaces = [InterfaceName::new(""); MAX_INTERFACES];
    interfaces[0] = InterfaceName::new("wan");
    interfaces[1] = InterfaceName::new("lan");
    SinkConfig {
        geometry: geometry(segments),
        snap_len,
        interfaces,
        interface_count: 2,
    }
}

fn tap(packet_id: u64, interface_id: u8, original_len: u32) -> CheckedTap {
    CheckedTap {
        packet_id,
        timestamp: 1_700_000_000_000_000 + packet_id,
        interface_id,
        original_len,
        outcome: TapOutcome::Forwarded,
        direction: TapDirection::Inbound,
        generation: 7,
        flow: None,
        rule: None,
        event: None,
    }
}

/// The same observation carrying the decision that opened a conversation: the
/// shape every field of the annotation is actually populated by.
fn tap_opening(packet_id: u64, interface_id: u8, original_len: u32) -> CheckedTap {
    CheckedTap {
        flow: Some(TapFlow {
            slot: 0x0002_2222,
            generation: 0x0033_3333,
            classification: TapClassification::New,
            state: TapFlowState::SynSent,
        }),
        rule: TapRule::new(5),
        event: Some(TapEvent::FlowOpened),
        ..tap(packet_id, interface_id, original_len)
    }
}

fn frame(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(index as u8))
        .collect()
}

/// A harness that owns the staging buffer and drains it the way a protection
/// domain does: record, flush whole sectors, acknowledge.
struct Harness {
    sink: Sink,
    staging: Vec<u8>,
    device: Device,
}

impl Harness {
    fn new(snap_len: u32, segments: u64) -> Self {
        let mut staging = vec![0u8; STAGING];
        let sink = Sink::new(config(snap_len, segments), &mut staging).expect("a legal sink");
        Self {
            sink,
            staging,
            device: Device::new(),
        }
    }

    fn drain(&mut self) {
        while let Some(flush) = self.sink.take_flush() {
            let sequence = self.sink.staged_sequence();
            self.device.apply(&flush, sequence, &self.staging);
            self.sink.acknowledge(flush, &mut self.staging);
        }
    }

    /// Record one observation, rolling the segment when it will not fit.
    fn record(&mut self, tap: &CheckedTap, frame: &[u8]) -> Recorded {
        match self.sink.record(tap, frame, &mut self.staging) {
            Recorded::SegmentFull => {
                self.roll();
                self.sink.record(tap, frame, &mut self.staging)
            }
            Recorded::StagingFull { .. } => {
                self.drain();
                self.sink.record(tap, frame, &mut self.staging)
            }
            other => other,
        }
    }

    fn roll(&mut self) {
        loop {
            match self.sink.close_segment(&mut self.staging) {
                Ok(_) => break,
                Err(EncodeError::OutOfSpace { .. }) => self.drain(),
                Err(error) => panic!("close refused: {error:?}"),
            }
        }
        self.drain();
        assert_eq!(
            self.sink.staged(),
            0,
            "a closed segment leaves nothing behind"
        );
        self.sink
            .begin_segment(&mut self.staging)
            .expect("the next prologue");
    }

    fn seal(&mut self) {
        loop {
            match self.sink.seal(&mut self.staging) {
                Ok(_) => break,
                Err(EncodeError::OutOfSpace { .. }) => self.drain(),
                Err(error) => panic!("seal refused: {error:?}"),
            }
        }
        self.drain();
    }

    /// Checkpoint the way the protection domain does — compose the region, put
    /// the part the sink named on the device, and read the state back off it —
    /// so what a test asserts on is what a later boot would actually find.
    fn checkpoint(&mut self) -> RingState {
        let mut image = [0u8; SUPERBLOCK_BYTES];
        let write = self
            .sink
            .superblock(&mut image)
            .expect("a representable cursor");
        assert!(write.at.is_multiple_of(SUPERBLOCK_COPY_BYTES));
        assert!(write.len.is_multiple_of(SUPERBLOCK_COPY_BYTES));
        assert!(write.at + write.len <= SUPERBLOCK_BYTES);
        let sector = self.sink.superblock_sector() + (write.at / SECTOR_SIZE) as u64;
        let at = sector as usize * SECTOR_SIZE;
        self.device.bytes[at..at + write.len]
            .copy_from_slice(&image[write.at..write.at + write.len]);
        self.sink.acknowledge_checkpoint();

        let region = self
            .device
            .read(self.sink.superblock_sector(), SUPERBLOCK_BYTES);
        let region: &[u8; SUPERBLOCK_BYTES] = region.try_into().expect("two sectors");
        lfw_capture_ring::decode_superblock(region).expect("what the sink wrote it reads")
    }

    /// The snapshot's bytes, gathered the way the management domain gathers
    /// them: one `locate` and one read at a time.
    fn download(&mut self) -> Vec<u8> {
        let snapshot = self.sink.snapshot();
        let mut body = Vec::new();
        while (body.len() as u64) < snapshot.total_len() {
            match self.sink.locate(&snapshot, body.len() as u64) {
                Locate::Live(span) => {
                    let bytes = self
                        .device
                        .read(span.sector(), span.sectors() as usize * SECTOR_SIZE);
                    body.extend_from_slice(&bytes[span.skip()..span.skip() + span.len()]);
                }
                Locate::PastEnd => break,
                Locate::Overrun => panic!("overrun during a quiescent download"),
            }
        }
        assert_eq!(body.len() as u64, snapshot.total_len(), "short download");
        body
    }
}

// ---------------------------------------------------------------------------
// An independent pcapng reader. It shares no code with the encoder.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct ReadPacket {
    interface_id: u32,
    timestamp: u64,
    captured: Vec<u8>,
    original_len: u32,
    flags: Option<u32>,
    packet_id: Option<u64>,
    drop_count: Option<u64>,
    verdict: Option<Vec<u8>>,
    annotation: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct ReadFile {
    sections: usize,
    interfaces: Vec<String>,
    packets: Vec<ReadPacket>,
    padding_blocks: usize,
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

/// Walk options: code (u16), length (u16), value padded to four, until
/// `opt_endofopt`.
fn options(mut body: &[u8], mut visit: impl FnMut(u16, &[u8])) {
    while body.len() >= 4 {
        let code = u16::from_le_bytes(body[0..2].try_into().expect("two bytes"));
        let len = u16::from_le_bytes(body[2..4].try_into().expect("two bytes")) as usize;
        if code == 0 {
            return;
        }
        let padded = len.div_ceil(4) * 4;
        assert!(4 + padded <= body.len(), "an option past its block");
        visit(code, &body[4..4 + len]);
        body = &body[4 + padded..];
    }
}

fn parse(bytes: &[u8]) -> ReadFile {
    let mut file = ReadFile::default();
    let mut at = 0usize;
    while at + 12 <= bytes.len() {
        let kind = le32(bytes, at);
        let total = le32(bytes, at + 4) as usize;
        assert!(total >= 12, "a block shorter than its framing at {at}");
        assert!(total.is_multiple_of(4), "an unaligned block at {at}");
        assert!(at + total <= bytes.len(), "a block past the file at {at}");
        assert_eq!(
            le32(bytes, at + total - 4),
            total as u32,
            "the trailing length disagrees at {at}"
        );
        let block = &bytes[at..at + total];
        match kind {
            0x0A0D_0D0A => {
                assert_eq!(le32(block, 8), 0x1A2B_3C4D, "byte-order magic");
                file.sections += 1;
                // A new section restarts the interface numbering.
                file.interfaces.clear();
            }
            0x0000_0001 => {
                let mut name = String::new();
                options(&block[16..total - 4], |code, value| {
                    if code == 2 {
                        name = String::from_utf8_lossy(value).into_owned();
                    }
                });
                file.interfaces.push(name);
            }
            0x0000_0006 => {
                let captured_len = le32(block, 20) as usize;
                let original_len = le32(block, 24);
                let padded = captured_len.div_ceil(4) * 4;
                let mut packet = ReadPacket {
                    interface_id: le32(block, 8),
                    timestamp: (u64::from(le32(block, 12)) << 32) | u64::from(le32(block, 16)),
                    captured: block[28..28 + captured_len].to_vec(),
                    original_len,
                    flags: None,
                    packet_id: None,
                    drop_count: None,
                    verdict: None,
                    annotation: None,
                };
                options(&block[28 + padded..total - 4], |code, value| match code {
                    2 => packet.flags = Some(u32::from_le_bytes(value.try_into().expect("u32"))),
                    4 => {
                        packet.drop_count = Some(u64::from_le_bytes(value.try_into().expect("u64")))
                    }
                    5 => {
                        packet.packet_id = Some(u64::from_le_bytes(value.try_into().expect("u64")))
                    }
                    7 => packet.verdict = Some(value.to_vec()),
                    2989 => {
                        assert_eq!(
                            le32(value, 0),
                            lfw_pcapng::UNREGISTERED_PEN,
                            "enterprise number"
                        );
                        packet.annotation = Some(value[4..].to_vec());
                    }
                    _ => {}
                });
                file.packets.push(packet);
            }
            0x0000_0BAD => {
                assert_eq!(
                    le32(block, 8),
                    lfw_pcapng::UNREGISTERED_PEN,
                    "padding block PEN"
                );
                file.padding_blocks += 1;
            }
            other => panic!("an unexpected block type {other:#010x} at {at}"),
        }
        at += total;
    }
    assert_eq!(at, bytes.len(), "trailing bytes that are not a block");
    file
}

// ---------------------------------------------------------------------------

#[test]
fn a_recording_round_trips_through_the_device_and_an_independent_reader() {
    let mut harness = Harness::new(2048, 4);
    let frames: Vec<Vec<u8>> = (0..24)
        .map(|index| frame(64 + index * 7, index as u8))
        .collect();
    for (index, bytes) in frames.iter().enumerate() {
        let tap = tap(index as u64 + 1, (index % 2) as u8, bytes.len() as u32);
        assert!(matches!(
            harness.record(&tap, bytes),
            Recorded::Placed { .. }
        ));
    }
    harness.seal();

    let file = parse(&harness.download());
    assert_eq!(file.sections, 1);
    assert_eq!(file.interfaces, vec!["wan".to_owned(), "lan".to_owned()]);
    assert_eq!(file.packets.len(), frames.len());
    for (index, (packet, bytes)) in file.packets.iter().zip(&frames).enumerate() {
        assert_eq!(&packet.captured, bytes, "packet {index} payload");
        assert_eq!(packet.original_len as usize, bytes.len());
        assert_eq!(packet.interface_id, (index % 2) as u32);
        assert_eq!(packet.packet_id, Some(index as u64 + 1));
        assert_eq!(packet.flags, Some(FLAGS_INBOUND));
        assert_eq!(packet.drop_count, Some(0));
        assert_eq!(
            packet.verdict,
            Some(vec![0xFF, ANNOTATION_VERDICT_FORWARDED])
        );
        let annotation = packet.annotation.as_ref().expect("an annotation");
        assert_eq!(annotation.len(), ANNOTATION_LEN);
        assert_eq!(annotation[0], ANNOTATION_VERSION);
        assert_eq!(annotation[1], ANNOTATION_VERDICT_FORWARDED);
        assert_eq!(annotation[2], 0, "no drop reason on a forwarded frame");
        assert_eq!(annotation[3], (index % 2) as u8);
        assert_eq!(annotation[4], 0, "inbound");
        assert_eq!(u32::from_le_bytes(annotation[8..12].try_into().unwrap()), 7);
    }
}

/// Every field the annotation gained, read back off the medium at the offsets a
/// reader outside this workspace navigates by.
///
/// This is the whole of what makes a record say *why*: the conversation it is
/// about, what the packet did to it, and which of the operator's rules decided
/// it. Asserted field by field at literal offsets rather than through the
/// constants that wrote them, so a field that moves is caught here and not
/// silently read as its neighbour.
#[test]
fn an_annotation_carries_the_flow_the_event_and_the_rule() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(96, 4);
    let observation = tap_opening(3, 1, bytes.len() as u32);
    assert!(matches!(
        harness.record(&observation, &bytes),
        Recorded::Placed { .. }
    ));
    harness.seal();

    let file = parse(&harness.download());
    let packet = &file.packets[0];
    let annotation = packet.annotation.as_ref().expect("an annotation");
    assert_eq!(annotation.len(), 24);
    assert_eq!(annotation[0], ANNOTATION_VERSION);
    assert_eq!(annotation[0], 2, "the layout a reader keys on");
    assert_eq!(annotation[1], ANNOTATION_VERDICT_FORWARDED);
    assert_eq!(annotation[2], 0, "no drop reason on a forwarded frame");
    assert_eq!(annotation[3], 1, "the interface");
    assert_eq!(annotation[4], 0, "inbound");
    assert_eq!(
        annotation[5] as u32,
        TapClassification::New.to_bits(),
        "the packet opened the conversation"
    );
    assert_eq!(annotation[6] as u32, TapEvent::FlowOpened.to_bits());
    assert_eq!(annotation[7] as u32, TapFlowState::SynSent.to_bits());
    assert_eq!(
        u32::from_le_bytes(annotation[8..12].try_into().expect("four octets")),
        7,
        "the configuration generation"
    );
    assert_eq!(
        u32::from_le_bytes(annotation[12..16].try_into().expect("four octets")),
        0x0002_2222,
        "the flow's slot"
    );
    assert_eq!(
        u32::from_le_bytes(annotation[16..20].try_into().expect("four octets")),
        0x0033_3333,
        "and which occupant of it"
    );
    assert_eq!(
        u16::from_le_bytes(annotation[20..22].try_into().expect("two octets")),
        6,
        "the rule at position five, one higher so zero can mean none"
    );
    assert_eq!(&annotation[22..], &[0, 0], "the layout ends where it says");
}

/// An observation naming no conversation leaves every one of those fields zero,
/// which is what makes *absent* a value a reader can read rather than a shape it
/// has to infer from a length.
#[test]
fn an_observation_with_no_flow_leaves_the_decision_fields_zero() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(64, 0);
    harness.record(&tap(1, 0, 64), &bytes);
    harness.seal();

    let file = parse(&harness.download());
    let annotation = file.packets[0]
        .annotation
        .as_ref()
        .expect("an annotation")
        .clone();
    assert_eq!(
        &annotation[5..8],
        &[0, 0, 0],
        "classification, event, state"
    );
    assert_eq!(&annotation[12..22], &[0; 10], "identity and rule");
}

#[test]
fn a_snap_length_truncates_the_bytes_and_keeps_the_wire_length() {
    let mut harness = Harness::new(64, 4);
    let bytes = frame(1500, 3);
    let tap = tap(1, 0, bytes.len() as u32);
    assert!(matches!(
        harness.record(&tap, &bytes),
        Recorded::Placed { .. }
    ));
    harness.seal();

    let file = parse(&harness.download());
    let packet = &file.packets[0];
    assert_eq!(packet.captured.len(), 64, "truncated to the snap length");
    assert_eq!(packet.captured, bytes[..64]);
    assert_eq!(packet.original_len, 1500, "the wire length survives");
}

#[test]
fn a_dropped_frame_carries_its_reason_into_the_annotation() {
    let mut harness = Harness::new(2048, 4);
    let mut observation = tap(9, 1, 80);
    observation.outcome = TapOutcome::Dropped(wire::TapDropReason::TtlExpired);
    observation.direction = TapDirection::Outbound;
    let bytes = frame(80, 1);
    assert!(matches!(
        harness.record(&observation, &bytes),
        Recorded::Placed { .. }
    ));
    harness.seal();

    let file = parse(&harness.download());
    let packet = &file.packets[0];
    assert_eq!(packet.flags, Some(FLAGS_OUTBOUND));
    let annotation = packet.annotation.as_ref().expect("an annotation");
    assert_eq!(annotation[1], ANNOTATION_VERDICT_DROPPED);
    assert_eq!(
        annotation[2] as u32,
        wire::TapDropReason::TtlExpired.to_bits()
    );
    assert_eq!(annotation[4], 1, "outbound");
}

#[test]
fn tap_ring_drops_are_attributed_to_the_next_record_and_then_cleared() {
    let mut harness = Harness::new(2048, 4);
    harness.sink.note_drops(3);
    harness.sink.note_drops(4);
    let bytes = frame(64, 0);
    harness.record(&tap(1, 0, 64), &bytes);
    harness.record(&tap(2, 0, 64), &bytes);
    harness.seal();

    let file = parse(&harness.download());
    assert_eq!(file.packets[0].drop_count, Some(7), "both notes accumulate");
    assert_eq!(file.packets[1].drop_count, Some(0), "and are then cleared");
}

#[test]
fn every_sector_boundary_case_yields_a_file_a_reader_accepts() {
    // Records are four-aligned, so the slack before a sector boundary walks
    // {0, 4, ..., 508}. Each is padded differently and each must parse.
    for extra in 0..8usize {
        let mut harness = Harness::new(2048, 4);
        let bytes = frame(60 + extra * 4, extra as u8);
        for index in 0..5u64 {
            harness.record(&tap(index + 1, 0, bytes.len() as u32), &bytes);
        }
        harness.seal();
        let body = harness.download();
        assert!(
            body.len().is_multiple_of(SECTOR_SIZE),
            "a sealed recording ends on a sector boundary"
        );
        let file = parse(&body);
        assert_eq!(file.packets.len(), 5, "extra {extra}");
    }
}

#[test]
fn a_seal_with_nothing_to_pad_writes_nothing() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(64, 0);
    harness.record(&tap(1, 0, 64), &bytes);
    harness.seal();
    let before = harness.sink.counters().padding_bytes;
    let second = harness
        .sink
        .seal(&mut harness.staging)
        .expect("a second seal");
    assert_eq!(second, 0, "already on a boundary");
    assert_eq!(harness.sink.counters().padding_bytes, before);
}

#[test]
fn a_closed_segment_is_exactly_one_segment_long_and_parses_alone() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(512, 5);
    let mut recorded = 0;
    // Enough to close two segments.
    for index in 0..64u64 {
        if matches!(
            harness.record(&tap(index + 1, 0, bytes.len() as u32), &bytes),
            Recorded::Placed { .. }
        ) {
            recorded += 1;
        }
        if harness.sink.counters().segments_closed >= 2 {
            break;
        }
    }
    harness.seal();
    assert!(recorded > 0);
    assert!(harness.sink.counters().segments_closed >= 2);

    let body = harness.download();
    assert!(
        body.len() > SEGMENT,
        "a download spanning more than one segment"
    );
    // Each closed segment is exactly SEGMENT bytes and is a whole file.
    let closed = &body[..SEGMENT];
    let file = parse(closed);
    assert_eq!(file.sections, 1, "a segment carries its own section header");
    assert_eq!(file.interfaces.len(), 2);
    // And the whole download parses as one concatenated file.
    let whole = parse(&body);
    assert!(whole.sections >= 2);
}

#[test]
fn a_record_no_segment_could_hold_is_refused_and_the_sink_carries_on() {
    let mut harness = Harness::new(u32::MAX, 4);
    let huge = frame(SEGMENT, 1);
    let outcome = harness
        .sink
        .record(&tap(1, 0, huge.len() as u32), &huge, &mut harness.staging);
    assert!(matches!(outcome, Recorded::Oversized { .. }), "{outcome:?}");
    assert_eq!(harness.sink.counters().dropped_oversized, 1);

    let bytes = frame(64, 2);
    assert!(matches!(
        harness.record(&tap(2, 0, 64), &bytes),
        Recorded::Placed { .. }
    ));
    harness.seal();
    assert_eq!(parse(&harness.download()).packets.len(), 1);
}

#[test]
fn a_staging_buffer_too_small_for_a_record_is_refused_rather_than_overrun() {
    let mut staging = vec![0u8; 4096];
    let mut sink = Sink::new(config(2048, 4), &mut staging).expect("a legal sink");
    let bytes = frame(2000, 3);
    // Fill the staging buffer without flushing.
    let mut refused = None;
    for index in 0..8u64 {
        match sink.record(&tap(index + 1, 0, bytes.len() as u32), &bytes, &mut staging) {
            Recorded::StagingFull { needed, free } => {
                refused = Some((needed, free));
                break;
            }
            Recorded::Placed { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let (needed, free) = refused.expect("the buffer fills");
    assert!(needed > free);
    assert_eq!(sink.counters().staging_deferrals, 1);
}

#[test]
fn a_wrap_evicts_the_oldest_segment_and_a_download_reports_it() {
    let mut harness = Harness::new(2048, 3);
    let bytes = frame(400, 9);
    // Two full wraps of a three-segment ring.
    while harness.sink.counters().wraps < 2 {
        harness.record(&tap(1, 0, bytes.len() as u32), &bytes);
    }
    harness.seal();

    let snapshot = harness.sink.snapshot();
    assert!(snapshot.total_len() > 0);
    // Everything the snapshot names is still live.
    let body = harness.download();
    assert_eq!(body.len() as u64, snapshot.total_len());
    parse(&body);

    // A snapshot taken before the wrap is overrun by it.
    let stale = Snapshot {
        first: 0,
        total: snapshot.total_len(),
    };
    let before = harness.sink.counters().download_overruns;
    assert_eq!(harness.sink.locate(&stale, 0), Locate::Overrun);
    assert_eq!(harness.sink.counters().download_overruns, before + 1);
}

#[test]
fn locate_answers_the_ends_and_the_seam_between_two_segments() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(512, 4);
    while harness.sink.counters().segments_closed < 1 {
        harness.record(&tap(1, 0, bytes.len() as u32), &bytes);
    }
    harness.record(&tap(2, 0, bytes.len() as u32), &bytes);
    harness.seal();

    let snapshot = harness.sink.snapshot();
    assert!(matches!(harness.sink.locate(&snapshot, 0), Locate::Live(_)));
    let last = snapshot.total_len() - 1;
    let Locate::Live(span) = harness.sink.locate(&snapshot, last) else {
        panic!("the last byte is live");
    };
    assert_eq!(span.len(), 1, "one byte remains");
    assert_eq!(
        harness.sink.locate(&snapshot, snapshot.total_len()),
        Locate::PastEnd
    );
    // The seam: the first byte of the second segment.
    let Locate::Live(seam) = harness.sink.locate(&snapshot, SEGMENT as u64) else {
        panic!("the seam is live");
    };
    assert_eq!(seam.skip(), 0, "a segment starts on a sector");
}

#[test]
fn an_empty_recording_has_nothing_to_download() {
    let harness = Harness::new(2048, 4);
    let snapshot = harness.sink.snapshot();
    assert_eq!(snapshot.total_len(), 0);
}

#[test]
fn a_durable_cursor_older_than_the_live_history_promises_nothing() {
    // Flushing far enough behind the writer that the durable segment has been
    // evicted. A snapshot that clamped the segment count to zero here would
    // keep the durable offset in its total and hand a reader that many bytes out
    // of a segment holding something else entirely.
    let mut harness = Harness::new(2048, 4);
    harness.record(&tap(1, 0, 300), &frame(300, 1));
    harness.record(&tap(2, 0, 300), &frame(300, 1));
    harness.drain();
    let durable = harness.sink.snapshot();
    assert!(
        durable.total_len() > 0,
        "the first segment has durable bytes to be left behind"
    );

    // Reopen segments without ever handing their bytes over, so the write
    // cursor runs away from the durable one.
    for _ in 0..4 {
        harness
            .sink
            .begin_segment(&mut harness.staging)
            .expect("a prologue fits a fresh buffer");
    }
    let (oldest, _) = harness.sink.ring.readable();
    assert!(
        oldest > 0,
        "the oldest live segment is past the durable one at zero"
    );
    assert_eq!(
        harness.sink.snapshot().total_len(),
        0,
        "nothing durable is still on the medium, so nothing may be promised"
    );
    assert_eq!(
        harness.sink.locate(&harness.sink.snapshot(), 0),
        Locate::PastEnd
    );
}

#[test]
fn a_sink_survives_a_reboot_through_its_superblock() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(256, 6);
    for index in 0..4u64 {
        harness.record(&tap(index + 1, 0, bytes.len() as u32), &bytes);
    }
    harness.seal();
    let state = harness.checkpoint();

    let mut staging = vec![0u8; STAGING];
    let resumed = Sink::resume(config(2048, 4), &state, &mut staging).expect("a resumed sink");
    assert!(
        resumed.cursor().sequence > 0,
        "a resumed ring continues past what the last boot left open"
    );
    assert!(
        resumed.staged() > 0,
        "and its segment's prologue is staged without a second call to ask for it"
    );
}

#[test]
fn a_resumed_recording_claims_no_byte_of_the_segment_the_last_boot_left_open() {
    // The previous boot's open segment was never padded to its end, so its tail
    // still holds an older wrap's bytes. A snapshot is one contiguous range, so
    // the only honest range is one starting after it — counting it would put
    // those bytes mid-body under an exact length.
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(256, 6);
    for index in 0..4u64 {
        harness.record(&tap(index + 1, 0, bytes.len() as u32), &bytes);
    }
    harness.seal();
    let state = harness.checkpoint();
    assert!(
        harness.sink.snapshot().total_len() > 0,
        "the boot being resumed from did record something"
    );

    let mut staging = vec![0u8; STAGING];
    let resumed = Sink::resume(config(2048, 4), &state, &mut staging).expect("a resumed sink");
    assert_eq!(
        resumed.snapshot().total_len(),
        0,
        "a resumed recording promises nothing until it has made bytes durable itself"
    );
}

#[test]
fn a_superblock_records_the_durable_cursor_and_not_the_append_cursor() {
    // The superblock is what anything holding the disk reads to learn where the
    // recording ends, so it must never name bytes still sitting in the staging
    // buffer: a resume from an over-stated cursor would append past the end of
    // what was written and leave a hole no reader can cross.
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(300, 2);
    for index in 0..3u64 {
        harness.record(&tap(index + 1, 0, bytes.len() as u32), &bytes);
    }
    assert!(
        harness.sink.staged() > 0,
        "records are staged and not yet handed to the device"
    );
    let appended = harness.sink.cursor();
    let state = harness.checkpoint();
    assert!(
        state.writer().offset < appended.offset,
        "the checkpoint recorded {} where the append cursor stood at {}",
        state.writer().offset,
        appended.offset
    );

    // And what it recorded is exactly what the device has taken.
    harness.drain();
    let durable = harness.checkpoint();
    let flushed = harness.sink.counters().sectors_written as usize * SECTOR_SIZE;
    assert_eq!(durable.writer().offset, flushed);
}

#[test]
fn a_superblock_from_another_geometry_is_refused_by_name() {
    let mut harness = Harness::new(2048, 4);
    harness.record(&tap(1, 0, 64), &frame(64, 0));
    let state = harness.checkpoint();
    let mut staging = vec![0u8; STAGING];
    let error =
        Sink::resume(config(2048, 8), &state, &mut staging).expect_err("a different extent");
    assert!(matches!(error, SinkError::State(_)), "{error:?}");
}

#[test]
fn a_segment_has_room_only_once_the_prologue_and_the_tail_reserve_are_paid() {
    let segment = lfw_capture_ring::MIN_SEGMENT_BYTES;
    assert!(payload_fits(0, segment));
    assert!(payload_fits(segment - TAIL_RESERVE - 1, segment));
    assert!(!payload_fits(segment - TAIL_RESERVE, segment));
    assert!(!payload_fits(segment, segment));
    assert!(!payload_fits(usize::MAX, segment), "the sum cannot wrap");
}

#[test]
fn the_widest_prologue_this_build_admits_leaves_a_usable_segment() {
    // Eight interfaces at the longest identifier the schema allows, in the
    // smallest legal segment: the case the guard above exists for, and the one
    // no configuration reaches.
    let mut interfaces = [InterfaceName::new(""); MAX_INTERFACES];
    for slot in &mut interfaces {
        *slot = InterfaceName::new("aaaaaaaaaaaaaaaa");
    }
    let config = SinkConfig {
        geometry: Geometry::new(0, 24, lfw_capture_ring::MIN_SEGMENT_BYTES, CAPACITY_SECTORS)
            .expect("a small legal geometry"),
        snap_len: 2048,
        interfaces,
        interface_count: MAX_INTERFACES,
    };
    let prologue = prologue_len(&config).expect("a measurable prologue");
    assert!(payload_fits(prologue, lfw_capture_ring::MIN_SEGMENT_BYTES));
    let mut staging = vec![0u8; STAGING];
    let sink = Sink::new(config, &mut staging).expect("a usable sink");
    assert_eq!(
        sink.staged(),
        prologue,
        "the measured prologue is the written one"
    );
}

#[test]
fn more_interfaces_than_a_recording_may_describe_are_refused() {
    let mut config = config(2048, 4);
    config.interface_count = MAX_INTERFACES + 1;
    let mut staging = vec![0u8; STAGING];
    assert!(matches!(
        Sink::new(config, &mut staging),
        Err(SinkError::TooManyInterfaces { .. })
    ));
    assert!(matches!(
        prologue_len(&config),
        Err(SinkError::TooManyInterfaces { .. })
    ));
}

#[test]
fn an_interface_name_longer_than_the_schema_admits_is_truncated_not_refused() {
    let name = InterfaceName::new("a-very-long-interface-identifier");
    assert_eq!(name.as_str().len(), MAX_INTERFACE_NAME);
    assert_eq!(name.as_str(), "a-very-long-inte");
    assert_eq!(InterfaceName::new("").as_str(), "");
}

#[test]
fn only_one_flush_is_outstanding_at_a_time() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(600, 7);
    for index in 0..4u64 {
        harness.record(&tap(index + 1, 0, bytes.len() as u32), &bytes);
    }
    let flush = harness.sink.take_flush().expect("whole sectors");
    assert!(
        harness.sink.take_flush().is_none(),
        "a second flush while one is outstanding"
    );
    let sequence = harness.sink.staged_sequence();
    harness.device.apply(&flush, sequence, &harness.staging);
    harness.sink.acknowledge(flush, &mut harness.staging);
    assert!(harness.sink.counters().sectors_written > 0);
}

#[test]
fn nothing_to_flush_is_not_a_flush() {
    let mut staging = vec![0u8; STAGING];
    let mut sink = Sink::new(config(2048, 4), &mut staging).expect("a legal sink");
    // A prologue alone is shorter than a sector.
    assert!(sink.take_flush().is_none());
    assert!(sink.staged() > 0);
}

#[test]
fn the_span_a_locate_returns_names_the_sectors_a_caller_must_read() {
    let span = Span {
        sector: 4,
        skip: 100,
        len: 500,
    };
    assert_eq!(span.sectors(), 2, "600 bytes from offset 100 spans two");
    assert!(!span.is_empty());
    let empty = Span {
        sector: 0,
        skip: 0,
        len: 0,
    };
    assert!(empty.is_empty());
    assert_eq!(empty.sectors(), 0);
}

#[test]
fn a_flush_reports_the_bytes_and_the_sector_it_names() {
    let flush = Flush {
        sector: 9,
        len: 1024,
    };
    assert_eq!(flush.sector(), 9);
    assert_eq!(flush.len(), 1024);
    assert!(!flush.is_empty());
    assert!(Flush { sector: 0, len: 0 }.is_empty());
}

#[test]
fn a_padding_request_below_a_representable_block_is_refused() {
    let mut staging = vec![0u8; STAGING];
    let mut sink = Sink::new(config(2048, 4), &mut staging).expect("a legal sink");
    let error = sink.pad(4, &mut staging).expect_err("too small to encode");
    assert!(
        matches!(error, EncodeError::BlockTooShort { .. }),
        "{error:?}"
    );
}

#[test]
fn a_seal_with_no_room_in_staging_is_refused_rather_than_silently_short() {
    let mut staging = vec![0u8; 2048];
    let mut sink = Sink::new(config(2048, 4), &mut staging).expect("a legal sink");
    let bytes = frame(900, 2);
    while matches!(
        sink.record(&tap(1, 0, bytes.len() as u32), &bytes, &mut staging),
        Recorded::Placed { .. }
    ) {}
    // Staging is now nearly full; a seal needing padding cannot fit.
    let mut small = vec![0u8; 8];
    let error = sink.pad(SECTOR_SIZE, &mut small);
    assert!(
        matches!(error, Err(EncodeError::OutOfSpace { .. })),
        "{error:?}"
    );
}

#[test]
fn a_tap_claiming_a_shorter_frame_than_it_carries_is_refused_by_name() {
    // The wire layer holds a peer to captured <= original, but the frame this
    // sink is handed is a separate value: a tap saying ten bytes while carrying
    // a hundred would encode a block no reader could believe.
    let mut staging = vec![0u8; STAGING];
    let mut sink = Sink::new(config(2048, 4), &mut staging).expect("a legal sink");
    let bytes = frame(100, 1);
    let mut observation = tap(1, 0, 100);
    observation.original_len = 10;
    let outcome = sink.record(&observation, &bytes, &mut staging);
    assert!(
        matches!(
            outcome,
            Recorded::Refused(EncodeError::CapturedExceedsOriginal { .. })
        ),
        "{outcome:?}"
    );
    assert_eq!(sink.counters().dropped_refused, 1);
    assert_eq!(sink.counters().records, 0, "nothing was placed");
}

#[test]
fn a_snapshot_offset_the_ring_never_wrote_ends_the_download() {
    // A snapshot longer than what the ring holds — the shape a forged or stale
    // total takes — resolves to the end rather than to a span of nothing.
    let mut harness = Harness::new(2048, 4);
    harness.record(&tap(1, 0, 64), &frame(64, 0));
    harness.seal();
    let real = harness.sink.snapshot();
    let overstated = Snapshot {
        first: 0,
        total: real.total_len() + SEGMENT as u64 * 2,
    };
    assert_eq!(
        harness
            .sink
            .locate(&overstated, real.total_len() + SEGMENT as u64),
        Locate::PastEnd,
        "a position no segment holds"
    );
}

#[test]
fn the_counters_report_what_the_sink_did() {
    let mut harness = Harness::new(2048, 4);
    let bytes = frame(300, 1);
    for index in 0..6u64 {
        harness.record(&tap(index + 1, 0, bytes.len() as u32), &bytes);
    }
    harness.seal();
    let counters = harness.sink.counters();
    assert_eq!(counters.records, 6);
    assert!(counters.record_bytes >= 6 * 300);
    assert!(counters.padding_bytes >= MIN_CUSTOM_BLOCK_LEN as u64);
    assert!(counters.sectors_written > 0);
    assert_eq!(counters.dropped_oversized, 0);
    assert_eq!(harness.sink.snap_len(), 2048);
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Whatever the traffic, every write is a whole sector inside the
        /// extent and no sector is ever written twice — the `Device` asserts
        /// the last of those itself.
        #[test]
        fn no_sequence_of_observations_writes_outside_the_extent_or_twice(
            lengths in prop::collection::vec(0usize..1600, 1..40),
            snap in prop::sample::select(vec![64u32, 256, 2048]),
        ) {
            let mut harness = Harness::new(snap, 3);
            for (index, len) in lengths.iter().enumerate() {
                let bytes = frame(*len, index as u8);
                harness.record(&tap(index as u64 + 1, (index % 2) as u8, *len as u32), &bytes);
            }
            harness.seal();
            prop_assert!(harness.sink.counters().records <= lengths.len() as u64);
        }

        /// What a download gathers is exactly what a reader can parse, and the
        /// packets in it are the ones that were recorded, in order.
        #[test]
        fn a_download_is_a_parseable_file_holding_the_records_in_order(
            count in 1usize..24,
            len in 32usize..600,
        ) {
            let mut harness = Harness::new(2048, 4);
            let bytes = frame(len, 3);
            let mut placed = 0u64;
            for index in 0..count {
                if matches!(
                    harness.record(&tap(index as u64 + 1, 0, len as u32), &bytes),
                    Recorded::Placed { .. }
                ) {
                    placed += 1;
                }
            }
            harness.seal();
            let body = harness.download();
            prop_assert_eq!(body.len() as u64, harness.sink.snapshot().total_len());
            let file = parse(&body);
            prop_assert_eq!(file.packets.len() as u64, placed);
            for (index, packet) in file.packets.iter().enumerate() {
                prop_assert_eq!(packet.packet_id, Some(index as u64 + 1));
                prop_assert_eq!(&packet.captured, &bytes);
            }
        }

        /// A snapshot's length is exactly the durable bytes, and every offset
        /// inside it resolves to a live span inside the extent.
        #[test]
        fn every_offset_of_a_snapshot_resolves_inside_the_extent(
            count in 1usize..30,
        ) {
            let mut harness = Harness::new(2048, 4);
            let bytes = frame(400, 8);
            for index in 0..count {
                harness.record(&tap(index as u64 + 1, 0, 400), &bytes);
            }
            harness.seal();
            let snapshot = harness.sink.snapshot();
            let extent = harness.sink.ring.geometry();
            let mut offset = 0u64;
            while offset < snapshot.total_len() {
                match harness.sink.locate(&snapshot, offset) {
                    Locate::Live(span) => {
                        prop_assert!(span.sector() >= extent.start_sector());
                        prop_assert!(
                            span.sector() + span.sectors()
                                <= extent.start_sector() + extent.sectors()
                        );
                        prop_assert!(span.skip() < SECTOR_SIZE);
                        prop_assert!(!span.is_empty());
                        offset += span.len() as u64;
                    }
                    other => prop_assert!(false, "offset {} gave {:?}", offset, other),
                }
            }
            prop_assert_eq!(offset, snapshot.total_len());
        }
    }
}
