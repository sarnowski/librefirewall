use super::*;

use std::boxed::Box;
use std::collections::VecDeque;
use std::{vec, vec::Vec};

use lfw_pcapng::BYTE_ORDER_MAGIC;
use wire::{
    DownloadReply, DownloadRequest, TapAnnotation, TapClassification, TapConsume, TapDecision,
    TapDirection, TapEvent, TapFlow, TapFlowState, TapOutcome, TapRecords, TapRule, TapWriter,
};

/// A device of 64 MiB — the size the QEMU harness attaches.
const CAPACITY_SECTORS: u64 = 64 * 1024 * 1024 / SECTOR_SIZE as u64;

/// pcapng block types this file walks. Restated here rather than exported from
/// `lfw_pcapng`, because a reader recognising a block by its number is what a
/// download must satisfy and the encoder must not be able to define its way out
/// of it.
const SECTION_HEADER_BLOCK: u32 = 0x0A0D_0D0A;
const ENHANCED_PACKET_BLOCK: u32 = 0x0000_0006;

/// A host stand-in for the block device and the staging window it transfers
/// through.
///
/// It is the hostile side of every test here: it refuses submits, fails
/// transfers and answers jobs nothing is waiting on, which is what makes a
/// byzantine device something the pass is proved against rather than something
/// it is assumed away from.
struct Fake {
    window: Vec<u8>,
    disk: Vec<u8>,
    ready: VecDeque<Polled>,
    /// Submits still to be refused before one is taken.
    refuse: usize,
    /// Transfers still to be failed before one is performed.
    fail: usize,
    /// Reads still to be answered `Ok` having moved one sector less than they
    /// asked for. Reads only, because virtio-blk has no partial write to
    /// acknowledge: a write's byte count is what was submitted.
    short_reads: usize,
    /// Completions still to be answered as attributable to no job at all — a
    /// device replaying entries of its used ring.
    unattributed: usize,
}

impl Fake {
    fn new() -> Self {
        Self {
            window: vec![0u8; STAGING_END],
            disk: vec![0u8; CAPACITY_SECTORS as usize * SECTOR_SIZE],
            ready: VecDeque::new(),
            refuse: 0,
            fail: 0,
            short_reads: 0,
            unattributed: 0,
        }
    }

    /// Write `bytes` onto the medium at `sector`, as an earlier deployment or a
    /// harness seeding the disk would have left them.
    fn seed(&mut self, sector: u64, bytes: &[u8]) {
        let at = sector as usize * SECTOR_SIZE;
        self.disk[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// The bytes of one device extent, as a reader holding the disk would see
    /// them.
    fn extent(&self, start_sector: u64, sectors: u64) -> &[u8] {
        let from = start_sector as usize * SECTOR_SIZE;
        let to = from + sectors as usize * SECTOR_SIZE;
        self.disk.get(from..to).unwrap_or_default()
    }

    /// Answer a job nothing asked for, claiming to have moved more than any
    /// transfer could — so what the pass makes of it turns on the attribution
    /// and never on the byte count.
    fn forge(&mut self, job: Job) {
        self.ready.push_back(Polled::Settled(Completion {
            job,
            ended: Ended::Ok {
                delivered: usize::MAX,
            },
        }));
    }
}

impl Medium for Fake {
    fn staging(&mut self, area: Area) -> &mut [u8] {
        let (offset, len) = area.extent();
        self.window
            .get_mut(offset..offset + len)
            .expect("the window holds every area")
    }

    fn submit(&mut self, job: Job, transfer: Transfer) -> Result<(), Refused> {
        if self.refuse > 0 {
            self.refuse -= 1;
            return Err(Refused);
        }
        if self.fail > 0 {
            self.fail -= 1;
            self.ready.push_back(Polled::Settled(Completion {
                job,
                ended: Ended::Failed,
            }));
            return Ok(());
        }
        // A short read: one sector fewer moved than asked for, reported `Ok`
        // exactly as a device that DMA'd less than it promised would. The tail
        // of the area keeps whatever the previous transfer left in it, which is
        // the whole hazard.
        let moved = if !transfer.write && self.short_reads > 0 {
            self.short_reads -= 1;
            transfer.len.saturating_sub(SECTOR_SIZE)
        } else {
            transfer.len
        };
        let (base, area_len) = transfer.area.extent();
        let offset = base + transfer.at;
        assert!(
            transfer.at + transfer.len <= area_len,
            "a transfer stays inside its area"
        );
        assert!(
            transfer.at.is_multiple_of(SECTOR_SIZE),
            "a transfer starts on a sector"
        );
        assert!(
            transfer.len.is_multiple_of(SECTOR_SIZE),
            "a block transfer is whole sectors"
        );
        let at = transfer.sector as usize * SECTOR_SIZE;
        assert!(
            at + transfer.len <= self.disk.len(),
            "a transfer stays inside the device"
        );
        for byte in 0..moved {
            if transfer.write {
                self.disk[at + byte] = self.window[offset + byte];
            } else {
                self.window[offset + byte] = self.disk[at + byte];
            }
        }
        self.ready.push_back(Polled::Settled(Completion {
            job,
            ended: Ended::Ok { delivered: moved },
        }));
        Ok(())
    }

    fn poll(&mut self) -> Option<Polled> {
        if self.unattributed > 0 {
            self.unattributed -= 1;
            return Some(Polled::Unattributed);
        }
        self.ready.pop_front()
    }
}

/// The tap, heaped: the records region is far larger than a stack frame.
struct Ring {
    records: Box<TapRecords>,
    consume: Box<TapConsume>,
}

impl Ring {
    fn new() -> Self {
        Self {
            records: Box::new(TapRecords::zero()),
            consume: Box::new(TapConsume::zero()),
        }
    }

    fn writer(&self) -> TapWriter<'_> {
        self.records.writer(&self.consume)
    }

    fn reader(&self) -> wire::TapReader<'_> {
        self.consume.reader(&self.records)
    }
}

/// An observation carrying a decision the log recording selects: a conversation
/// opened, admitted by a rule. Every deck test that asserts on both recordings
/// needs one, the log holding only observations that carry an event.
fn annotation(packet_id: u64, interface_id: u8) -> TapAnnotation {
    TapAnnotation::new(
        packet_id,
        1_000 + packet_id,
        interface_id,
        TapDecision {
            outcome: TapOutcome::Forwarded,
            direction: TapDirection::Inbound,
            generation: 1,
            flow: Some(TapFlow {
                slot: 11,
                generation: 3,
                classification: TapClassification::New,
                state: TapFlowState::UdpUnreplied,
            }),
            rule: TapRule::new(0),
            event: Some(TapEvent::FlowOpened),
        },
    )
}

/// One the log recording does not select: traffic on a conversation already
/// accounted for, which the capture holds alone.
fn unremarkable(packet_id: u64, interface_id: u8) -> TapAnnotation {
    TapAnnotation::new(
        packet_id,
        1_000 + packet_id,
        interface_id,
        TapDecision {
            outcome: TapOutcome::Forwarded,
            direction: TapDirection::Inbound,
            generation: 1,
            flow: Some(TapFlow {
                slot: 11,
                generation: 3,
                classification: TapClassification::Established,
                state: TapFlowState::UdpAssured,
            }),
            rule: None,
            event: None,
        },
    )
}

fn interfaces() -> ([InterfaceName; MAX_INTERFACES], usize) {
    let mut names = [InterfaceName::new(""); MAX_INTERFACES];
    if let Some(slot) = names.get_mut(0) {
        *slot = InterfaceName::new("port0");
    }
    if let Some(slot) = names.get_mut(1) {
        *slot = InterfaceName::new("port1");
    }
    (names, 2)
}

/// A calibration a recording states its instants against: a 1 GHz counter
/// anchored at a round instant, so a recorded timestamp is readable in a
/// failure rather than merely present.
fn clock() -> Option<lfw_clock::Calibration> {
    Some(lfw_clock::Calibration::new(
        core::num::NonZeroU64::new(1_000_000_000).expect("a nonzero frequency"),
        lfw_clock::Ticks(0),
        1_700_000_000_000_000_000,
    ))
}

fn deck(medium: &mut Fake) -> Deck {
    let (names, count) = interfaces();
    Deck::new(CAPACITY_SECTORS, names, count, medium).expect("a 64 MiB device holds both extents")
}

/// One demand, minted the way the management domain's requester mints one.
fn demand(sink: DownloadSink, offset: u64, len: usize) -> DownloadDemand {
    let request = Box::new(DownloadRequest::zero());
    let reply = Box::new(DownloadReply::zero());
    let mut requester = request.requester(&reply);
    let _pending = requester.request(sink, offset, len);
    let mut responder = reply.responder(&request);
    responder.take().expect("a request was just issued")
}

/// Publish `frames` observations of `len` bytes and run `passes` passes.
///
/// The reader is the caller's, because a `TapReader` *is* a position: a second
/// one would restart at slot zero and re-deliver every record.
fn run(
    deck: &mut Deck,
    medium: &mut Fake,
    ring: &Ring,
    reader: &mut wire::TapReader<'_>,
    frames: usize,
    len: usize,
    passes: usize,
) {
    {
        let mut writer = ring.writer();
        let frame = vec![0xAB; len];
        for packet_id in 0..frames {
            writer
                .write(&annotation(packet_id as u64, 0), len as u32, &frame)
                .expect("the ring holds this many");
        }
    }
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..passes {
        deck.poll(medium, reader, &mut scratch, clock());
    }
}

/// Walk a pcapng stream by block length, answering the Section Header blocks
/// and Enhanced Packet blocks it holds.
///
/// A length walk rather than a search for magic bytes: a stream whose lengths
/// disagree with its content stops the walk, which is the property a reader
/// like `tcpdump` actually depends on.
fn walk(bytes: &[u8]) -> (usize, usize) {
    let mut at = 0;
    let mut sections = 0;
    let mut packets = 0;
    while let Some(header) = bytes.get(at..at + 8) {
        let kind = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if len < BLOCK_FRAMING_LEN || !len.is_multiple_of(4) {
            break;
        }
        let Some(block) = bytes.get(at..at + len) else {
            break;
        };
        let Some(trailer) = block.get(len - 4..) else {
            break;
        };
        if u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]) as usize != len {
            break;
        }
        match kind {
            SECTION_HEADER_BLOCK => {
                let magic = block.get(8..12).expect("a section header is longer");
                assert_eq!(
                    u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]),
                    BYTE_ORDER_MAGIC
                );
                sections += 1;
            }
            ENHANCED_PACKET_BLOCK => packets += 1,
            _ => {}
        }
        at += len;
    }
    (sections, packets)
}

/// pcapng's framing: the type, the length, and the length again.
const BLOCK_FRAMING_LEN: usize = 12;

/// The instant the first packet block states, in microseconds — the two 32-bit
/// halves pcapng carries, high then low.
///
/// Found by walking the blocks rather than by searching for the type's bytes:
/// a payload holding the same four bytes is not a block, and a test that could
/// not tell the two apart would assert on whatever it found first.
fn first_timestamp(bytes: &[u8]) -> Option<u64> {
    let mut at = 0;
    while let Some(header) = bytes.get(at..at + 8) {
        let kind = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if len < BLOCK_FRAMING_LEN || !len.is_multiple_of(4) {
            return None;
        }
        let block = bytes.get(at..at + len)?;
        if kind == ENHANCED_PACKET_BLOCK {
            let high = u32::from_le_bytes(block.get(12..16)?.try_into().ok()?);
            let low = u32::from_le_bytes(block.get(16..20)?.try_into().ok()?);
            return Some((u64::from(high) << 32) | u64::from(low));
        }
        at += len;
    }
    None
}

#[test]
fn the_two_extents_are_disjoint_and_inside_a_64_mib_device() {
    let [(log_start, log_sectors), (capture_start, capture_sectors)] = Deck::extents();
    assert!(log_start >= RESERVED_SECTORS);
    assert!(log_start + log_sectors <= capture_start);
    assert!(capture_start + capture_sectors <= CAPACITY_SECTORS);
    const { assert!(STAGING_END.is_multiple_of(SECTOR_SIZE)) };
    // The `blk_io` grant is 256 KiB, and the layout must fit it.
    const { assert!(STAGING_END <= 256 * 1024) };
}

#[test]
fn a_device_too_small_for_the_capture_extent_is_refused_by_name() {
    let mut medium = Fake::new();
    let (names, count) = interfaces();
    let built = Deck::new(CAPTURE_START_SECTOR + 8, names, count, &mut medium);
    assert!(matches!(
        built.err(),
        Some(DeckError::Extent {
            which: Which::Capture,
            ..
        })
    ));
}

#[test]
fn both_recordings_reach_the_medium_as_pcapng() {
    // The whole of the recording path in one run: observations in, two
    // parseable pcapng streams on the device.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let frames = 12;
    run(&mut deck, &mut medium, &ring, &mut reader, frames, 600, 8);
    // A download seals both recordings, which is what puts the last part-sector
    // of records on the medium; without it the tail is still in staging and the
    // disk holds a whole file that is simply shorter.
    for sink in [DownloadSink::Log, DownloadSink::Capture] {
        let _ = download(&mut deck, &mut medium, &mut reader, sink);
    }

    let counters = deck.counters();
    assert_eq!(counters.tap_records, frames as u64);
    for sink in counters.sinks {
        assert_eq!(sink.records, frames as u64);
        assert_eq!(sink.dropped_oversized, 0);
        assert_eq!(sink.dropped_refused, 0);
    }
    assert_eq!(counters.medium_failures, 0);
    assert_eq!(counters.completions_unexpected, 0);

    for (start, sectors) in Deck::extents() {
        // Past segment 0, which holds the superblock and no record.
        let payload = medium.extent(start + SEGMENT_SECTORS, sectors - SEGMENT_SECTORS);
        let (sections, packets) = walk(payload);
        assert_eq!(sections, 1, "one section header per segment prologue");
        assert_eq!(packets, frames, "one packet block per observation");
    }
}

#[test]
fn a_capture_keeps_the_whole_frame_and_a_log_keeps_only_its_head() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 1, 900, 6);

    let [log, capture] = deck.counters().sinks;
    assert!(
        capture.record_bytes > log.record_bytes,
        "the capture keeps 900 bytes and the log {LOG_SNAP_LEN}"
    );
    assert!(log.record_bytes < 900);
}

#[test]
fn the_superblock_identifies_each_extent_on_the_medium() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 1, 64, 8);

    for (start, sectors) in Deck::extents() {
        let image = medium.extent(start, (SUPERBLOCK_BYTES / SECTOR_SIZE) as u64);
        let image: &[u8; SUPERBLOCK_BYTES] = image.try_into().expect("two sectors");
        let state = lfw_capture_ring::decode_superblock(image)
            .expect("the recorder writes a decodable superblock");
        assert_eq!(state.geometry().start_sector(), start);
        assert_eq!(state.geometry().sectors(), sectors);
    }
}

#[test]
fn a_medium_that_refuses_every_submit_loses_no_record() {
    // Backpressure must never cost an observation: a record is held until both
    // recordings have taken it, and the pass stops drawing new ones.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    medium.refuse = usize::MAX / 2;

    run(&mut deck, &mut medium, &ring, &mut reader, 40, 1500, 4);
    medium.refuse = 0;
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..64 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    }

    let counters = deck.counters();
    assert_eq!(
        counters.tap_records, 40,
        "every published record was drained"
    );
    assert!(counters.medium_refusals > 0, "the medium did refuse");
    for sink in counters.sinks {
        assert_eq!(sink.records, 40, "and every one of them was recorded");
    }
}

#[test]
fn a_failing_medium_is_counted_and_the_recording_keeps_going() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    medium.fail = 3;
    run(&mut deck, &mut medium, &ring, &mut reader, 6, 200, 12);

    let counters = deck.counters();
    assert_eq!(counters.medium_failures, 3);
    assert_eq!(counters.tap_records, 6);
    for sink in counters.sinks {
        assert_eq!(sink.records, 6);
    }
}

#[test]
fn a_completion_for_a_job_nothing_awaits_is_counted_and_changes_nothing() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    medium.forge(Job::Flush(Which::Log));
    medium.forge(Job::Checkpoint(Which::Capture));
    medium.forge(Job::Fetch);
    run(&mut deck, &mut medium, &ring, &mut reader, 2, 100, 6);

    let counters = deck.counters();
    assert_eq!(counters.completions_unexpected, 3);
    for sink in counters.sinks {
        assert_eq!(sink.records, 2);
    }
}

#[test]
fn a_tap_annotation_the_reader_refuses_is_counted_and_recorded_nowhere() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    {
        let mut writer = ring.writer();
        writer
            .write(&annotation(0, 0), 32, &[1u8; 32])
            .expect("the ring is empty");
        // Interface 200 names no row of any configured table, which is a
        // peer-written field a first-party producer would never set and the
        // reader refuses rather than records.
        writer
            .write(&annotation(1, 200), 4, &[0u8; 4])
            .expect("the ring has a second slot");
    }
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..4 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    }

    let counters = deck.counters();
    assert_eq!(counters.tap_refused, 1);
    assert_eq!(counters.tap_records, 1);
    for sink in counters.sinks {
        assert_eq!(sink.records, 1);
    }
}

/// One answer, detached from the medium whose staging it borrowed.
#[derive(Debug)]
enum Answer {
    Bytes(Vec<u8>, u64),
    Refused(
        DownloadRefusal,
        #[expect(dead_code, reason = "read by the Debug a failing match prints")] u64,
    ),
}

/// Run passes until the download is answered, or give up after `passes`.
fn pump(
    deck: &mut Deck,
    medium: &mut Fake,
    reader: &mut wire::TapReader<'_>,
    scratch: &mut [u8; TAP_SNAP_LEN],
    passes: usize,
) -> Option<Answer> {
    for _ in 0..passes {
        deck.poll(medium, reader, scratch, clock());
        if let Some(served) = deck.answer(medium) {
            return Some(match served {
                Served::Deliver {
                    bytes, total_len, ..
                } => Answer::Bytes(bytes.to_vec(), total_len),
                Served::Refuse {
                    reason, total_len, ..
                } => Answer::Refused(reason, total_len),
            });
        }
    }
    None
}

/// Serve a whole download, one window at a time, and answer what came back.
fn download(
    deck: &mut Deck,
    medium: &mut Fake,
    reader: &mut wire::TapReader<'_>,
    sink: DownloadSink,
) -> Vec<u8> {
    let mut scratch = [0u8; TAP_SNAP_LEN];
    let mut body = Vec::new();
    let mut offset = 0u64;
    for _ in 0..256 {
        deck.demand(demand(sink, offset, DOWNLOAD_WINDOW_LEN));
        match pump(deck, medium, reader, &mut scratch, 32) {
            Some(Answer::Bytes(bytes, _)) if bytes.is_empty() => break,
            Some(Answer::Bytes(bytes, _)) => {
                offset += bytes.len() as u64;
                body.extend_from_slice(&bytes);
            }
            Some(Answer::Refused(reason, _)) => {
                panic!("the recorder refused a download of its own recording: {reason:?}")
            }
            None => panic!("a download went unanswered for thirty-two passes"),
        }
    }
    body
}

#[test]
fn a_download_delivers_exactly_what_is_on_the_medium() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let frames = 20;
    run(&mut deck, &mut medium, &ring, &mut reader, frames, 400, 8);

    let body = download(&mut deck, &mut medium, &mut reader, DownloadSink::Log);
    let (sections, packets) = walk(&body);
    assert_eq!(sections, 1);
    assert_eq!(packets, frames);
    assert!(deck.counters().downloads_served > 0);

    // And what was delivered is what the medium holds, byte for byte: a
    // download is a byte range and never a transformation.
    let (start, _) = Deck::extents()[0];
    let sectors = (body.len() / SECTOR_SIZE + 1) as u64;
    let on_disk = medium.extent(start + SEGMENT_SECTORS, sectors);
    assert_eq!(on_disk.get(..body.len()), Some(&body[..]));
}

#[test]
fn a_download_of_an_untouched_recording_delivers_its_prologue_and_no_packets() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();

    let body = download(&mut deck, &mut medium, &mut reader, DownloadSink::Capture);
    let (sections, packets) = walk(&body);
    assert_eq!(sections, 1, "the segment prologue is already durable");
    assert_eq!(packets, 0, "and nothing has been observed yet");
}

#[test]
fn an_offset_past_the_end_answers_no_bytes_under_the_right_total() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 128, 8);

    let body = download(&mut deck, &mut medium, &mut reader, DownloadSink::Capture);
    let mut scratch = [0u8; TAP_SNAP_LEN];
    deck.demand(demand(DownloadSink::Capture, body.len() as u64 + 1, 64));
    let served = pump(&mut deck, &mut medium, &mut reader, &mut scratch, 16);
    match served {
        Some(Answer::Bytes(bytes, total_len)) => {
            assert!(bytes.is_empty());
            assert_eq!(total_len, body.len() as u64);
        }
        other => panic!("past the end is not a refusal: {other:?}"),
    }
}

#[test]
fn a_later_offset_with_no_snapshot_pinned_is_refused_as_not_ready() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    deck.demand(demand(DownloadSink::Log, 4096, 64));
    let mut scratch = [0u8; TAP_SNAP_LEN];
    match pump(&mut deck, &mut medium, &mut reader, &mut scratch, 4) {
        Some(Answer::Refused(reason, _)) => assert_eq!(reason, DownloadRefusal::NotReady),
        other => panic!("a download nobody started is refused: {other:?}"),
    }
    assert_eq!(deck.counters().downloads_refused, 1);
}

#[test]
fn an_offset_pinned_against_the_other_recording_is_refused_rather_than_answered() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 128, 8);
    let _ = download(&mut deck, &mut medium, &mut reader, DownloadSink::Log);

    deck.demand(demand(DownloadSink::Capture, 128, 64));
    let mut scratch = [0u8; TAP_SNAP_LEN];
    match pump(&mut deck, &mut medium, &mut reader, &mut scratch, 4) {
        Some(Answer::Refused(reason, _)) => assert_eq!(reason, DownloadRefusal::NotReady),
        other => panic!("the snapshot pinned is the log's, not the capture's: {other:?}"),
    }
}

#[test]
fn a_read_the_medium_fails_answers_a_device_error_rather_than_hanging() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 128, 8);

    let mut scratch = [0u8; TAP_SNAP_LEN];
    deck.demand(demand(DownloadSink::Log, 0, DOWNLOAD_WINDOW_LEN));
    // The seal reaches the medium first; the read after it is the one broken.
    deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    medium.fail = 1;
    let served = pump(&mut deck, &mut medium, &mut reader, &mut scratch, 16);
    match served {
        Some(Answer::Refused(reason, _)) => assert_eq!(reason, DownloadRefusal::DeviceError),
        other => panic!("a failed read is answered: {other:?}"),
    }
}

#[test]
fn a_read_the_device_under_delivers_is_refused_rather_than_served_as_content() {
    // The staging area a download reads into is reused window after window and
    // is never cleared, so a device that completes a read `Ok` having moved
    // fewer bytes than it was asked for leaves the previous window's bytes in
    // the tail. Serving them would put one part of the recording inside
    // another's body, at full length, under a correct total.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 40, 1400, 12);

    // A whole download first, so the download area holds real recording bytes
    // for a short read to expose.
    let honest = download(&mut deck, &mut medium, &mut reader, DownloadSink::Log);
    assert!(!honest.is_empty(), "there is a recording to download");
    let served = deck.counters().downloads_served;

    // The recording is already sealed and drained, so the next demand locates and
    // reads within one pass — the read this device cuts short.
    let mut scratch = [0u8; TAP_SNAP_LEN];
    medium.short_reads = 1;
    deck.demand(demand(DownloadSink::Log, 0, DOWNLOAD_WINDOW_LEN));
    match pump(&mut deck, &mut medium, &mut reader, &mut scratch, 16) {
        Some(Answer::Refused(reason, _)) => assert_eq!(reason, DownloadRefusal::DeviceError),
        other => panic!("a read the device cut short is refused, not served: {other:?}"),
    }
    let counters = deck.counters();
    assert_eq!(
        counters.downloads_served, served,
        "not one byte was handed out for the short read"
    );
    assert!(
        counters.medium_failures > 0,
        "and the shortfall reached the fault counters rather than passing as a success"
    );
}

#[test]
fn a_completion_answering_no_job_is_counted_without_ending_the_drain() {
    // A device replaying its used ring publishes completions this side holds no
    // request for. Reporting one as "the device has nothing more" would let it
    // throttle the recorder's completion drain on every pass while every fault
    // surface read clean, so it is counted and drained past instead.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    // One pass, so the records are staged and their flushes submitted but no
    // completion has been settled yet.
    run(&mut deck, &mut medium, &ring, &mut reader, 8, 900, 1);
    let before = deck.counters();
    assert!(
        before.sinks.iter().all(|sink| sink.sectors_written == 0),
        "nothing has been acknowledged yet"
    );

    // Three completions answering nothing, queued ahead of the ones that answer
    // the flushes.
    let mut scratch = [0u8; TAP_SNAP_LEN];
    medium.unattributed = 3;
    deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    let after = deck.counters();
    assert_eq!(
        after.completions_unexpected,
        before.completions_unexpected + 3,
        "every unattributable completion is counted"
    );
    assert_eq!(
        after.medium_failures, before.medium_failures,
        "an unattributable completion is not a transfer that failed"
    );
    let sectors = |counters: &RecorderCounters| -> u64 {
        counters.sinks.iter().map(|sink| sink.sectors_written).sum()
    };
    assert!(
        sectors(&after) > sectors(&before),
        "and the pass went on to settle the flush the device really did answer"
    );

    // The recording is unharmed: everything published still reaches a segment.
    medium.unattributed = 0;
    for _ in 0..64 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    }
    for sink in deck.counters().sinks {
        assert_eq!(sink.records, 8);
    }
}

#[test]
fn a_superblock_states_a_short_runs_durable_end_without_waiting_for_a_segment_to_roll() {
    // A segment is a megabyte and a short run never fills one, so rolling is far
    // too coarse a trigger for the medium's only statement of where a recording
    // ends: an extent would claim nothing durable for the whole of such a run,
    // and anything reading the disk afterwards would conclude the appliance had
    // composed records that never reached it.
    let mut medium = Fake::new();
    let (log_start, _) = Deck::extents()[0];
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 200, 8);

    let image = medium.extent(log_start, (SUPERBLOCK_BYTES / SECTOR_SIZE) as u64);
    let image: &[u8; SUPERBLOCK_BYTES] = image.try_into().expect("two sectors");
    let found = lfw_capture_ring::decode_superblock(image).expect("a decodable superblock");
    assert_eq!(
        found.writer().sequence,
        0,
        "the run stays inside its first segment"
    );
    assert!(
        found.writer().offset > 0,
        "the superblock still says no byte is durable after a flush landed"
    );
}

#[test]
fn a_stale_superblock_of_an_older_ring_cannot_outrank_a_fresh_recording() {
    // A re-initialised appliance, or a redeployment: the extent already carries
    // a ring of exactly this geometry at a generation far above anything a
    // fresh one reaches. Parity selection alone would leave it in the copy the
    // fresh ring's first checkpoint does not touch, and a decode prefers the
    // higher generation — so a later boot would resume a cursor into a
    // recording that no longer exists.
    let mut medium = Fake::new();
    let (log_start, log_sectors) = Deck::extents()[0];
    let geometry =
        lfw_capture_ring::Geometry::new(log_start, log_sectors, SEGMENT_BYTES, CAPACITY_SECTORS)
            .expect("the log extent");
    let stale = lfw_capture_ring::RingState::new(
        geometry,
        500,
        lfw_capture_ring::Cursor {
            sequence: 400,
            offset: SEGMENT_BYTES / 2,
        },
        &[],
    )
    .expect("a legal state");
    let mut region = [0u8; SUPERBLOCK_BYTES];
    lfw_capture_ring::encode_superblock(&mut region, &stale, lfw_capture_ring::Copies::Parity);
    medium.seed(log_start, &region);
    assert_eq!(
        lfw_capture_ring::decode_superblock(&region).map(|state| state.write_generation()),
        Some(500),
        "the extent starts out holding the older ring"
    );

    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 200, 8);

    let image = medium.extent(log_start, (SUPERBLOCK_BYTES / SECTOR_SIZE) as u64);
    let image: &[u8; SUPERBLOCK_BYTES] = image.try_into().expect("two sectors");
    let found = lfw_capture_ring::decode_superblock(image).expect("a decodable superblock");
    assert!(
        found.write_generation() < 500,
        "a resuming ring would have adopted the older ring's generation {}",
        found.write_generation()
    );
    assert!(
        found.writer().sequence < 400,
        "and its cursor, {} segments into a recording this boot never wrote",
        found.writer().sequence
    );
}

/// The two recordings differ by **what they hold**: the log takes an observation
/// carrying a lifecycle or policy event and the capture takes every one.
///
/// This is the landing's headline property and it is stated on the counters
/// rather than on the medium, because it is a property of the selection: the
/// capture's record count is the number offered and the log's is the number that
/// carried an event, and the two are different numbers for the same traffic.
#[test]
fn the_log_recording_holds_only_the_observations_that_carry_an_event() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let mut scratch = [0u8; TAP_SNAP_LEN];
    let frame = [0x5au8; 200];
    let mut writer = ring.writer();
    // Five observations, of which two carry an event: the connection history
    // holds those two and the capture holds all five.
    let events = 2;
    for (index, carries_an_event) in [true, false, false, true, false].into_iter().enumerate() {
        let annotation = if carries_an_event {
            annotation(index as u64, 0)
        } else {
            unremarkable(index as u64, 0)
        };
        writer
            .write(&annotation, frame.len() as u32, &frame)
            .expect("the ring is empty");
    }
    deck.poll(&mut medium, &mut reader, &mut scratch, clock());

    let counters = deck.counters();
    assert_eq!(counters.tap_records, 5, "every observation was drained");
    assert_eq!(counters.sinks[0].records, events);
    assert_eq!(counters.sinks[1].records, 5);
    // And the log skipping one is never a reason the tap stops draining: nothing
    // is held, and no record was deferred for want of staging.
    assert_eq!(counters.sinks[0].staging_deferrals, 0);
    assert_eq!(counters.sinks[1].staging_deferrals, 0);
}

#[test]
fn a_recording_under_sustained_traffic_rolls_segments_and_stays_consistent() {
    // Enough frames to close several segments of the log ring, which is the
    // state a reader must be able to resynchronise on.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let mut scratch = [0u8; TAP_SNAP_LEN];
    let frame = [0x77u8; 1500];
    let mut published = 0u64;
    // Taken once and kept, which is the ring's protocol: a second writer
    // restarts at slot zero, so the reader would be handed slots nothing ever
    // wrote and the traffic this test claims to sustain would be zeroed slots.
    let mut writer = ring.writer();
    for _ in 0..600 {
        for _ in 0..8 {
            if writer
                .write(&annotation(published, 0), 1500, &frame)
                .is_ok()
            {
                published += 1;
            }
        }
        deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    }
    let counters = deck.counters();
    assert_eq!(counters.tap_records, published);
    assert!(published > 0);
    assert!(
        counters.sinks[0].segments_closed > 0,
        "the log ring closed at least one segment"
    );
    assert_eq!(counters.completions_unexpected, 0);
    assert_eq!(counters.medium_failures, 0);
    // What is on the medium is still a walkable stream, wrap or no wrap.
    let (start, sectors) = Deck::extents()[0];
    let payload = medium.extent(start + SEGMENT_SECTORS, sectors - SEGMENT_SECTORS);
    let (sections, packets) = walk(payload);
    assert!(sections >= 1);
    assert!(packets > 0);
}

#[test]
fn a_record_carries_the_instant_its_counter_reading_converts_to() {
    // The whole reason the conversion is here: a recording that stated a raw
    // counter reading would put a plausible-looking wrong wall-clock time in an
    // evidence artifact, which an operator has no way to un-guess.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 1, 64, 6);
    let body = download(&mut deck, &mut medium, &mut reader, DownloadSink::Log);

    // The annotation carried 1000 ticks of a 1 GHz counter anchored at
    // 1_700_000_000 seconds, which is one microsecond past that instant.
    let micros = first_timestamp(&body).expect("the recording holds a packet block");
    assert_eq!(micros, 1_700_000_000_000_001);
    assert_eq!(deck.counters().records_unclocked, 0);
}

#[test]
fn an_unclocked_recorder_states_no_instant_rather_than_a_counter_reading() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    {
        let mut writer = ring.writer();
        writer
            .write(&annotation(0, 0), 64, &[0xABu8; 64])
            .expect("the ring is empty");
    }
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..4 {
        deck.poll(&mut medium, &mut reader, &mut scratch, None);
    }
    assert_eq!(deck.counters().records_unclocked, 1);
    assert_eq!(deck.counters().sinks[0].records, 1);
}

#[test]
fn a_segment_reopens_only_once_its_predecessor_is_durable() {
    // `Sink::begin_segment` delegates "call only once the closed segment's
    // bytes are on the device" to its caller and names this pass as the
    // enforcer. This is that proof: with a medium that refuses every
    // submit, no recording may roll, because a roll would readdress the staging
    // buffer against the next segment while the closed one is still in it.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    medium.refuse = usize::MAX / 2;

    // Far more than one segment's worth, so a roll is certainly wanted.
    run(&mut deck, &mut medium, &ring, &mut reader, 40, 1500, 64);
    for sink in deck.counters().sinks {
        assert_eq!(
            sink.segments_closed, 0,
            "a segment whose bytes the medium never took must not be left behind"
        );
    }

    // Let the medium take them, and the roll follows.
    medium.refuse = 0;
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..512 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    }
    for sink in deck.counters().sinks {
        assert_eq!(sink.records, 40, "and every record still reached a segment");
    }
}

#[test]
fn a_records_drop_count_states_what_the_tap_ring_lost_before_it() {
    // A recording is meant to state its own loss in-band. The tap
    // ring is deliberately lossy, and a reader learns how much only because the
    // rise in the writer's drop count is carried into the next record's
    // `epb_dropcount` rather than left to a metric taken somewhere else.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();

    // Offer far more than the ring holds, with nothing draining it, so the
    // writer refuses the newest and counts them.
    {
        let mut writer = ring.writer();
        let frame = vec![0xCD; 200];
        for packet_id in 0..(wire::TAP_SLOTS as u64 * 3) {
            let _ = writer.write(&annotation(packet_id, 0), 200, &frame);
        }
        assert!(writer.dropped() > 0, "the ring did refuse records");
    }

    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..256 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock());
    }

    let counters = deck.counters();
    assert!(
        counters.tap_dropped_by_writer > 0,
        "the pass observed the writer's drops"
    );
    let stated = Deck::extents().iter().any(|(start, sectors)| {
        let payload = medium.extent(start + SEGMENT_SECTORS, sectors - SEGMENT_SECTORS);
        drop_counts(payload).iter().any(|count| *count > 0)
    });
    assert!(
        stated,
        "and attributed them to a record, so the file states its own loss"
    );
}

/// Every `epb_dropcount` a stream carries, in order.
fn drop_counts(bytes: &[u8]) -> Vec<u64> {
    const EPB_DROPCOUNT: u16 = 4;
    let mut counts = Vec::new();
    let mut at = 0;
    while let Some(header) = bytes.get(at..at + 8) {
        let kind = u32::from_le_bytes(header[0..4].try_into().expect("four bytes"));
        let total = u32::from_le_bytes(header[4..8].try_into().expect("four bytes")) as usize;
        if total < 12 || !total.is_multiple_of(4) || at + total > bytes.len() {
            break;
        }
        if kind == ENHANCED_PACKET_BLOCK {
            let block = &bytes[at..at + total];
            let captured =
                u32::from_le_bytes(block[20..24].try_into().expect("four bytes")) as usize;
            let mut option = 28 + captured.div_ceil(4) * 4;
            while let Some(head) = block.get(option..option + 4) {
                let code = u16::from_le_bytes(head[0..2].try_into().expect("two bytes"));
                let len = u16::from_le_bytes(head[2..4].try_into().expect("two bytes")) as usize;
                if code == 0 {
                    break;
                }
                if code == EPB_DROPCOUNT
                    && let Some(value) = block.get(option + 4..option + 12)
                    && len == 8
                {
                    counts.push(u64::from_le_bytes(value.try_into().expect("eight bytes")));
                }
                option += 4 + len.div_ceil(4) * 4;
            }
        }
        at += total;
    }
    counts
}
