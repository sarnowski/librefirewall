use super::*;

use std::boxed::Box;
use std::collections::VecDeque;
use std::{vec, vec::Vec};

use lfw_pcapng::BYTE_ORDER_MAGIC;
use wire::{
    DownloadReader, DownloadReply, DownloadRequest, TapAnnotation, TapClassification, TapConsume,
    TapDecision, TapDirection, TapEvent, TapFlow, TapFlowState, TapOutcome, TapRecords, TapRule,
    TapWriter,
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
    /// Whether this device negotiated a flush, and so whether the deck may order
    /// a checkpoint behind one.
    orders_writes: bool,
    /// Barriers still to be failed. Separate from `fail` because a device that
    /// takes every write and honours no flush is a device in its own right, and
    /// it is the one whose checkpoint must not go out.
    fail_barriers: usize,
    /// Every job this device was handed, in the order it was handed them —
    /// barriers included. What a checkpoint owes is an *order* and not a count, so
    /// a test that only tallied barriers would pass on a superblock written
    /// before one.
    order: Vec<Job>,
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
            orders_writes: true,
            fail_barriers: 0,
            order: Vec::new(),
        }
    }

    /// The same device without a negotiated flush, which is what a virtio-blk
    /// that never offered `VIRTIO_BLK_F_FLUSH` looks like from here.
    fn without_flush() -> Self {
        Self {
            orders_writes: false,
            ..Self::new()
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

    fn orders_writes(&self) -> bool {
        self.orders_writes
    }

    fn barrier(&mut self, job: Job) -> Result<(), Refused> {
        if self.refuse > 0 {
            self.refuse -= 1;
            return Err(Refused);
        }
        self.order.push(job);
        if self.fail_barriers > 0 {
            self.fail_barriers -= 1;
            self.ready.push_back(Polled::Settled(Completion {
                job,
                ended: Ended::Failed,
            }));
            return Ok(());
        }
        // A real barrier moves nothing and commits everything already written.
        // This fake writes through, so there is nothing to commit — what it
        // models is the completion, which is the whole of what the deck waits on.
        self.ready.push_back(Polled::Settled(Completion {
            job,
            ended: Ended::Ok { delivered: 0 },
        }));
        Ok(())
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
        self.order.push(job);
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
            direction: Some(TapDirection::Inbound),
            generation: 1,
            flow: Some(TapFlow {
                slot: 11,
                generation: 3,
                classification: Some(TapClassification::New),
                state: TapFlowState::UdpUnreplied,
            }),
            rule: TapRule::new(0),
            event: Some(TapEvent::FlowOpened),
        },
    )
}

/// The one observation that is about no frame: a flow the appliance ended when a
/// policy commit stopped admitting it. The **log** holds it and the capture does
/// not, which is the other half of the selection law.
fn revocation(packet_id: u64, interface_id: u8) -> TapAnnotation {
    TapAnnotation::new(
        packet_id,
        1_000 + packet_id,
        interface_id,
        TapDecision {
            outcome: TapOutcome::Revoked,
            direction: None,
            generation: 2,
            flow: Some(TapFlow {
                slot: 11,
                generation: 3,
                classification: None,
                state: TapFlowState::UdpAssured,
            }),
            rule: None,
            event: Some(TapEvent::FlowRevoked),
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
            direction: Some(TapDirection::Inbound),
            generation: 1,
            flow: Some(TapFlow {
                slot: 11,
                generation: 3,
                classification: Some(TapClassification::Established),
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
    Deck::new(CAPACITY_SECTORS, [None; 2], names, count, medium)
        .expect("a 64 MiB device holds both extents")
        .0
}

/// One demand, minted the way the management domain's requester mints one: in
/// the coordinate the management channel's ring cursor asks in, which is the
/// only one there is.
fn ring_demand(sink: DownloadSink, position: u64, len: usize) -> DownloadDemand {
    minted(DownloadReader::Ring, sink, position, len)
}

fn minted(reader: DownloadReader, sink: DownloadSink, offset: u64, len: usize) -> DownloadDemand {
    let request = Box::new(DownloadRequest::zero());
    let reply = Box::new(DownloadReply::zero());
    let mut requester = request.requester(&reply);
    let _pending = requester.request(reader, sink, offset, len);
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
        deck.poll(medium, reader, &mut scratch, clock(), None, None);
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
    let built = Deck::new(
        CAPTURE_START_SECTOR + 8,
        [None; 2],
        names,
        count,
        &mut medium,
    );
    assert!(matches!(
        built.err(),
        Some(DeckError::Extent {
            which: Which::Capture,
            ..
        })
    ));
}

/// One whole boot over `medium`: read what is there, build both recordings on
/// it, run `frames` observations through them and seal both so the last
/// part-sector reaches the device.
///
/// The read is `preload`'s, not a shortcut past it: what a second boot resumes
/// from must be what the domain's own boot sequence would have found.
fn boot(medium: &mut Fake, ring: &Ring, frames: usize) -> [Opened; 2] {
    let stored = crate::preload::read_superblocks(CAPACITY_SECTORS, medium)
        .expect("the fake answers every read");
    let (names, count) = interfaces();
    let (mut deck, opened) = Deck::new(CAPACITY_SECTORS, stored, names, count, medium)
        .expect("a 64 MiB device holds both extents");
    let mut reader = ring.reader();
    run(&mut deck, medium, ring, &mut reader, frames, 600, 8);
    for sink in [DownloadSink::Log, DownloadSink::Capture] {
        let _ = download(&mut deck, medium, &mut reader, sink);
    }
    opened
}

/// Each extent's superblock as a reader holding the disk would decode it.
fn superblocks(medium: &Fake) -> [lfw_capture_ring::RingState; 2] {
    Deck::extents().map(|(start, _)| {
        let image = medium.extent(start, (SUPERBLOCK_BYTES / SECTOR_SIZE) as u64);
        let image: &[u8; SUPERBLOCK_BYTES] = image.try_into().expect("two sectors");
        lfw_capture_ring::decode_superblock(image).expect("a decodable superblock")
    })
}

#[test]
fn a_resumed_recording_tells_a_channel_cursor_where_to_carry_on_from() {
    // What a channel reader meets on every appliance that has rebooted once. Its
    // cursor starts at zero, the segment this boot opened is nowhere near zero,
    // and the recording refuses the position — so the reply has to carry the one
    // fact that turns that refusal into progress: where the recording now
    // begins. Without it the appliance stops shipping that recording for the
    // rest of the boot and the console says only that a ring was overrun.
    let mut medium = Fake::new();
    let _ = boot(&mut medium, &Ring::new(), 24);

    // A ring of this boot's own: a tap ring is one producer and one consumer,
    // and the boot above has already filled and drained its own.
    let ring = Ring::new();
    let stored = crate::preload::read_superblocks(CAPACITY_SECTORS, &mut medium)
        .expect("the fake answers every read");
    let (names, count) = interfaces();
    let (mut deck, opened) = Deck::new(CAPACITY_SECTORS, stored, names, count, &mut medium)
        .expect("a 64 MiB device holds both extents");
    assert!(
        matches!(opened[0], Opened::Resumed { .. }),
        "this boot must have resumed the medium the first one left"
    );
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 24, 600, 8);
    let mut scratch = [0u8; TAP_SNAP_LEN];

    // A cursor that stood at zero when the node went down still stands at a
    // position this boot serves: the recording was resumed inside the segment
    // the medium named, so nothing an earlier boot wrote left the ring.
    deck.demand(ring_demand(DownloadSink::Log, 0, 512));
    match pump(&mut deck, &mut medium, &mut reader, &mut scratch, 32) {
        Some(Answer::Bytes(bytes, _)) => assert!(
            !bytes.is_empty(),
            "a resumed recording answered position zero with no bytes"
        ),
        other => panic!("a resumed recording refused position zero: {other:?}"),
    }
}

#[test]
fn a_second_boot_of_one_medium_continues_the_ring_rather_than_writing_over_it() {
    // The defect this whole path exists to close, stated end to end: two boots
    // share one device, and the second must come up inside the segment the first
    // left open and at the offset it left — with the first boot's bytes still
    // where it put them.
    let mut medium = Fake::new();
    let first = boot(&mut medium, &Ring::new(), 24);
    assert_eq!(first, [Opened::FreshMedium, Opened::FreshMedium]);
    let after_first = superblocks(&medium);

    // What a reader holding only the disk can see of the first boot, kept for
    // the comparison below: the disk is what the claim is about.
    let carried: Vec<Vec<u8>> = Deck::extents()
        .iter()
        .map(|(start, sectors)| medium.extent(*start, *sectors).to_vec())
        .collect();

    let second = boot(&mut medium, &Ring::new(), 24);
    for (index, resumed) in second.into_iter().enumerate() {
        let Opened::Resumed {
            generation,
            sequence,
            offset,
        } = resumed
        else {
            panic!("recording {index} did not resume: {resumed:?}");
        };
        assert_eq!(
            generation,
            after_first[index].write_generation(),
            "the generation the second boot resumed at is the one the first left"
        );
        assert_eq!(sequence, after_first[index].writer().sequence);
        assert_eq!(
            offset,
            after_first[index].writer().offset as u64,
            "a resumed recording continues at the position the medium named, so \
             nothing the previous boot made durable stops being servable"
        );
    }

    // The second boot advanced the ring rather than restarting it: a higher
    // generation, and a write cursor past where the first boot stopped.
    let after_second = superblocks(&medium);
    for (index, (before, after)) in after_first.iter().zip(&after_second).enumerate() {
        assert!(
            after.write_generation() > before.write_generation(),
            "recording {index} did not checkpoint past the generation it resumed"
        );
        let stopped = before.writer().sequence as usize * SEGMENT_BYTES + before.writer().offset;
        let reached = after.writer().sequence as usize * SEGMENT_BYTES + after.writer().offset;
        assert!(
            reached > stopped,
            "recording {index} did not write past where the first boot stopped"
        );
    }

    // And the first boot's payload is still on the medium: the second boot
    // picked up at the byte the first stopped on, so nothing it wrote landed on
    // the bytes before it. Compared over the first boot's own written prefix,
    // which is what its durable cursor names.
    for (index, ((start, _), before)) in Deck::extents().iter().zip(&after_first).enumerate() {
        let written = before.writer().sequence as usize * SEGMENT_BYTES + before.writer().offset;
        let payload_at = SEGMENT_BYTES;
        let now = medium.extent(*start, LOG_SECTORS.max(CAPTURE_SECTORS));
        assert_eq!(
            now.get(payload_at..payload_at + written),
            carried[index].get(payload_at..payload_at + written),
            "recording {index} lost bytes the first boot had made durable"
        );
    }
}

#[test]
fn a_superblock_describing_another_ring_is_recorded_over_and_said_so() {
    // The decision this states: not recording at all is the worse failure for
    // an appliance whose recordings are its evidence, so a rebound extent is
    // recorded fresh — and loudly, because what it overwrote was somebody's.
    let mut medium = Fake::new();
    let (start_sector, sectors) = Which::Log.extent();
    let elsewhere = Geometry::new(
        start_sector + SEGMENT_SECTORS,
        sectors,
        SEGMENT_BYTES,
        CAPACITY_SECTORS,
    )
    .expect("a legal geometry that is not this extent's");
    let state = lfw_capture_ring::RingState::new(
        elsewhere,
        11,
        lfw_capture_ring::Cursor {
            sequence: 4,
            offset: 0,
        },
        &[],
    )
    .expect("a cursor inside the geometry");

    let (names, count) = interfaces();
    let (mut deck, opened) = Deck::new(
        CAPACITY_SECTORS,
        [Some(state), None],
        names,
        count,
        &mut medium,
    )
    .expect("the deck is built either way");
    assert!(
        matches!(opened[0], Opened::Rebound(_)),
        "the log extent held another ring: {:?}",
        opened[0]
    );
    assert_eq!(opened[1], Opened::FreshMedium);

    // Fresh means fresh: the recording starts at sequence zero and its first
    // checkpoint replaces **both** copies, so no copy of the stranger's ring is
    // left for a later boot to prefer.
    let ring = Ring::new();
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 600, 8);
    let _ = download(&mut deck, &mut medium, &mut reader, DownloadSink::Log);
    let [log, _] = superblocks(&medium);
    assert_eq!(log.geometry().start_sector(), start_sector);
    assert_eq!(log.writer().sequence, 0);
    let image = medium.extent(start_sector, (SUPERBLOCK_BYTES / SECTOR_SIZE) as u64);
    let (first, second) = image.split_at(SUPERBLOCK_COPY_BYTES);
    let decode = |bytes: &[u8]| {
        let bytes: &[u8; SUPERBLOCK_COPY_BYTES] = bytes.try_into().expect("one sector");
        let mut region = [0u8; SUPERBLOCK_BYTES];
        region[..SUPERBLOCK_COPY_BYTES].copy_from_slice(bytes);
        region[SUPERBLOCK_COPY_BYTES..].copy_from_slice(bytes);
        lfw_capture_ring::decode_superblock(&region).expect("a decodable copy")
    };
    for copy in [decode(first), decode(second)] {
        assert_eq!(
            copy.geometry().start_sector(),
            start_sector,
            "a copy of the stranger's ring survived the first checkpoint"
        );
    }
}

#[test]
fn a_stored_state_this_deployment_cannot_use_never_stops_the_other_recording() {
    // Both extents are independent: one rebound must not cost the other its
    // resume, and neither must cost the deck its build.
    let mut medium = Fake::new();
    let first = boot(&mut medium, &Ring::new(), 8);
    assert_eq!(first, [Opened::FreshMedium, Opened::FreshMedium]);
    let [_, capture] = superblocks(&medium);

    let (start_sector, sectors) = Which::Log.extent();
    let elsewhere = Geometry::new(start_sector, sectors * 2, SEGMENT_BYTES, CAPACITY_SECTORS)
        .expect("a legal geometry that is not this extent's");
    let rebound = lfw_capture_ring::RingState::new(
        elsewhere,
        3,
        lfw_capture_ring::Cursor {
            sequence: 1,
            offset: 0,
        },
        &[],
    )
    .expect("a cursor inside the geometry");

    let (names, count) = interfaces();
    let (_deck, opened) = Deck::new(
        CAPACITY_SECTORS,
        [Some(rebound), Some(capture)],
        names,
        count,
        &mut medium,
    )
    .expect("the deck is built either way");
    assert!(matches!(opened[0], Opened::Rebound(_)));
    assert!(matches!(opened[1], Opened::Resumed { .. }));
}

#[test]
fn a_completion_for_a_boot_time_read_reaching_the_pass_is_counted_and_never_settled() {
    // The reads finish before the pass exists, so one answered inside it is a
    // device replaying its used ring — counted like every other completion
    // nothing is waiting on, and never taken as an answer to anything.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    medium.forge(Job::Preload(Which::Log));
    medium.forge(Job::Preload(Which::Capture));
    let mut scratch = [0u8; TAP_SNAP_LEN];
    deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
    assert_eq!(deck.counters().completions_unexpected, 2);
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
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
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

/// **The selection law, both ways.** The connection history holds an observation
/// that carries an event; the capture holds an observation *of a frame*. So the
/// record for a flow the appliance ended goes to the log alone — a capture is the
/// frames themselves, and that one was on no wire — while traffic on a
/// conversation already accounted for goes to the capture alone.
///
/// Both directions in one test because they are one decision: a sink that took
/// everything, or that took nothing frameless, would fail exactly one of the two.
#[test]
fn a_revoked_flow_reaches_the_connection_history_and_not_the_capture() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    {
        let mut writer = ring.writer();
        let frame = vec![0xAB; 100];
        // An opening, which both take; a packet on the running conversation, which
        // only the capture takes; and the revocation, which only the log takes.
        writer
            .write(&annotation(0, 0), 100, &frame)
            .expect("the ring holds three");
        writer
            .write(&unremarkable(1, 0), 100, &frame)
            .expect("the ring holds three");
        writer
            .write(&revocation(2, 0), 0, &[])
            .expect("the ring holds three");
    }
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..12 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
    }

    let counters = deck.counters();
    assert_eq!(counters.tap_records, 3, "every observation was drained");
    assert_eq!(
        counters.sinks[Which::Log.index()].records,
        2,
        "the opening and the revocation carry an event; the traffic between them does not"
    );
    assert_eq!(
        counters.sinks[Which::Capture.index()].records,
        2,
        "the two frames, and not the record that is about no frame"
    );
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
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
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
        /// Where the recording now begins, which is the whole of what makes an
        /// overrun something a reader carries on from. Nothing here matches on
        /// it: a resumed recording no longer refuses a position an earlier boot
        /// shipped, so the only way to reach this arm is a wrap, and where a
        /// wrap sends a reader is held at sink level on a ring small enough to
        /// wrap in a test.
        #[expect(dead_code, reason = "read by the Debug a failing match prints")]
        u64,
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
        deck.poll(medium, reader, scratch, clock(), None, None);
        if let Some(served) = deck.answer(medium) {
            return Some(match served {
                Served::Deliver {
                    bytes, total_len, ..
                } => Answer::Bytes(bytes.to_vec(), total_len),
                Served::Refuse {
                    reason,
                    total_len,
                    first,
                    ..
                } => Answer::Refused(reason, total_len, first),
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
        deck.demand(ring_demand(sink, offset, DOWNLOAD_WINDOW_LEN));
        match pump(deck, medium, reader, &mut scratch, 32) {
            Some(Answer::Bytes(bytes, _)) if bytes.is_empty() => break,
            Some(Answer::Bytes(bytes, _)) => {
                offset += bytes.len() as u64;
                body.extend_from_slice(&bytes);
            }
            Some(Answer::Refused(reason, ..)) => {
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
fn a_read_of_an_untouched_recording_delivers_no_packets_and_seals_nothing() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();

    // A reader is offered what the medium has taken and never more, and asking
    // is not what makes a recording durable: nothing seals on a reader's
    // account, so an untouched recording yields the records it holds — none —
    // rather than a segment padded out to be shown.
    let body = download(&mut deck, &mut medium, &mut reader, DownloadSink::Capture);
    let (_, packets) = walk(&body);
    assert_eq!(packets, 0, "nothing has been observed yet");
    assert_eq!(
        deck.counters().sinks[0].segments_closed,
        0,
        "a read sealed a segment"
    );
    // And the second read agrees with the first: a read is a read.
    assert_eq!(
        download(&mut deck, &mut medium, &mut reader, DownloadSink::Capture),
        body,
        "two reads of one recording disagreed"
    );
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
    deck.demand(ring_demand(
        DownloadSink::Capture,
        body.len() as u64 + 1,
        64,
    ));
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
fn a_read_the_medium_fails_answers_a_device_error_rather_than_hanging() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 128, 8);

    let mut scratch = [0u8; TAP_SNAP_LEN];
    // Everything the run staged reaches the medium first, so the read the
    // demand below issues is the operation the failure lands on.
    for _ in 0..8 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
    }
    deck.demand(ring_demand(DownloadSink::Log, 0, DOWNLOAD_WINDOW_LEN));
    medium.fail = 1;
    let served = pump(&mut deck, &mut medium, &mut reader, &mut scratch, 16);
    match served {
        Some(Answer::Refused(reason, ..)) => assert_eq!(reason, DownloadRefusal::DeviceError),
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
    deck.demand(ring_demand(DownloadSink::Log, 0, DOWNLOAD_WINDOW_LEN));
    match pump(&mut deck, &mut medium, &mut reader, &mut scratch, 16) {
        Some(Answer::Refused(reason, ..)) => assert_eq!(reason, DownloadRefusal::DeviceError),
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
    deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
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
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
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
    deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);

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
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
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
        deck.poll(&mut medium, &mut reader, &mut scratch, None, None, None);
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
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
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
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
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

/// The positions in `order` a job of exactly this shape was handed over at.
fn positions(order: &[Job], wanted: Job) -> Vec<usize> {
    order
        .iter()
        .enumerate()
        .filter(|(_, job)| **job == wanted)
        .map(|(at, _)| at)
        .collect()
}

#[test]
fn every_superblock_is_submitted_behind_a_barrier_and_the_payload_it_describes() {
    // The whole of what the barrier buys, and it is an ordering rather than a
    // count: a device is free to commit writes out of order and to hold earlier
    // ones in a cache, so a superblock published before the payload's write is on
    // the medium leaves an extent whose own durable cursor points into bytes that
    // were never written. Asserting that a barrier merely happened would pass on
    // exactly that.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 200, 8);

    for which in [Which::Log, Which::Capture] {
        let checkpoints = positions(&medium.order, Job::Checkpoint(which));
        let barriers = positions(&medium.order, Job::Barrier(which));
        let flushes = positions(&medium.order, Job::Flush(which));
        assert!(
            !checkpoints.is_empty(),
            "{which:?} never checkpointed, so the ordering is untested"
        );
        let first_checkpoint = checkpoints[0];
        let barrier_before = barriers
            .iter()
            .copied()
            .find(|at| *at < first_checkpoint)
            .expect("a superblock went out with no barrier ahead of it");
        assert!(
            flushes.iter().any(|at| *at < barrier_before),
            "the barrier at {barrier_before} ordered nothing: no payload write preceded it"
        );
        for at in &checkpoints {
            assert!(
                barriers.iter().any(|barrier| barrier < at),
                "the superblock at {at} was submitted with no barrier ahead of it"
            );
        }
    }
}

#[test]
fn a_barrier_the_device_fails_leaves_the_superblock_unwritten_rather_than_unordered() {
    // An extent claiming bytes the device may not hold is worse than one claiming
    // none, so the checkpoint is abandoned. The recording itself keeps going.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    // Every write is taken and every flush is refused, which is the device this
    // separation exists for: the payload reaches the medium and nothing orders
    // the superblock against it.
    medium.fail_barriers = usize::MAX;
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 200, 8);

    assert!(
        medium
            .order
            .iter()
            .any(|job| matches!(job, Job::Barrier(_))),
        "no barrier was attempted, so nothing about failing one is tested"
    );
    assert!(
        !medium
            .order
            .iter()
            .any(|job| matches!(job, Job::Checkpoint(_))),
        "a superblock went out behind a barrier the device had failed"
    );
    assert!(
        deck.counters().medium_failures > 0,
        "a failed barrier is counted like every other failed transfer"
    );
    // And the recording itself is unaffected: an unwritten checkpoint costs the
    // extent its statement of where it ends, never a record.
    assert!(
        deck.counters().sinks[0].records > 0,
        "the recording stopped because a checkpoint could not be ordered"
    );
}

#[test]
fn a_device_that_negotiated_no_flush_still_checkpoints_without_one() {
    // The rings are deliberately temporary, so a device with no flush gets a
    // weaker recording rather than none: waiting for a barrier it will never
    // complete would leave every extent claiming nothing durable forever.
    let mut medium = Fake::without_flush();
    let (log_start, _) = Deck::extents()[0];
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 200, 8);

    assert!(
        positions(&medium.order, Job::Barrier(Which::Log)).is_empty(),
        "a barrier was submitted to a device that never negotiated one"
    );
    let image = medium.extent(log_start, (SUPERBLOCK_BYTES / SECTOR_SIZE) as u64);
    let image: &[u8; SUPERBLOCK_BYTES] = image.try_into().expect("two sectors");
    let found = lfw_capture_ring::decode_superblock(image).expect("a decodable superblock");
    assert!(
        found.writer().offset > 0,
        "no checkpoint reached a device with no flush, so its extent says nothing durable"
    );
}

#[test]
fn a_forged_barrier_completion_releases_no_superblock() {
    // The device's one route to publishing a superblock ahead of its payload:
    // answer a barrier nothing took. It is counted and changes nothing, on the
    // same terms as every other unattributable completion.
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    medium.forge(Job::Barrier(Which::Log));
    medium.forge(Job::Barrier(Which::Capture));
    let mut scratch = [0u8; TAP_SNAP_LEN];
    deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);

    assert_eq!(
        deck.counters().completions_unexpected,
        2,
        "a barrier nothing awaited must be counted, not acted on"
    );
    assert!(
        positions(&medium.order, Job::Checkpoint(Which::Log)).is_empty(),
        "a forged barrier released a superblock"
    );
}

// --- the channel's ring cursor ----------------------------------------------

/// Read a whole ring the way the management channel's cursor reads one: from
/// absolute position zero, one bounded shipment at a time.
fn ship(
    deck: &mut Deck,
    medium: &mut Fake,
    reader: &mut wire::TapReader<'_>,
    sink: DownloadSink,
    at_most: usize,
) -> Vec<u8> {
    let mut scratch = [0u8; TAP_SNAP_LEN];
    let mut body = Vec::new();
    let mut position = 0u64;
    for _ in 0..256 {
        deck.demand(ring_demand(sink, position, at_most));
        match pump(deck, medium, reader, &mut scratch, 32) {
            Some(Answer::Bytes(bytes, _)) if bytes.is_empty() => break,
            Some(Answer::Bytes(bytes, _)) => {
                assert!(bytes.len() <= at_most, "a shipment past what was asked for");
                position += bytes.len() as u64;
                body.extend_from_slice(&bytes);
            }
            Some(Answer::Refused(reason, ..)) => {
                panic!("the recorder refused a ring read of its own recording: {reason:?}")
            }
            None => panic!("a ring read went unanswered for thirty-two passes"),
        }
    }
    body
}

#[test]
fn a_ring_cursor_reads_the_same_bytes_a_download_would() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 20, 400, 8);

    // Read up the channel first: it seals nothing, so what it sees is what the
    // medium already held. The download that follows seals, which is why the
    // shipped run is a prefix of the downloaded one rather than equal to it.
    let shipped = ship(&mut deck, &mut medium, &mut reader, DownloadSink::Log, 1024);
    assert!(!shipped.is_empty());
    let body = download(&mut deck, &mut medium, &mut reader, DownloadSink::Log);
    assert_eq!(
        body.get(..shipped.len()),
        Some(&shipped[..]),
        "the two readers disagree about the same recording"
    );
}

#[test]
fn a_ring_position_past_what_the_medium_took_answers_nothing_yet() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 4, 128, 8);

    let shipped = ship(
        &mut deck,
        &mut medium,
        &mut reader,
        DownloadSink::Capture,
        4096,
    );
    let mut scratch = [0u8; TAP_SNAP_LEN];
    deck.demand(ring_demand(
        DownloadSink::Capture,
        shipped.len() as u64 + 1,
        64,
    ));
    match pump(&mut deck, &mut medium, &mut reader, &mut scratch, 16) {
        Some(Answer::Bytes(bytes, total_len)) => {
            assert!(bytes.is_empty());
            assert_eq!(
                total_len,
                shipped.len() as u64,
                "the total a ring reader is given is the durable end of its ring"
            );
        }
        other => panic!("past the durable end is not a refusal: {other:?}"),
    }
}

#[test]
fn a_read_never_seals_the_recording_it_reads() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    run(&mut deck, &mut medium, &ring, &mut reader, 12, 300, 8);
    let mut scratch = [0u8; TAP_SNAP_LEN];

    // A read is a read: it pads nothing, so a reader cannot make the recording
    // write on its account however often it asks.
    let sealed = deck.counters().sinks[0].padding_bytes;
    for position in [0u64, 512] {
        deck.demand(ring_demand(DownloadSink::Log, position, 512));
        match pump(&mut deck, &mut medium, &mut reader, &mut scratch, 32) {
            Some(Answer::Bytes(bytes, _)) => assert!(!bytes.is_empty()),
            other => panic!("a read of a written recording is served: {other:?}"),
        }
        assert_eq!(
            deck.counters().sinks[0].padding_bytes,
            sealed,
            "a read wrote padding into the recording"
        );
    }
}

// ---------------------------------------------------------------------------
// The metric reading a recording carries
// ---------------------------------------------------------------------------

/// A Custom Block's enterprise number and the byte behind it, read out of a
/// recording exactly as a management server does: by block type, then by the
/// leading byte that tells a reading from the padding.
const CUSTOM_BLOCK: u32 = 0x0000_0BAD;

/// Every Custom Block in a stream, as `(pen, data)`, walked by length.
fn customs(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(header) = bytes.get(at..at + 8) {
        let kind = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if len < BLOCK_FRAMING_LEN || !len.is_multiple_of(4) || at + len > bytes.len() {
            break;
        }
        if kind == CUSTOM_BLOCK
            && let Some(body) = bytes.get(at + 8..at + len - 4)
            && let Some(pen) = body.get(..4)
        {
            found.push((
                u32::from_le_bytes([pen[0], pen[1], pen[2], pen[3]]),
                body[4..].to_vec(),
            ));
        }
        at += len;
    }
    found
}

/// Every kind-1 Custom Block in a stream, decoded.
fn readings(bytes: &[u8]) -> Vec<lfw_metrics::MetricSnapshot> {
    customs(bytes)
        .into_iter()
        .filter_map(|(_pen, data)| lfw_metrics::decode_snapshot(&data).ok())
        .collect()
}

/// A relay holding one reading, at generation 2.
fn published(unix_nanos: u64, first: u64) -> Box<StatsRelay> {
    let relay = Box::new(StatsRelay::zero());
    let mut values = [0u64; lfw_metrics::SNAPSHOT_SLOTS];
    for (slot, value) in values.iter_mut().enumerate() {
        *value = first.wrapping_add(slot as u64);
    }
    relay.publish(unix_nanos, &values);
    relay
}

/// The payload of one recording: its extent past segment 0, which carries the
/// superblock and no block a pcapng reader walks.
fn payload(medium: &Fake, which: Which) -> &[u8] {
    let (start, sectors) = which.extent();
    medium.extent(start + SEGMENT_SECTORS, sectors - SEGMENT_SECTORS)
}

/// Publish, poll until the reading is framed, then seal the log recording so the
/// part-sector holding it reaches the device. Bounded by passes throughout —
/// never by elapsed time — because a device that never completes must end the
/// test rather than hang it.
fn settle(
    deck: &mut Deck,
    medium: &mut Fake,
    reader: &mut wire::TapReader<'_>,
    relay: &StatsRelay,
    passes: usize,
) {
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..passes {
        deck.poll(medium, reader, &mut scratch, clock(), Some(relay), None);
    }
    // A download seals the recording, which is what puts the last part-sector on
    // the medium; without it the block is staged and the disk is simply shorter.
    let _ = download(deck, medium, reader, DownloadSink::Log);
}

#[test]
fn a_published_reading_reaches_the_log_recording_and_decodes() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let relay = published(1_785_443_220_000_000_000, 7);
    settle(&mut deck, &mut medium, &mut reader, &relay, 8);
    assert_eq!(deck.counters().snapshots_written, 1);
    assert_eq!(deck.counters().snapshots_dropped, 0);

    let held = readings(payload(&medium, Which::Log));
    assert_eq!(held.len(), 1, "the log recording holds one reading");
    assert_eq!(held[0].unix_nanos, 1_785_443_220_000_000_000);
    assert_eq!(held[0].values[0], 7);
    assert_eq!(held[0].values[1], 8);
}

/// The capture recording is deliberately not offered one: its rate is three to
/// four orders of magnitude higher, so a reading placed there would be swept
/// past by traffic before anybody read it.
#[test]
fn the_capture_recording_carries_no_reading() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let relay = published(1, 1);
    settle(&mut deck, &mut medium, &mut reader, &relay, 8);
    let _ = download(&mut deck, &mut medium, &mut reader, DownloadSink::Capture);
    assert!(readings(payload(&medium, Which::Capture)).is_empty());
}

/// The generation is the pace. A relay that has not moved is read on every pass
/// and framed on none of them, which is what keeps the recording's snapshot rate
/// the publisher's rather than the poll loop's.
#[test]
fn a_reading_is_framed_once_per_publish_however_often_it_is_polled() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let relay = published(1, 1);
    settle(&mut deck, &mut medium, &mut reader, &relay, 8);
    assert_eq!(deck.counters().snapshots_written, 1);

    relay.publish(2, &[9u64; 4]);
    settle(&mut deck, &mut medium, &mut reader, &relay, 8);
    assert_eq!(deck.counters().snapshots_written, 2);

    let held = readings(payload(&medium, Which::Log));
    assert_eq!(held.len(), 2);
    assert_eq!(held[1].unix_nanos, 2);
    // The second publish is shorter than the catalogue, and the slots it did not
    // reach read zero rather than the first reading's tail.
    assert_eq!(held[1].values[0], 9);
    assert_eq!(held[1].values[5], 0);
}

/// A publisher caught mid-write costs a counted miss and nothing else: the next
/// pass asks again, and no half-written reading reaches the medium.
#[test]
fn a_publisher_caught_mid_write_costs_a_counted_miss() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let relay = Box::new(StatsRelay::zero());
    let mut scratch = [0u8; TAP_SNAP_LEN];

    // A zeroed region is a publisher that has published nothing, which reads the
    // same way a torn one does and is counted the same way.
    for _ in 0..4 {
        deck.poll(
            &mut medium,
            &mut reader,
            &mut scratch,
            clock(),
            Some(&relay),
            None,
        );
    }
    assert_eq!(deck.counters().snapshots_missed, 4);
    assert_eq!(deck.counters().snapshots_written, 0);
    assert!(readings(payload(&medium, Which::Log)).is_empty());
}

/// No relay at all — the shape a host test or an unmapped region has — writes
/// nothing and counts nothing.
#[test]
fn a_deck_offered_no_relay_frames_nothing() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..8 {
        deck.poll(&mut medium, &mut reader, &mut scratch, clock(), None, None);
    }
    let counters = deck.counters();
    assert_eq!(counters.snapshots_written, 0);
    assert_eq!(counters.snapshots_missed, 0);
    assert_eq!(counters.snapshots_dropped, 0);
}

/// A reading placed among observations leaves both readable: the packet blocks
/// are still there and still in order, which is the property a reader that does
/// not know this enterprise number depends on.
#[test]
fn a_reading_between_observations_leaves_the_recording_parseable() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let relay = published(5, 5);

    // Observations, a reading, then more observations, so the reading sits
    // between packet blocks rather than behind all of them. One writer for the
    // whole test, as the forwarding domain has one for its life: a second would
    // restart at slot zero.
    let mut writer = ring.writer();
    let frame = [0xABu8; 64];
    for packet_id in 0..4u64 {
        writer
            .write(&annotation(packet_id, 0), frame.len() as u32, &frame)
            .expect("the ring holds four");
    }
    settle(&mut deck, &mut medium, &mut reader, &relay, 8);
    relay.publish(6, &[6u64; 8]);
    for packet_id in 4..8u64 {
        writer
            .write(&annotation(packet_id, 0), frame.len() as u32, &frame)
            .expect("the ring holds four more");
    }
    settle(&mut deck, &mut medium, &mut reader, &relay, 8);

    let bytes = payload(&medium, Which::Log);
    let (sections, packets) = walk(bytes);
    assert_eq!(sections, 1);
    assert_eq!(
        packets, 8,
        "the observations survived the readings among them"
    );
    assert_eq!(readings(bytes).len(), 2);
}

/// The padding that fills the slack behind a sector shares this block type and
/// this enterprise number, and is told apart by its leading zero. Every padding
/// block a recording holds must therefore decode as padding and never as a
/// reading — the property every recording ever written rests on.
#[test]
fn the_padding_a_recording_holds_is_never_read_as_a_reading() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let relay = published(9, 9);
    run(&mut deck, &mut medium, &ring, &mut reader, 16, 128, 32);
    settle(&mut deck, &mut medium, &mut reader, &relay, 8);

    let bytes = payload(&medium, Which::Log);
    let blocks = customs(bytes);
    assert!(blocks.len() > 1, "the recording holds padding as well");
    let mut padding = 0;
    for (pen, data) in &blocks {
        assert_eq!(*pen, lfw_pcapng::UNREGISTERED_PEN);
        match lfw_metrics::decode_snapshot(data) {
            Ok(_reading) => assert_eq!(data.first(), Some(&1)),
            Err(lfw_metrics::SnapshotDecodeError::Padding) => {
                padding += 1;
                assert!(data.iter().all(|byte| *byte == 0));
            }
            Err(other) => panic!("a block a recording holds decoded as {other:?}"),
        }
    }
    assert!(padding > 0, "no padding block was written at all");
}

// ── The console transcript, out of the relay and into the log recording ──────

/// Every kind-2 Custom Block in a stream, as the lines it carried.
fn transcript(bytes: &[u8]) -> Vec<(u8, Option<u64>, String)> {
    let mut lines = Vec::new();
    for (_pen, data) in customs(bytes) {
        let _ = wire::decode_transcript(&data, |line| {
            lines.push((
                line.origin,
                line.unix_nanos,
                String::from_utf8_lossy(line.line).into_owned(),
            ))
        });
    }
    lines
}

/// The two relay regions, on the heap because one is a page.
struct Lines {
    relay: Box<wire::LogRelay>,
    consume: Box<wire::LogRelayConsume>,
}

fn lines() -> Lines {
    Lines {
        relay: Box::new(wire::LogRelay::zero()),
        consume: Box::new(wire::LogRelayConsume::zero()),
    }
}

impl Lines {
    fn writer(&self) -> wire::LogRelayWriter<'_> {
        self.relay.writer(&self.consume)
    }

    fn transcript(&self) -> Transcript<'_> {
        Transcript::new(self.consume.reader(&self.relay))
    }
}

/// As [`settle`], driving the transcript relay instead of the metric one.
fn settle_transcript(
    deck: &mut Deck,
    medium: &mut Fake,
    reader: &mut wire::TapReader<'_>,
    transcript: &mut Transcript<'_>,
    passes: usize,
) {
    let mut scratch = [0u8; TAP_SNAP_LEN];
    for _ in 0..passes {
        deck.poll(
            medium,
            reader,
            &mut scratch,
            clock(),
            None,
            Some(transcript),
        );
    }
    let _ = download(deck, medium, reader, DownloadSink::Log);
}

#[test]
fn published_console_lines_reach_the_log_recording_and_decode() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let region = lines();
    let mut writer = region.writer();
    assert!(writer.publish(
        0,
        None,
        b"LFW-PD time=unsynchronized domain=forwarder state=ready"
    ));
    assert!(writer.publish(
        6,
        Some(1_785_443_220_000_000_000),
        b"LFW-PD domain=recorder state=ready"
    ));
    let mut held = region.transcript();
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 8);

    assert_eq!(
        deck.counters().transcripts_written,
        1,
        "one batch, two lines"
    );
    assert_eq!(deck.counters().transcript_lines, 2);
    assert_eq!(deck.counters().transcripts_dropped, 0);

    let carried = transcript(payload(&medium, Which::Log));
    assert_eq!(carried.len(), 2);
    assert_eq!(carried[0].0, 0);
    assert_eq!(carried[0].1, None);
    assert!(carried[0].2.contains("domain=forwarder"));
    assert_eq!(carried[1].0, 6);
    assert_eq!(carried[1].1, Some(1_785_443_220_000_000_000));
}

/// The capture recording is deliberately not offered the transcript either, for
/// the reason it is offered no reading.
#[test]
fn the_capture_recording_carries_no_transcript() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let region = lines();
    assert!(
        region
            .writer()
            .publish(0, None, b"LFW-PD domain=console state=ready")
    );
    let mut held = region.transcript();
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 8);
    let _ = download(&mut deck, &mut medium, &mut reader, DownloadSink::Capture);
    assert!(transcript(payload(&medium, Which::Capture)).is_empty());
}

/// A relay that has not moved is read on every pass and framed on none of them,
/// so the recording carries one batch per burst of lines rather than one per
/// pass — which is what keeps a busy poll loop from filling the medium with
/// empty batches.
#[test]
fn an_empty_relay_frames_nothing_however_often_it_is_polled() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let region = lines();
    let mut held = region.transcript();
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 12);
    assert_eq!(deck.counters().transcripts_written, 0);
    assert_eq!(deck.counters().transcript_lines, 0);
    assert!(transcript(payload(&medium, Which::Log)).is_empty());

    assert!(
        region
            .writer()
            .publish(0, None, b"LFW-PD domain=clock state=ready")
    );
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 12);
    assert_eq!(deck.counters().transcripts_written, 1);
    assert_eq!(deck.counters().transcript_lines, 1);
}

/// Every line the relay holds goes into one batch, so a full relay costs one
/// block and not fifteen.
#[test]
fn a_full_relay_becomes_one_batch() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let region = lines();
    let mut writer = region.writer();
    let capacity = writer.capacity();
    for index in 0..capacity {
        let line = std::format!("LFW-CFG time=unsynchronized generation={index} outcome=applied");
        assert!(writer.publish(3, Some(u64::from(index)), line.as_bytes()));
    }
    let mut held = region.transcript();
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 8);
    assert_eq!(deck.counters().transcripts_written, 1);
    assert_eq!(deck.counters().transcript_lines, u64::from(capacity));
    assert_eq!(
        transcript(payload(&medium, Which::Log)).len(),
        capacity as usize
    );
}

/// The console's own drop count crosses to the domain that publishes it, which is
/// how a gap in a recorded transcript becomes a number an operator can reading.
#[test]
fn the_consoles_drop_count_is_visible_to_the_recorder() {
    let region = lines();
    let mut writer = region.writer();
    for _ in 0..writer.capacity() {
        assert!(writer.publish(0, None, b"line"));
    }
    assert!(!writer.publish(0, None, b"refused"));
    let held = region.transcript();
    assert_eq!(held.dropped_by_console(), 1);
}

/// The widest line the console grammar renders survives the whole path, which is
/// what keeps a refusal — the widest shape there is — out of a truncation.
#[test]
fn the_widest_line_survives_the_relay_and_the_block() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let region = lines();
    let widest: Vec<u8> = core::iter::repeat_n(b'~', wire::RELAY_LINE_BYTES).collect();
    assert!(region.writer().publish(9, None, &widest));
    let mut held = region.transcript();
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 8);
    let carried = transcript(payload(&medium, Which::Log));
    assert_eq!(carried.len(), 1);
    assert_eq!(carried[0].2.len(), wire::RELAY_LINE_BYTES);
}

/// A line is released from the relay exactly once. A batch framed twice would
/// duplicate the transcript in the recording, and a reader has no way to tell a
/// duplicated line from a repeated one.
#[test]
fn a_line_is_framed_once_however_many_passes_follow() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let region = lines();
    assert!(
        region
            .writer()
            .publish(0, None, b"LFW-PD domain=store state=ready")
    );
    let mut held = region.transcript();
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 24);
    assert_eq!(deck.counters().transcripts_written, 1);
    assert_eq!(deck.counters().transcript_lines, 1);
    assert_eq!(transcript(payload(&medium, Which::Log)).len(), 1);
}

/// A batch the recording cannot take yet is offered again rather than lost: the
/// lines are peeked and released only once the block is placed. Driven by a
/// device that acknowledges nothing, so the staging buffer is what a batch meets
/// — and bounded by passes throughout, never by elapsed time.
#[test]
fn a_batch_the_recording_defers_is_offered_again_and_loses_nothing() {
    let mut medium = Fake::new();
    let ring = Ring::new();
    let mut deck = deck(&mut medium);
    let mut reader = ring.reader();
    let region = lines();
    let mut writer = region.writer();
    let mut held = region.transcript();
    let mut scratch = [0u8; TAP_SNAP_LEN];

    // Every submission refused, so nothing leaves the staging buffer and it
    // fills; the batch then meets `StagingFull` rather than a placed block.
    medium.refuse = usize::MAX;
    let mut published = 0u32;
    for _ in 0..400 {
        if writer.publish(
            0,
            None,
            b"LFW-PD time=unsynchronized domain=store state=ready",
        ) {
            published += 1;
        }
        deck.poll(
            &mut medium,
            &mut reader,
            &mut scratch,
            clock(),
            None,
            Some(&mut held),
        );
    }
    let deferred = published - deck.counters().transcript_lines as u32;
    assert!(
        deferred > 0,
        "the staging buffer never filled, so nothing was deferred"
    );

    // Released, and every line that was deferred is still in the relay and still
    // reaches the recording: nothing was consumed on a block that was not placed.
    medium.refuse = 0;
    let before = deck.counters().transcript_lines;
    settle_transcript(&mut deck, &mut medium, &mut reader, &mut held, 64);
    assert!(
        deck.counters().transcript_lines > before,
        "the deferred lines were consumed rather than offered again"
    );
}
