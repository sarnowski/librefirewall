//! `lfw_recorder`'s recording pass and sink, and `lfw_capture_ring`'s
//! superblock and ring, under a byzantine forwarder, a byzantine management
//! domain and a hostile medium.
//!
//! Three harnesses live here, narrowest first — the order
//! [`crate::tests::HARNESSES`] is kept in and for the same reason. A defect in
//! the superblock shows up in all three, one in the sink in two, and only the
//! pass sees all three adversaries at once; the narrowest is the one worth
//! reading, so it is the one that fails first.
//!
//! * [`capture_superblock`] — the bytes read back off the medium, and the ring
//!   a decoded one is resumed into.
//! * [`recorder_sink`] — one recording: pcapng records encoded into a staging
//!   buffer and placed as whole sectors of an extent.
//! * [`recording_pass`] — the protection domain's whole pass, where the tap,
//!   the download channel and the device meet.
//!
//! # The adversary and the surface
//!
//! Three adversaries at once, which is why one harness drives them
//! together: the pass is where their inputs meet.
//!
//! * **A byzantine neighbour PD** on the tap: it writes annotation words and
//!   payload bytes into the shared slots and moves both cursors, so a captured
//!   length, an interface id, a verdict and a drop reason are all values it
//!   chose. The frame bytes behind them are **untrusted network traffic** one
//!   remove further out.
//! * **A byzantine neighbour PD** on the download channel: the sink, the offset
//!   and the length of a demand are the management domain's claims, and only
//!   this side knows how long a snapshot is.
//! * **A hostile or malfunctioning device** behind the medium: it refuses
//!   submits, fails transfers, and answers jobs nothing is waiting on.
//!
//! The superblock is the same medium's bytes read back, so arbitrary input is
//! exactly what `decode_superblock` faces on a fresh, corrupt or forged disk.
//!
//! # What is asserted
//!
//! * **Containment.** Every transfer the pass asks for lies inside the staging
//!   area it names *and* inside the device — the arbitrary-write invariant, and
//!   the one that matters most here because the recorder is the only domain
//!   that can put a byte on the medium.
//! * **Sector discipline.** Every transfer is a whole number of sectors at a
//!   sector-aligned offset, which is what makes "no sector is ever written
//!   twice" a property of the placement rather than of the encoder.
//! * **Boundedness.** A pass performs work bounded by the recorder's own
//!   constants: it drains at most `TAP_BUDGET` records and settles at most
//!   `COMPLETION_BUDGET` completions however many the peers offer.
//! * **Conservation.** No record the reader accepted is silently lost: the
//!   number a recording placed plus what it counted as dropped never exceeds
//!   what was drained, and one demand produces at most one answer.
//! * **A superblock is decoded or refused, never half-believed**, and a decoded
//!   one round-trips its geometry.
//! * **Nothing a decoded superblock says can address a byte outside the
//!   extent**, or inside the one segment the superblock itself occupies —
//!   neither its own cursors, nor any placement of the ring resumed from it.
//! * **A sink stays inside the buffer it was lent** and inside the extent it
//!   was configured with, and never promises a download more bytes than the
//!   device has taken.

use std::{collections::VecDeque, string::String, vec, vec::Vec};

use arbitrary::{Arbitrary, Unstructured};
use lfw_capture_ring::{
    Append, Copies, Cursor, Fit, Geometry, Located, MAX_READERS, Placement, ReaderCursor, Ring,
    SECTOR_SIZE, SUPERBLOCK_BYTES, SUPERBLOCK_COPY_BYTES, SUPERBLOCK_MAGIC, SUPERBLOCK_VERSION,
    decode_superblock, encode_superblock,
};
use lfw_recorder::deck::{
    Area, COMPLETION_BUDGET, Completion, Deck, Ended, Job, Medium, Polled, Refused, STAGING_END,
    Served, TAP_BUDGET, Transfer,
};
use lfw_recorder::{
    Flush, InterfaceName, Locate, MAX_INTERFACES, Recorded, Sink, SinkConfig, prologue_len,
};
use wire::{
    CheckedTap, DOWNLOAD_WINDOW_LEN, DownloadReply, DownloadRequest, DownloadSink, TAP_SNAP_LEN,
    TapAnnotation, TapClassification, TapConsume, TapDecision, TapDirection, TapDropReason,
    TapEvent, TapFlow, TapFlowState, TapOutcome, TapRecords, TapRule,
};

use crate::guard::Guarded;
use crate::{any_u16, any_u32, any_u64, next_op};

/// The device the harness attaches, in sectors. Large enough for both extents
/// and no larger, so a transfer past the last one is caught here.
const CAPACITY_SECTORS: u64 = 64 * 1024 * 1024 / SECTOR_SIZE as u64;

/// Steps one run performs, bounding the harness itself rather than the code:
/// the code's own bounds are what is asserted.
const MAX_STEPS: usize = 64;

/// One thing the adversaries do next, decoded from the input by hand.
///
/// By hand rather than derived, as every harness here does it: `arbitrary`'s
/// derive is not a dependency of this workspace, and the decoding is where the
/// *authority* each adversary has is expressed rather than merely its data.
enum Step {
    /// The forwarder publishes an observation. Every annotation field is the
    /// adversary's, including an interface no table has a row for and a decision
    /// whose flow, rule and event stand in no relation to each other.
    Observe {
        packet_id: u64,
        timestamp: u64,
        interface_id: u8,
        decision: TapDecision,
        frame: Vec<u8>,
    },
    /// The management domain asks for a window, at any offset and any length.
    Demand {
        sink: DownloadSink,
        offset: u64,
        len: u32,
    },
    /// The recorder runs a pass.
    Pass,
    /// The device refuses the next `count` submits.
    Refuse { count: usize },
    /// The device fails the next `count` transfers.
    Fail { count: usize },
    /// The device answers a job nothing is waiting on.
    Forge { job: Job },
    /// The device replays entries of its used ring, so the driver hands the
    /// pass a completion it could attribute to no job at all.
    Replay { count: usize },
    /// The device answers the next `count` reads `Ok` having moved less than
    /// they asked for, leaving the rest of the staging area holding whatever
    /// the previous transfer left in it.
    UnderDeliver { count: usize },
}

fn take_step(unstructured: &mut Unstructured<'_>) -> Option<Step> {
    let tag = u8::arbitrary(unstructured).ok()?;
    Some(match tag % 6 {
        0 => Step::Observe {
            packet_id: u64::arbitrary(unstructured).ok()?,
            timestamp: u64::arbitrary(unstructured).ok()?,
            interface_id: u8::arbitrary(unstructured).ok()?,
            decision: arbitrary_decision(unstructured)?,
            frame: {
                let len = u16::arbitrary(unstructured).ok()? as usize % (TAP_SNAP_LEN + 64);
                let byte = u8::arbitrary(unstructured).ok()?;
                vec![byte; len]
            },
        },
        1 => Step::Demand {
            sink: if bool::arbitrary(unstructured).ok()? {
                DownloadSink::Capture
            } else {
                DownloadSink::Log
            },
            offset: u64::arbitrary(unstructured).ok()?,
            len: u32::arbitrary(unstructured).ok()?,
        },
        2 | 3 => Step::Pass,
        4 => match u8::arbitrary(unstructured).ok()? % 5 {
            0 => Step::Refuse {
                count: u8::arbitrary(unstructured).ok()? as usize,
            },
            1 => Step::Fail {
                count: u8::arbitrary(unstructured).ok()? as usize,
            },
            2 => Step::Replay {
                count: u8::arbitrary(unstructured).ok()? as usize,
            },
            3 => Step::UnderDeliver {
                count: u8::arbitrary(unstructured).ok()? as usize,
            },
            _ => Step::Forge {
                job: forged_job(u8::arbitrary(unstructured).ok()?),
            },
        },
        _ => Step::Pass,
    })
}

/// A job the device may claim to be answering, which is any of the five this
/// recorder ever submits.
fn forged_job(bits: u8) -> Job {
    use lfw_recorder::Which;
    match bits % 5 {
        0 => Job::Flush(Which::Log),
        1 => Job::Flush(Which::Capture),
        2 => Job::Checkpoint(Which::Log),
        3 => Job::Checkpoint(Which::Capture),
        _ => Job::Fetch,
    }
}

/// The medium, asserting containment on every transfer it is handed.
struct Disk {
    window: Vec<u8>,
    disk: Vec<u8>,
    /// Each completion and whether the transfer it answers was cut short.
    ready: VecDeque<(Polled, bool)>,
    refuse: usize,
    fail: usize,
    /// Reads still to be answered `Ok` for one sector less than they asked for.
    under_deliver: usize,
    /// Short transfers whose completion the pass has actually taken. Counted on
    /// the way out rather than on the way in: one still sitting in the queue has
    /// reached no counter yet, and holding the pass to it would be asserting
    /// against a completion it was never handed.
    short_taken: u64,
    /// Whether the most recent read into the download area was cut short, and
    /// so whether that area's tail still holds the previous window's bytes.
    fetch_short: bool,
    /// Reads into the download area published and not yet answered.
    fetches_inflight: usize,
    /// Whether two reads into the download area were ever outstanding at once.
    ///
    /// A demand for offset zero arriving while a read is in flight starts a
    /// fresh seal and publishes a second read into the same area without
    /// cancelling the first, and either completion then promotes whichever read
    /// the pass currently holds. The window a download is answered from is then
    /// not the window that read filled — a reported finding, and one no
    /// assertion here can hold the pass to until it is decided.
    fetch_overlap: bool,
    /// Unattributable completions the pass has actually taken, each of which
    /// must reach a counter rather than ending the drain.
    replays_taken: u64,
    /// Completions minted for a job that was never submitted. Authority a real
    /// device does not hold — the protection domain attributes a completion
    /// through a token table it keeps outside the DMA region, so a replayed
    /// used-ring entry arrives as [`Polled::Unattributed`] and never as an
    /// answer to a job. Generated all the same, and recorded so the assertions
    /// that rest on the pass knowing what it submitted can say when they hold.
    forged: u64,
}

impl Disk {
    fn new() -> Self {
        Self {
            window: vec![0u8; STAGING_END],
            disk: vec![0u8; CAPACITY_SECTORS as usize * SECTOR_SIZE],
            ready: VecDeque::new(),
            refuse: 0,
            fail: 0,
            under_deliver: 0,
            short_taken: 0,
            fetch_short: false,
            fetches_inflight: 0,
            fetch_overlap: false,
            replays_taken: 0,
            forged: 0,
        }
    }
}

impl Medium for Disk {
    fn staging(&mut self, area: Area) -> &mut [u8] {
        let (offset, len) = area.extent();
        self.window
            .get_mut(offset..offset + len)
            .expect("the window holds every area the layout names")
    }

    fn submit(&mut self, job: Job, transfer: Transfer) -> Result<(), Refused> {
        // Containment, both ends, and sector discipline. Asserted before a byte
        // moves, because a transfer that failed either would be an arbitrary
        // write the device performs and the driver never sees.
        let (base, area_len) = transfer.area.extent();
        assert!(
            transfer.at.is_multiple_of(SECTOR_SIZE),
            "a transfer starts on a sector: {transfer:?}"
        );
        assert!(
            transfer.len.is_multiple_of(SECTOR_SIZE),
            "a transfer is whole sectors: {transfer:?}"
        );
        assert!(transfer.len > 0, "a zero-length transfer: {transfer:?}");
        assert!(
            transfer.at.saturating_add(transfer.len) <= area_len,
            "a transfer past its staging area: {transfer:?}"
        );
        let sectors = (transfer.len / SECTOR_SIZE) as u64;
        assert!(
            transfer
                .sector
                .checked_add(sectors)
                .is_some_and(|end| end <= CAPACITY_SECTORS),
            "a transfer past the device: {transfer:?}"
        );

        if self.refuse > 0 {
            self.refuse -= 1;
            return Err(Refused);
        }
        if self.fail > 0 {
            self.fail -= 1;
            self.ready.push_back((
                Polled::Settled(Completion {
                    job,
                    ended: Ended::Failed,
                }),
                false,
            ));
            return Ok(());
        }
        // A read cut short: the bytes past `moved` keep whatever the previous
        // transfer through this area left there, which is precisely the content
        // a pass must never serve as this window's.
        let moved = if !transfer.write && self.under_deliver > 0 {
            self.under_deliver -= 1;
            transfer.len.saturating_sub(SECTOR_SIZE)
        } else {
            transfer.len
        };
        if !transfer.write {
            self.fetch_short = moved < transfer.len;
            self.fetches_inflight += 1;
            self.fetch_overlap |= self.fetches_inflight > 1;
        }
        let offset = base + transfer.at;
        let at = transfer.sector as usize * SECTOR_SIZE;
        for byte in 0..moved {
            if transfer.write {
                self.disk[at + byte] = self.window[offset + byte];
            } else {
                self.window[offset + byte] = self.disk[at + byte];
            }
        }
        self.ready.push_back((
            Polled::Settled(Completion {
                job,
                ended: Ended::Ok { delivered: moved },
            }),
            moved < transfer.len,
        ));
        Ok(())
    }

    fn poll(&mut self) -> Option<Polled> {
        let (polled, short) = self.ready.pop_front()?;
        if polled == Polled::Unattributed {
            self.replays_taken += 1;
        }
        if let Polled::Settled(Completion {
            job: Job::Fetch, ..
        }) = polled
        {
            self.fetches_inflight = self.fetches_inflight.saturating_sub(1);
        }
        if short {
            self.short_taken += 1;
        }
        Some(polled)
    }
}

/// Everything the forwarder concluded, every field the adversary's.
///
/// The combinations are **not** reduced to the coherent ones. `wire`'s reader
/// refuses an incoherent annotation, so a sink only ever sees a coherent one —
/// and a harness that generated only those would be asserting that the sink is
/// total over exactly the inputs something else already guarantees. The same
/// argument the interface id is left unreduced under.
fn arbitrary_decision(unstructured: &mut Unstructured<'_>) -> Option<TapDecision> {
    Some(TapDecision {
        outcome: match u8::arbitrary(unstructured).ok()? {
            0 => TapOutcome::Forwarded,
            bits => TapOutcome::Dropped(drop_reason(bits)),
        },
        direction: if bool::arbitrary(unstructured).ok()? {
            TapDirection::Outbound
        } else {
            TapDirection::Inbound
        },
        generation: u32::arbitrary(unstructured).ok()?,
        flow: arbitrary_flow(unstructured)?,
        rule: TapRule::new(usize::from(u8::arbitrary(unstructured).ok()?)),
        event: arbitrary_event(u8::arbitrary(unstructured).ok()?),
    })
}

/// A flow the observation may name, or none. Indexed rather than matched, on
/// [`drop_reason`]'s terms.
fn arbitrary_flow(unstructured: &mut Unstructured<'_>) -> Option<Option<TapFlow>> {
    let tag = u8::arbitrary(unstructured).ok()?;
    if tag == 0 {
        return Some(None);
    }
    let classifications = [
        TapClassification::New,
        TapClassification::Established,
        TapClassification::Related,
    ];
    let states = [
        TapFlowState::SynSent,
        TapFlowState::SynReceived,
        TapFlowState::Established,
        TapFlowState::FinWait,
        TapFlowState::CloseWait,
        TapFlowState::Closing,
        TapFlowState::TimeWait,
        TapFlowState::Closed,
        TapFlowState::UdpUnreplied,
        TapFlowState::UdpAssured,
        TapFlowState::IcmpUnreplied,
        TapFlowState::IcmpReplied,
    ];
    Some(Some(TapFlow {
        slot: u32::arbitrary(unstructured).ok()?,
        generation: u32::arbitrary(unstructured).ok()?,
        classification: classifications[usize::from(tag) % classifications.len()],
        state: states[usize::from(u8::arbitrary(unstructured).ok()?) % states.len()],
    }))
}

/// An event the observation may carry, or none.
fn arbitrary_event(bits: u8) -> Option<TapEvent> {
    if bits == 0 {
        return None;
    }
    Some(TapEvent::ALL[usize::from(bits) % TapEvent::ALL.len()])
}

fn drop_reason(bits: u8) -> TapDropReason {
    // Every reason, indexed rather than matched: a reason added upstream is
    // then generated here without this harness needing an entry.
    let all = [
        TapDropReason::UnconfiguredIngressPort,
        TapDropReason::InterfaceDisabled,
        TapDropReason::NotAddressedToUs,
        TapDropReason::VlanTagged,
        TapDropReason::MartianSource,
        TapDropReason::UnroutableDestination,
        TapDropReason::AddressedToThisRouter,
        TapDropReason::TtlExpired,
        TapDropReason::NoRoute,
        TapDropReason::EgressIsIngress,
        TapDropReason::NoNeighbour,
    ];
    all[bits as usize % all.len()]
}

/// Drive the pass with everything three adversaries can express.
pub fn recording_pass(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);

    let records = Box::new(TapRecords::zero());
    let consume = Box::new(TapConsume::zero());
    let request = Box::new(DownloadRequest::zero());
    let reply = Box::new(DownloadReply::zero());

    let mut medium = Disk::new();
    let mut names = [InterfaceName::new(""); MAX_INTERFACES];
    if let Some(slot) = names.get_mut(0) {
        *slot = InterfaceName::new("port0");
    }
    let Ok(mut deck) = Deck::new(CAPACITY_SECTORS, names, 1, &mut medium) else {
        return;
    };
    let mut writer = records.writer(&consume);
    let mut reader = consume.reader(&records);
    let mut requester = request.requester(&reply);
    let mut responder = reply.responder(&request);
    let mut scratch = [0u8; TAP_SNAP_LEN];
    let mut answers = 0usize;
    let mut demands = 0usize;

    for _ in 0..MAX_STEPS {
        let Some(step) = take_step(&mut unstructured) else {
            break;
        };
        match step {
            Step::Observe {
                packet_id,
                timestamp,
                interface_id,
                decision,
                frame,
            } => {
                let annotation =
                    TapAnnotation::new(packet_id, timestamp, interface_id, decision);
                // The wire length is the frame's own, which is the one field a
                // first-party producer cannot get wrong; every other field
                // above is the adversary's.
                let original_len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
                let _ = writer.write(&annotation, original_len, &frame);
            }
            Step::Demand { sink, offset, len } => {
                let _pending = requester.request(sink, offset, len as usize);
                if let Some(demand) = responder.take() {
                    demands += 1;
                    deck.demand(demand);
                }
            }
            Step::Pass => {
                let before = deck.counters();
                deck.poll(&mut medium, &mut reader, &mut scratch, None);
                let after = deck.counters();
                // Boundedness: the pass's own constants, never the peers'.
                assert!(
                    after.tap_records + after.tap_refused
                        <= before.tap_records + before.tap_refused + TAP_BUDGET as u64,
                    "a pass drained more than its budget"
                );
                // Per counter rather than against their sum: one completion can
                // legitimately move both — a transfer the medium failed, or cut
                // short, that also answers a job this side no longer holds is a
                // failure *and* an unexpected completion. Each counter still
                // rises at most once per completion, which is what makes each
                // rise the bound on completions settled.
                assert!(
                    after.medium_failures
                        <= before
                            .medium_failures
                            .saturating_add(COMPLETION_BUDGET as u64),
                    "a pass settled more failed completions than its budget"
                );
                assert!(
                    after.completions_unexpected
                        <= before
                            .completions_unexpected
                            .saturating_add(COMPLETION_BUDGET as u64),
                    "a pass settled more unattributable completions than its budget"
                );
                // Read before the answer borrows the medium: the bytes handed
                // back point into its staging window.
                let forged = medium.forged;
                let fetch_short = medium.fetch_short;
                let overlap = medium.fetch_overlap;
                if let Some(served) = deck.answer(&mut medium) {
                    answers += 1;
                    match served {
                        Served::Deliver { demand, bytes, .. } => {
                            assert!(
                                bytes.len() <= demand.len(),
                                "more bytes delivered than were asked for"
                            );
                            assert!(bytes.len() <= DOWNLOAD_WINDOW_LEN);
                            // The read that filled this window moved every byte
                            // it was asked for. Otherwise the tail of the area
                            // still holds the previous window's content, and
                            // delivering it puts one part of the recording
                            // inside another's body under a correct length.
                            //
                            // Scoped to a run with no forged attributed
                            // completion, for the reason `Disk::forged` records:
                            // under one the pass is answering a fetch it
                            // believes completed, which is authority the real
                            // device does not have. And scoped past
                            // `Disk::fetch_overlap`, where two reads into the
                            // area were outstanding at once and the window a
                            // completion promotes is not the window it filled —
                            // a separate finding, recorded there.
                            assert!(
                                bytes.is_empty() || forged > 0 || overlap || !fetch_short,
                                "{} bytes were delivered out of a window the device \
                                 filled short",
                                bytes.len()
                            );
                            responder.deliver(demand, bytes, 0);
                        }
                        Served::Refuse { demand, reason, .. } => {
                            responder.refuse(demand, reason, 0);
                        }
                    }
                }
            }
            Step::Refuse { count } => medium.refuse = count,
            Step::Fail { count } => medium.fail = count,
            Step::UnderDeliver { count } => medium.under_deliver = count,
            Step::Replay { count } => {
                for _ in 0..count.min(MAX_STEPS) {
                    medium.ready.push_back((Polled::Unattributed, false));
                }
            }
            Step::Forge { job } => {
                medium.forged += 1;
                medium.ready.push_back((
                    Polled::Settled(Completion {
                        job,
                        // More than any transfer could have moved, so what the pass
                        // makes of a forged completion turns on the attribution and
                        // never on the byte count.
                        ended: Ended::Ok {
                            delivered: usize::MAX,
                        },
                    }),
                    false,
                ));
            }
        }
    }

    // Conservation: a recording never claims to have placed more than reached
    // it, and one demand never produces two answers.
    let counters = deck.counters();
    for sink in counters.sinks {
        assert!(
            sink.records + sink.dropped_oversized + sink.dropped_refused <= counters.tap_records,
            "a recording accounted for more records than were drained"
        );
    }
    assert!(
        answers <= demands,
        "more answers than demands: {answers} > {demands}"
    );
    assert_eq!(
        counters.downloads_served + counters.downloads_refused,
        answers as u64,
        "every answer is counted exactly once"
    );
    // A transfer the device completed `Ok` having moved less than it was given
    // is a failure however it reports itself: the shortfall is whatever the
    // staging area held before, and a pass that took it for a success would
    // serve one window's bytes inside another's body.
    //
    // Either counter is the right home depending on whether the pass still held
    // the transfer the completion answers: one it does hold and that came up
    // short is a medium failure, and one it no longer holds — the requester
    // having abandoned that window, or a forged completion having consumed the
    // state first — is an unexpected completion. What must never happen is
    // neither, which is a short transfer passing for a plain success.
    assert!(
        counters
            .medium_failures
            .saturating_add(counters.completions_unexpected)
            >= medium.short_taken,
        "{} short transfers were settled and only {} reached a fault surface",
        medium.short_taken,
        counters
            .medium_failures
            .saturating_add(counters.completions_unexpected)
    );
    // A completion answering no job must reach a counter rather than passing
    // for an idle device and ending the drain.
    assert!(
        counters.completions_unexpected >= medium.replays_taken,
        "{} unattributable completions were taken and only {} counted",
        medium.replays_taken,
        counters.completions_unexpected
    );
}

/// Steps the resumed ring is driven through, bounding the harness rather than
/// the code: every call below must return on its own, and what is asserted is
/// where its answer points.
const MAX_RING_STEPS: usize = 48;

/// A superblock is decoded or refused, never half-believed — and nothing a
/// decoded one says addresses a byte outside the extent.
///
/// # Two regions, and why the second is not a filter
///
/// A uniformly random kilobyte is refused at the magic, and on the vanishing
/// chance it is not, at the CRC. Every rule *behind* those two — a geometry
/// that is not a geometry, a writer past its segment, a reader ahead of the
/// writer, a repeated reader identifier, meaning in a byte this writer zeroes
/// — would then be unreachable, and the target would be a magic-number check
/// wearing a superblock's name.
///
/// So two regions are examined on every input. The first is the fuzzer's bytes
/// laid over the region exactly as the medium handed them back, which is the
/// adversary's full authority and is never narrowed. The second is a region
/// assembled field by field from the same input and finished with a *correct*
/// CRC, so it reaches `RingState::new` and `Geometry::new` with values nobody
/// filtered. Additive, in the sense that matters: the first region is
/// checked whatever the second contains, so nothing the fuzzer can express is
/// taken away by the targeting — what is added is the ability to express it
/// past the checksum, which an offline attacker holding the disk plainly has.
/// # How an input is laid out, and why it is cut rather than shared
///
/// The first [`SUPERBLOCK_BYTES`] are the region exactly as the medium handed
/// it back, so a corpus entry can be authored and read as the thing it is — the
/// same reason [`crate::handover::image_from_region`] lays its input over the
/// ABI positionally. Everything after them is the *script*: the ring operations
/// the resumed ring is driven through, and then the fields the forged region is
/// assembled from.
///
/// Cutting the input in two rather than reading both from one cursor is what
/// makes the second half mean anything. Sharing it, the forger consumed the
/// head of the script before the walk ever saw it, so every operation a seed
/// stated was read at an offset the seed did not choose — the walk still ran,
/// on bytes that happened to be a superblock's own fields, and no authored
/// sequence reached the code it was written for.
pub fn capture_superblock(data: &[u8]) {
    let split = data.len().min(SUPERBLOCK_BYTES);
    let (region, script) = data.split_at(split);
    let mut verbatim = [0u8; SUPERBLOCK_BYTES];
    for (slot, byte) in verbatim.iter_mut().zip(region) {
        *slot = *byte;
    }

    let mut unstructured = Unstructured::new(script);
    // The verbatim region first, so a script follows the region it belongs to.
    // A region that does not decode consumes nothing, which leaves the whole
    // script to the forged one below.
    examine_region(&verbatim, &mut unstructured);
    let forged = forged_region(&mut unstructured);
    examine_region(&forged, &mut unstructured);
}

/// Decode one region and hold everything it yields to the extent.
fn examine_region(region: &[u8; SUPERBLOCK_BYTES], unstructured: &mut Unstructured<'_>) {
    let Some(state) = decode_superblock(region) else {
        return;
    };

    // A decoded state describes a ring, and re-encoding it reproduces the copy
    // its generation selects: a decode that invented a field would not. Whole
    // equality rather than field by field, because a reader position dropped or
    // duplicated on the way through is exactly the loss this checkpoint exists
    // to prevent.
    let mut round = [0u8; SUPERBLOCK_BYTES];
    let written = encode_superblock(&mut round, &state, Copies::Parity);
    assert!(
        written.at == 0 || written.at == SUPERBLOCK_COPY_BYTES,
        "a superblock was written at {}, which is neither copy",
        written.at
    );
    assert_eq!(
        written.len, SUPERBLOCK_COPY_BYTES,
        "a parity write is one copy and no more, or it would overwrite the copy \
         the medium is relying on"
    );
    let again = decode_superblock(&round).expect("what this crate wrote it reads");
    assert_eq!(
        again, state,
        "a superblock did not survive being written and read back"
    );
    assert_crc_agrees(&round, written.at);

    // A ring with nothing of its own on the medium replaces both copies, so
    // whatever the extent already carried — here the adversary's own bytes,
    // which may be a valid ring of this very geometry at a far higher
    // generation — can never be preferred over what was just written.
    let mut occupied = *region;
    let both = encode_superblock(&mut occupied, &state, Copies::Both);
    assert_eq!(
        both,
        lfw_capture_ring::SuperblockWrite {
            at: 0,
            len: SUPERBLOCK_BYTES,
        },
        "a first checkpoint must replace the whole region"
    );
    assert_eq!(
        decode_superblock(&occupied),
        Some(state),
        "an older ring left in the other copy outranked a fresh checkpoint"
    );
    assert_crc_agrees(&occupied, 0);
    assert_crc_agrees(&occupied, SUPERBLOCK_COPY_BYTES);

    let stored = state.geometry();
    assert!(
        stored.segments() >= 2,
        "a ring with nothing to spare was decoded"
    );
    assert!(
        state.writer().offset <= stored.segment_bytes(),
        "a writer outside its segment was decoded"
    );

    // Two geometries the deployment might have been configured with: the one
    // that agrees with what the medium claims, which is the only way to reach
    // `Ring::resume` at all, and one that does not — a rebound extent, a disk
    // moved between deployments — and must be refused by name.
    let agreeing = Geometry::new(
        stored.start_sector(),
        stored.sectors(),
        stored.segment_bytes(),
        stored.start_sector().saturating_add(stored.sectors()),
    );
    let differing = deployment_geometry();

    for configured in [agreeing.ok(), differing].into_iter().flatten() {
        let Ok(checked) = state.check(&configured) else {
            // A refusal is a whole answer: the medium is holding somebody
            // else's ring, and nothing here may adopt it.
            continue;
        };
        assert_eq!(
            checked.geometry(),
            configured,
            "a checked state kept the geometry the medium claimed rather than the configured one"
        );
        assert_cursors_inside(&checked, &configured);
        resume_and_walk(checked, &configured, unstructured);
    }
}

/// Every cursor a checked state carries addresses a segment of the extent, and
/// never the one the superblock itself occupies.
fn assert_cursors_inside(checked: &lfw_capture_ring::CheckedState, geometry: &Geometry) {
    let writer = checked.writer();
    assert!(
        writer.offset <= geometry.segment_bytes(),
        "a checked writer sits {} bytes into a {}-byte segment",
        writer.offset,
        geometry.segment_bytes()
    );
    assert_segment_inside(geometry, writer.sequence, "the writer");

    let mut seen: [Option<u32>; MAX_READERS] = [None; MAX_READERS];
    for (slot, reader) in checked.readers().iter().flatten().enumerate() {
        assert!(
            reader.cursor.offset <= geometry.segment_bytes(),
            "reader {} sits {} bytes into a {}-byte segment",
            reader.id,
            reader.cursor.offset,
            geometry.segment_bytes()
        );
        assert!(
            reader.cursor.sequence <= writer.sequence,
            "reader {} was accepted at sequence {}, ahead of the writer's {}",
            reader.id,
            reader.cursor.sequence,
            writer.sequence
        );
        assert!(
            !seen.iter().flatten().any(|id| *id == reader.id),
            "two cursors were accepted under reader identifier {}",
            reader.id
        );
        if let Some(place) = seen.get_mut(slot) {
            *place = Some(reader.id);
        }
        assert_segment_inside(geometry, reader.cursor.sequence, "a reader");
    }
}

/// The segment a sequence names lies wholly inside the extent, and is not
/// segment 0 — which holds the superblock and which no record may reach.
fn assert_segment_inside(geometry: &Geometry, sequence: u64, who: &str) {
    let sector = geometry.segment_sector(sequence);
    let first_payload = geometry
        .start_sector()
        .checked_add(geometry.segment_sectors())
        .expect("a validated geometry's first payload sector");
    let extent_end = geometry
        .start_sector()
        .checked_add(geometry.sectors())
        .expect("a validated geometry's last sector");
    assert!(
        sector >= first_payload,
        "{who} at sequence {sequence} addresses sector {sector}, inside the superblock's own \
         segment"
    );
    assert!(
        sector
            .checked_add(geometry.segment_sectors())
            .is_some_and(|end| end <= extent_end),
        "{who} at sequence {sequence} addresses sector {sector}, outside the extent ending at \
         {extent_end}"
    );
}

/// A span this ring produced lies wholly inside one payload segment of the
/// extent — the arbitrary-write invariant, stated where the write is decided.
fn assert_placement_inside(placement: &Placement, geometry: &Geometry, what: &str) {
    let first_payload = geometry
        .start_sector()
        .checked_add(geometry.segment_sectors())
        .expect("a validated geometry's first payload sector");
    let extent_end = geometry
        .start_sector()
        .checked_add(geometry.sectors())
        .expect("a validated geometry's last sector");
    assert!(
        placement.sector() >= first_payload,
        "{what} placed bytes at sector {}, inside the superblock's own segment",
        placement.sector()
    );
    assert!(
        placement
            .sector()
            .checked_add(geometry.segment_sectors())
            .is_some_and(|end| end <= extent_end),
        "{what} placed bytes at sector {}, outside the extent ending at {extent_end}",
        placement.sector()
    );
    assert!(
        placement
            .byte_offset()
            .checked_add(placement.len())
            .is_some_and(|end| end <= geometry.segment_bytes()),
        "{what} placed {} bytes at offset {} of a {}-byte segment",
        placement.len(),
        placement.byte_offset(),
        geometry.segment_bytes()
    );
}

/// Resume a ring from an accepted superblock and drive it, holding every span
/// it hands back to the extent.
fn resume_and_walk(
    checked: lfw_capture_ring::CheckedState,
    geometry: &Geometry,
    unstructured: &mut Unstructured<'_>,
) {
    // Unreduced, so both sides of `opening_offset`'s cap are reachable: a
    // prologue longer than a segment leaves no payload at all, which the crate
    // documents as visible rather than refused.
    let prologue = any_u32(unstructured) as usize;
    let mut ring = Ring::resume(checked, prologue);
    assert_placement_inside(&ring.prologue(), geometry, "the resumed prologue");

    for _ in 0..MAX_RING_STEPS {
        let Some(op) = next_op(unstructured) else {
            break;
        };
        match op % 5 {
            0 | 1 | 2 => {
                let len = any_u32(unstructured) as usize;
                // `fit` and `append` are one decision reached two ways, so they
                // cannot be allowed to disagree about it.
                let expected = ring.fit(len);
                match (expected, ring.append(len)) {
                    (Fit::Fits(want), Append::Placed(reservation)) => {
                        let placement = reservation.placement();
                        assert_eq!(want, placement, "fit and append placed one record twice");
                        assert_placement_inside(&placement, geometry, "an append");
                        assert!(
                            placement.len() == len,
                            "a reservation of {} bytes was made for a {len}-byte record",
                            placement.len()
                        );
                        if len.is_multiple_of(2) {
                            reservation.commit();
                        }
                    }
                    (Fit::SegmentFull, Append::SegmentFull)
                    | (Fit::Oversized { .. }, Append::Oversized { .. }) => {}
                    (expected, actual) => panic!(
                        "fit answered {expected:?} where append answered {actual:?} for a \
                         {len}-byte record"
                    ),
                }
            }
            3 => {
                let placement = ring.roll();
                assert_placement_inside(&placement, geometry, "a rolled prologue");
            }
            _ => {
                let sequence = any_u64(unstructured);
                let offset = any_u32(unstructured) as usize;
                if let Located::Live(placement) = ring.locate(sequence, offset) {
                    assert_placement_inside(&placement, geometry, "a located span");
                    assert!(
                        !placement.is_empty(),
                        "a reader was pointed at a live span of no bytes"
                    );
                }
            }
        }
        assert!(
            ring.cursor().offset <= geometry.segment_bytes(),
            "the append cursor left its segment"
        );
        let (oldest, newest) = ring.readable();
        assert!(oldest <= newest, "the ring's history runs backwards");
    }

    // A checkpoint of whatever state the walk arrived at must round-trip, so a
    // cursor reachable by appending and rolling is one the medium can carry.
    let readers = arbitrary_readers(unstructured);
    let at = if any_u32(unstructured) % 2 == 0 {
        ring.cursor()
    } else {
        // A position behind the append cursor, which is what a caller holding a
        // staging buffer checkpoints: the superblock states what the medium has,
        // never what the writer has reached.
        Cursor {
            sequence: ring.cursor().sequence,
            offset: any_u32(unstructured) as usize % (geometry.segment_bytes() + 1),
        }
    };
    if let Ok(state) = ring.checkpoint(at, &readers) {
        let mut region = [0u8; SUPERBLOCK_BYTES];
        encode_superblock(&mut region, &state, Copies::Parity);
        let again = decode_superblock(&region).expect("what this crate wrote it reads");
        assert_eq!(
            again, state,
            "a checkpoint of a resumed ring did not survive the medium"
        );
    }
}

/// Reader cursors a caller may present at a checkpoint: identifiers and
/// positions taken whole, so a repeat and a position past the writer are both
/// ordinary inputs and the refusal is the code's to make.
fn arbitrary_readers(unstructured: &mut Unstructured<'_>) -> Vec<ReaderCursor> {
    let count = (any_u32(unstructured) as usize) % (MAX_READERS + 2);
    (0..count)
        .map(|_| ReaderCursor {
            id: any_u32(unstructured),
            cursor: Cursor {
                sequence: any_u64(unstructured),
                offset: any_u32(unstructured) as usize,
            },
        })
        .collect()
}

/// The extent this deployment configured, which a superblock describing some
/// other ring must be refused against.
fn deployment_geometry() -> Option<Geometry> {
    Geometry::new(
        SINK_START_SECTOR,
        SINK_EXTENT_SECTORS,
        SINK_SEGMENT_BYTES,
        CAPACITY_SECTORS,
    )
    .ok()
}

/// Assemble a region field by field from the fuzzer's own bytes and finish each
/// copy with a correct CRC, so the rules behind the checksum are reachable.
///
/// Every field is either the deployment's value or the fuzzer's, chosen per
/// field: a copy in which only the segment size disagrees is what a rebound
/// extent looks like, and it is far more interesting than one in which nothing
/// matches.
fn forged_region(unstructured: &mut Unstructured<'_>) -> [u8; SUPERBLOCK_BYTES] {
    let mut region = [0u8; SUPERBLOCK_BYTES];
    let (first, second) = region.split_at_mut(SUPERBLOCK_COPY_BYTES);
    forge_copy(unstructured, first);
    forge_copy(unstructured, second);
    region
}

/// Field offsets within one copy, restated from the ABI the crate header pins
/// rather than imported: they are the on-disk layout, and a harness that took
/// them from the code under test would follow a field that moved instead of
/// noticing it had (the layout assertions fail then, and they should).
const MAGIC_AT: usize = 0;
const VERSION_AT: usize = 8;
const READER_COUNT_AT: usize = 12;
const GENERATION_AT: usize = 16;
const START_SECTOR_AT: usize = 24;
const SECTORS_AT: usize = 32;
const SEGMENT_BYTES_AT: usize = 40;
const WRITER_SEQUENCE_AT: usize = 48;
const WRITER_OFFSET_AT: usize = 56;
const READERS_AT: usize = 64;
const READER_BYTES: usize = 24;
const CRC_AT: usize = SUPERBLOCK_COPY_BYTES - 4;

fn forge_copy(unstructured: &mut Unstructured<'_>, copy: &mut [u8]) {
    // Usually the real magic and version, so the copy gets past the door;
    // occasionally the fuzzer's, so the door is exercised too.
    let magic = if any_u32(unstructured) % 8 == 0 {
        any_u64(unstructured)
    } else {
        SUPERBLOCK_MAGIC
    };
    let version = if any_u32(unstructured) % 8 == 0 {
        any_u32(unstructured)
    } else {
        SUPERBLOCK_VERSION
    };
    put_u64(copy, MAGIC_AT, magic);
    put_u32(copy, VERSION_AT, version);

    let count = any_u32(unstructured) % (MAX_READERS as u32 + 2);
    put_u32(copy, READER_COUNT_AT, count);
    put_u64(copy, GENERATION_AT, any_u64(unstructured));

    let (start, sectors, segment) = if any_u32(unstructured) % 2 == 0 {
        (SINK_START_SECTOR, SINK_EXTENT_SECTORS, SINK_SEGMENT_BYTES)
    } else {
        (
            any_u64(unstructured),
            any_u64(unstructured),
            any_u32(unstructured) as usize,
        )
    };
    put_u64(copy, START_SECTOR_AT, start);
    put_u64(copy, SECTORS_AT, sectors);
    put_u64(copy, SEGMENT_BYTES_AT, segment as u64);

    put_u64(copy, WRITER_SEQUENCE_AT, any_u64(unstructured));
    // Around the segment boundary as often as anywhere, because that is where
    // `WriterOffsetOutsideSegment` changes its mind.
    let offset = if any_u32(unstructured) % 2 == 0 {
        (segment as u64)
            .wrapping_add(any_u32(unstructured) as u64 % 4)
            .wrapping_sub(2)
    } else {
        any_u64(unstructured)
    };
    put_u64(copy, WRITER_OFFSET_AT, offset);

    for index in 0..(count as usize).min(MAX_READERS) {
        let at = READERS_AT + index * READER_BYTES;
        // Identifiers from a tiny alphabet, so `DuplicateReaderId` is reached
        // by ordinary chance rather than by a collision in a 32-bit space.
        put_u32(copy, at, any_u32(unstructured) % 3);
        // The four octets of padding behind the identifier, which this writer
        // zeroes and a decoder must refuse non-zero.
        put_u32(
            copy,
            at + 4,
            if any_u32(unstructured) % 8 == 0 {
                any_u32(unstructured)
            } else {
                0
            },
        );
        put_u64(copy, at + 8, any_u64(unstructured));
        put_u64(copy, at + 16, any_u64(unstructured));
    }

    // A byte of meaning in the reserved tail, which this writer zeroes: the
    // canonical-bytes rule the superblock header states, and one no random
    // region would ever reach with a valid checksum.
    if any_u32(unstructured) % 8 == 0 {
        let at = READERS_AT + MAX_READERS * READER_BYTES;
        let span = CRC_AT - at;
        if span > 0 {
            let where_at = at + (any_u32(unstructured) as usize) % span;
            if let Some(slot) = copy.get_mut(where_at) {
                *slot = u8::arbitrary(unstructured).unwrap_or(1);
            }
        }
    }

    // Usually the checksum the bytes deserve, so the copy is decodable at all;
    // occasionally the fuzzer's, which is a torn or rotted sector.
    let crc = if any_u32(unstructured) % 8 == 0 {
        any_u32(unstructured)
    } else {
        crc32(
            copy.get(..CRC_AT)
                .expect("a copy is longer than its checksum"),
        )
    };
    put_u32(copy, CRC_AT, crc);
}

fn put_u32(copy: &mut [u8], at: usize, value: u32) {
    if let Some(slot) = copy.get_mut(at..at + 4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

fn put_u64(copy: &mut [u8], at: usize, value: u64) {
    if let Some(slot) = copy.get_mut(at..at + 8) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// CRC-32 with the reflected IEEE polynomial — zlib's, and pcapng's.
///
/// Written out here rather than reached for in `lfw_capture_ring`, which is the
/// code under test: this is a published standard, so an independent
/// implementation of it is a second opinion rather than a copy, and the
/// agreement asserted in [`assert_crc_agrees`] is what makes a superblock this
/// harness forges one a real writer would also have produced.
fn crc32(bytes: &[u8]) -> u32 {
    let mut remainder = u32::MAX;
    for byte in bytes {
        remainder ^= u32::from(*byte);
        for _ in 0..8 {
            remainder = if remainder & 1 == 0 {
                remainder >> 1
            } else {
                (remainder >> 1) ^ 0xEDB8_8320
            };
        }
    }
    remainder ^ u32::MAX
}

/// The crate's checksum and the standard one agree.
///
/// Asserted against a copy the crate itself produced, so a polynomial or a
/// reflection changed on either side fails here rather than silently making
/// every forged region undecodable — which would have quietly emptied this
/// target of everything behind the checksum.
fn assert_crc_agrees(region: &[u8; SUPERBLOCK_BYTES], at: usize) {
    let copy = region
        .get(at..at + SUPERBLOCK_COPY_BYTES)
        .expect("a written copy lies inside the region");
    let covered = copy
        .get(..CRC_AT)
        .expect("a copy is longer than its checksum");
    let field: [u8; 4] = copy
        .get(CRC_AT..)
        .and_then(|bytes| bytes.try_into().ok())
        .expect("the checksum is the copy's last four octets");
    assert_eq!(
        u32::from_le_bytes(field),
        crc32(covered),
        "the superblock's checksum is not CRC-32 over the bytes before it"
    );
}

/// The extent one recording is given, and the device it sits on.
///
/// Deliberately small — three payload segments over the smallest segment the
/// geometry admits — so a wrap is a handful of records away rather than hours
/// of traffic, and so the reader-overrun and eviction paths are ordinary
/// outcomes of a fuzz input rather than states no run reaches.
const SINK_START_SECTOR: u64 = 8;
const SINK_SEGMENT_BYTES: usize = 4096;
const SINK_EXTENT_SECTORS: u64 = 4 * (SINK_SEGMENT_BYTES / SECTOR_SIZE) as u64;

/// Steps one sink run performs. A harness budget, not a bound on any call:
/// every operation below still carries whatever the peers chose.
const MAX_SINK_STEPS: usize = 96;

/// One recording sink over a small extent, under a byzantine tap and a caller
/// that sequences its obligations however it likes.
///
/// # The adversary and the surface
///
/// Two adversaries. The annotations and frame bytes are **a byzantine
/// neighbour PD**'s — the forwarder fills the tap slots — and the frames behind
/// them are **untrusted network traffic** one remove out. What the sink does
/// with them is arithmetic on sector numbers, so a length that steered a write
/// is a write to a sector of a block device nothing else in the system can
/// reach.
///
/// # What the adversary may express here
///
/// Every field of a [`CheckedTap`] whole, the interface identifier included.
/// That one is deliberate and is not a claim that a peer can forge it: `wire`
/// establishes `interface_id < MAX_INTERFACES` before a `CheckedTap` exists, so
/// driving the sink past that bound asks a different question — whether the
/// sink *relies* on a precondition it did not establish. It must not
/// index with the value, and this is what says so.
///
/// The **ordering** is the other half, and it is the caller's authority rather
/// than the peer's: `record`, `seal`, `close_segment` and `begin_segment` are
/// four obligations with a documented order, and every interleaving of them is
/// generated — closing a segment twice, beginning one whose predecessor's bytes
/// are still staged, sealing an empty buffer, taking a flush and never
/// acknowledging it, locating into a snapshot pinned several wraps ago. A
/// harness that only produced the documented order would leave the placement
/// arithmetic exercised on exactly the path its author already believed.
///
/// # What is asserted
///
/// * **Containment, twice over.** Guard bytes surround the staging buffer and
///   are never written; and every [`Flush`] lies inside the extent, inside the
///   one segment it is addressed against, and never in segment 0 where the
///   superblock lives. The second of those is scoped to a caller that honoured
///   `begin_segment`'s precondition — see [`assert_flush_placed`] for which
///   component enforces it and why the interleavings that break it are still
///   generated rather than filtered out.
/// * **Sector discipline.** A flush is a whole, non-zero number of sectors, and
///   never more than the staging buffer holds — what makes "no sector is
///   written twice" a property of the placement rather than of the encoder, and
///   what bounds the caller's own read out of the buffer. Unconditional.
/// * **Nothing is promised that is not durable.** `snapshot().total_len()`
///   never exceeds the bytes the device has actually been handed, so a download
///   cannot commit to a body the medium does not hold. The one assertion here
///   that is *scoped* rather than unconditional — see
///   [`assert_promises_only_durable_bytes`] for which caller contract it rests
///   on, which component enforces that contract, and why scoping it removes no
///   input.
/// * **A located span is readable.** Every [`Locate::Live`] lies inside the
///   extent and covers at least one byte, so a reader is never sent to an empty
///   or out-of-extent span.
/// * **Staging is bounded by the buffer.** What the sink says it has staged
///   never exceeds the buffer it was lent, and a placed record grows it by
///   exactly the bytes it reported.
pub fn recorder_sink(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let Ok(geometry) = Geometry::new(
        SINK_START_SECTOR,
        SINK_EXTENT_SECTORS,
        SINK_SEGMENT_BYTES,
        CAPACITY_SECTORS,
    ) else {
        return;
    };

    let interface_count = (any_u32(&mut unstructured) as usize) % (MAX_INTERFACES + 1);
    let mut interfaces = [InterfaceName::new(""); MAX_INTERFACES];
    for slot in interfaces.iter_mut().take(interface_count) {
        *slot = InterfaceName::new(&interface_name(&mut unstructured));
    }
    let config = SinkConfig {
        geometry,
        snap_len: any_u32(&mut unstructured),
        interfaces,
        interface_count,
    };
    let Ok(prologue) = prologue_len(&config) else {
        return;
    };

    // A staging buffer between "just enough for the prologue" and "a whole
    // segment and a sector over". The floor is not a filter: below it the sink
    // cannot be built at all and the run ends at once, so the band is where the
    // sink can be driven, and its lower end is exactly the cramped case where a
    // record or a pad has nowhere to go.
    let headroom = (any_u32(&mut unstructured) as usize) % (SINK_SEGMENT_BYTES + SECTOR_SIZE);
    let mut staging = Guarded::new(prologue.saturating_add(headroom));
    // A sink that exists has its prologue staged: there is no second call to
    // make, and so no interleaving in which a segment's records were composed
    // over an absent one.
    let Ok(mut sink) = Sink::new(config, staging.out()) else {
        return;
    };
    staging.assert_margins_intact("new");

    // Everything the device has been handed, which is what a snapshot may
    // promise and no more — while the caller has kept its side of the bargain.
    let mut flushed: u64 = 0;
    let mut outstanding: Option<Flush> = None;
    // `Deck`'s own two-state rule, mirrored so the harness can *observe*
    // whether the caller honoured it rather than being prevented from breaking
    // it. See `assert_promises_only_durable_bytes` on why that distinction is
    // the whole difference between scoping an invariant and deleting an input.
    let mut rolling = false;
    let mut contract_kept = true;

    for _ in 0..MAX_SINK_STEPS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        let staged_before = sink.staged();
        let label = match op % 8 {
            0 | 1 | 2 => {
                let tap = arbitrary_tap(&mut unstructured);
                let frame = arbitrary_frame(&mut unstructured);
                match sink.record(&tap, &frame, staging.out()) {
                    Recorded::Placed { bytes } => assert_eq!(
                        sink.staged(),
                        staged_before.saturating_add(bytes),
                        "a placed record of {bytes} bytes moved the staged length by something \
                         else"
                    ),
                    Recorded::SegmentFull
                    | Recorded::Oversized { .. }
                    | Recorded::StagingFull { .. }
                    | Recorded::Refused(_) => assert_eq!(
                        sink.staged(),
                        staged_before,
                        "a refused record still moved the staged length"
                    ),
                }
                "record"
            }
            3 => {
                sink.note_drops(any_u64(&mut unstructured));
                "note_drops"
            }
            4 => {
                let _ = sink.seal(staging.out());
                "seal"
            }
            5 => {
                if sink.close_segment(staging.out()).is_ok() {
                    rolling = true;
                }
                "close_segment"
            }
            6 => {
                // `Deck::advance` reopens a segment only once its predecessor
                // was closed and every byte of it acknowledged. Breaking that
                // is generated here, and recorded rather than prevented.
                if rolling && sink.staged() == 0 && outstanding.is_none() {
                    rolling = false;
                } else {
                    contract_kept = false;
                }
                let _ = sink.begin_segment(staging.out());
                "begin_segment"
            }
            _ => {
                // The device half: take a flush, or answer one already taken.
                // Both directions are the caller's to choose, and never
                // acknowledging is how a stalled device looks from here.
                if outstanding.is_some() && bool::arbitrary(&mut unstructured).unwrap_or(true) {
                    if let Some(flush) = outstanding.take() {
                        flushed = flushed.saturating_add(flush.len() as u64);
                        sink.acknowledge(flush, staging.out());
                    }
                    "acknowledge"
                } else {
                    if let Some(flush) = sink.take_flush() {
                        assert_flush_is_whole_staged_sectors(&flush, staging.capacity());
                        assert_flush_placed(&flush, &geometry, &sink, contract_kept);
                        assert!(
                            outstanding.is_none(),
                            "a second flush was handed out while one was still outstanding"
                        );
                        outstanding = Some(flush);
                    }
                    "take_flush"
                }
            }
        };
        staging.assert_margins_intact(label);

        assert!(
            sink.staged() <= staging.capacity(),
            "{label}: the sink reports {} bytes staged in a {}-byte buffer",
            sink.staged(),
            staging.capacity()
        );
        assert!(
            sink.cursor().offset <= SINK_SEGMENT_BYTES,
            "{label}: the append cursor left its segment"
        );

        let snapshot = sink.snapshot();
        assert_promises_only_durable_bytes(&snapshot, flushed, contract_kept, label);

        // A download reads the snapshot at an offset the management domain
        // chose, so the offset is taken whole rather than reduced into it.
        let offset = any_u64(&mut unstructured);
        for at in [
            offset,
            snapshot.total_len(),
            snapshot.total_len().saturating_sub(1),
        ] {
            if let Locate::Live(span) = sink.locate(&snapshot, at) {
                assert_span_inside(&span, &geometry, label);
                assert!(
                    at < snapshot.total_len(),
                    "{label}: offset {at} of a {}-byte snapshot resolved to live bytes",
                    snapshot.total_len()
                );
            }
        }
        staging.assert_margins_intact(label);
    }

    // Whatever state the run arrived at must still describe a ring the medium
    // can carry, and the counters must not have counted more than happened.
    let mut region = [0u8; SUPERBLOCK_BYTES];
    if let Ok(written) = sink.superblock(&mut region) {
        assert!(
            written.at.is_multiple_of(SUPERBLOCK_COPY_BYTES)
                && written.len.is_multiple_of(SUPERBLOCK_COPY_BYTES)
                && written.at + written.len <= SUPERBLOCK_BYTES,
            "a checkpoint named {written:?}, which is not a whole copy of the region"
        );
        let state = decode_superblock(&region).expect("what this crate wrote it reads");
        // A superblock states where the *medium* ends, never where the writer
        // has reached: the two differ by everything still in the staging
        // buffer, and a checkpoint of the append cursor would over-state the
        // recording by that much to anything holding the disk — a resuming ring
        // included.
        //
        // Scoped for the reason `assert_flush_placed` is: the staging offset
        // tracks the segment only while `begin_segment`'s precondition holds,
        // and a caller that reopened a segment with bytes still staged has
        // already put the two out of step, so the append cursor is no longer a
        // fixed distance ahead of the durable one. Every misordering is still
        // generated and still executed.
        assert!(
            !contract_kept || sink.staged() == 0 || state.writer() != sink.cursor(),
            "a checkpoint recorded the append cursor {:?} with {} bytes staged behind it",
            sink.cursor(),
            sink.staged()
        );
    }
    let counters = sink.counters();
    assert_eq!(
        counters.sectors_written.saturating_mul(SECTOR_SIZE as u64),
        flushed,
        "the sink counted a different number of sectors than were acknowledged"
    );
}

/// A download is never promised a byte the device has not been given.
///
/// # Why this one invariant is scoped, and the rest are not
///
/// [`lfw_recorder::Snapshot::total_len`] is `(durable.sequence - oldest) *
/// segment_bytes + durable.offset`, so it counts every segment before the
/// durable one as a *whole* segment of body. That is true exactly when each of
/// them was padded to its end by `close_segment` and then flushed — which is
/// the precondition `Sink::begin_segment` delegates to its caller ("call only
/// once the closed segment's bytes are on the device"), and which
/// `Deck::advance` is the component that enforces it: it reopens a segment only
/// while `rolling && in_flight.is_none() && staged() == 0`. Roll a half-written segment instead and the snapshot counts
/// the part nobody wrote, offering a download bytes the medium never received.
///
/// So the bound is asserted while the caller kept that contract, and not while
/// it did not. The distinction that matters is that this **scopes an assertion,
/// it does not filter an input**: every misordering is still generated, still
/// executed, and still held to every other invariant here — containment, sector
/// discipline, staging bounds and span validity are unconditional, because
/// none of them is contingent on the caller's ordering. A harness must never
/// narrow what the adversary may express; the ordering of a sink's own
/// obligations is not the adversary's to choose in the first place, and where
/// the harness lets it be chosen anyway, the outcome is observed rather than
/// prevented.
///
/// If this ever fires with `contract_kept`, the finding is real: a caller that
/// did everything the API asks of it was still promised bytes the device does
/// not hold.
fn assert_promises_only_durable_bytes(
    snapshot: &lfw_recorder::Snapshot,
    flushed: u64,
    contract_kept: bool,
    label: &str,
) {
    if !contract_kept {
        return;
    }
    assert!(
        snapshot.total_len() <= flushed,
        "{label}: a snapshot promises {} bytes of body where {flushed} have reached the device, \
         and every segment was closed and flushed before the next was opened",
        snapshot.total_len()
    );
}

/// A flush is whole sectors of the staging buffer — asserted whatever the
/// caller has done, because these two are what bound the caller's own read out
/// of that buffer when it hands the bytes to the device.
fn assert_flush_is_whole_staged_sectors(flush: &Flush, staging: usize) {
    assert!(!flush.is_empty(), "a flush of no bytes was handed out");
    assert!(
        flush.len().is_multiple_of(SECTOR_SIZE),
        "a flush of {} bytes is not whole sectors",
        flush.len()
    );
    assert!(
        flush.len() <= staging,
        "a flush names {} bytes from the front of a {staging}-byte staging buffer",
        flush.len()
    );
}

/// A flush lands inside the extent, inside the segment it is addressed against,
/// and never in the superblock's own segment.
///
/// # Scoped for the same reason [`assert_promises_only_durable_bytes`] is
///
/// A flush's sector is `segment_sector(staged_sequence) + staged_from /
/// SECTOR_SIZE`, and `staged_from` only tracks the segment while
/// `begin_segment`'s precondition holds. Reopen a segment with a flush still
/// outstanding and `begin_segment` resets `staged_from` to zero under it; the
/// later `acknowledge` then advances it by the outstanding flush's whole
/// length, and from that point the offset no longer describes where in the
/// segment the buffer sits. `Deck::advance` is the component that forbids it, reopening only while
/// `rolling && in_flight.is_none() && staged() == 0`.
///
/// So the placement is asserted while the caller kept that contract. The
/// interleaving that breaks it is still generated and still executed — it is
/// simply no longer held to a claim the API never made about it — and
/// everything not contingent on the caller's ordering stays unconditional:
/// the staging buffer's margins, the flush's sector discipline, the span a
/// download is pointed at, and the cursor's own bound.
///
/// If this fires with `contract_kept`, the finding is real: a caller that did
/// everything the API asks of it was handed a write outside the segment it
/// belongs to.
fn assert_flush_placed(flush: &Flush, geometry: &Geometry, sink: &Sink, contract_kept: bool) {
    if !contract_kept {
        return;
    }
    let segment = geometry.segment_sector(sink.staged_sequence());
    let segment_end = segment
        .checked_add(geometry.segment_sectors())
        .expect("a validated geometry's segment end");
    let first_payload = geometry
        .start_sector()
        .checked_add(geometry.segment_sectors())
        .expect("a validated geometry's first payload sector");
    assert!(
        flush.sector() >= first_payload,
        "a flush addresses sector {}, inside the superblock's own segment at {}",
        flush.sector(),
        geometry.superblock_sector()
    );
    assert!(
        flush.sector() >= segment,
        "a flush addresses sector {}, before the segment it belongs to at {segment}",
        flush.sector()
    );
    let sectors = (flush.len() / SECTOR_SIZE) as u64;
    assert!(
        flush
            .sector()
            .checked_add(sectors)
            .is_some_and(|end| end <= segment_end),
        "a flush of {sectors} sectors at {} runs past its segment ending at {segment_end}",
        flush.sector()
    );
    let extent_end = geometry
        .start_sector()
        .checked_add(geometry.sectors())
        .expect("a validated geometry's last sector");
    assert!(
        flush
            .sector()
            .checked_add(sectors)
            .is_some_and(|end| end <= extent_end),
        "a flush of {sectors} sectors at {} runs past the extent ending at {extent_end}",
        flush.sector()
    );
}

/// A located span lies inside the extent and covers bytes a reader can read.
fn assert_span_inside(span: &lfw_recorder::Span, geometry: &Geometry, label: &str) {
    assert!(
        !span.is_empty(),
        "{label}: a reader was pointed at a live span of no bytes"
    );
    assert!(
        span.skip() < SECTOR_SIZE,
        "{label}: a span skips {} bytes of a {SECTOR_SIZE}-byte sector",
        span.skip()
    );
    let first_payload = geometry
        .start_sector()
        .checked_add(geometry.segment_sectors())
        .expect("a validated geometry's first payload sector");
    let extent_end = geometry
        .start_sector()
        .checked_add(geometry.sectors())
        .expect("a validated geometry's last sector");
    assert!(
        span.sector() >= first_payload,
        "{label}: a span reads sector {}, inside the superblock's own segment",
        span.sector()
    );
    assert!(
        span.sector()
            .checked_add(span.sectors())
            .is_some_and(|end| end <= extent_end),
        "{label}: a span of {} sectors at {} runs past the extent ending at {extent_end}",
        span.sectors(),
        span.sector()
    );
}

/// An observation the forwarder claims to have made, every field its own.
fn arbitrary_tap(unstructured: &mut Unstructured<'_>) -> CheckedTap {
    CheckedTap {
        packet_id: any_u64(unstructured),
        timestamp: any_u64(unstructured),
        // Unreduced; see the harness header on why the bound `wire` establishes
        // is deliberately crossed here.
        interface_id: u8::arbitrary(unstructured).unwrap_or(0),
        original_len: any_u32(unstructured),
        outcome: match u8::arbitrary(unstructured).unwrap_or(0) {
            0 => TapOutcome::Forwarded,
            bits => TapOutcome::Dropped(drop_reason(bits)),
        },
        direction: if bool::arbitrary(unstructured).unwrap_or(false) {
            TapDirection::Outbound
        } else {
            TapDirection::Inbound
        },
        generation: any_u32(unstructured),
        // Unreduced, on `arbitrary_decision`'s terms: the sink must be total over
        // a decision whose parts contradict each other, not only over the ones
        // `wire`'s reader admits.
        flow: arbitrary_flow(unstructured).unwrap_or(None),
        rule: TapRule::new(usize::from(u8::arbitrary(unstructured).unwrap_or(0))),
        event: arbitrary_event(u8::arbitrary(unstructured).unwrap_or(0)),
    }
}

/// The captured bytes behind one observation.
///
/// The length reaches past `TAP_SNAP_LEN`, which is what a sink truncating to
/// its own snap length has to cope with; the content is one repeated byte
/// because the encoder copies it opaquely and what varies usefully is how much
/// of it there is.
fn arbitrary_frame(unstructured: &mut Unstructured<'_>) -> Vec<u8> {
    let len = (any_u16(unstructured) as usize) % (TAP_SNAP_LEN + SECTOR_SIZE);
    let byte = u8::arbitrary(unstructured).unwrap_or(0);
    vec![byte; len]
}

/// An interface name, whose bytes reach the prologue an operator's reader
/// renders and whose length crosses `MAX_INTERFACE_NAME` in both directions.
fn interface_name(unstructured: &mut Unstructured<'_>) -> String {
    let len = (any_u32(unstructured) as usize) % (lfw_recorder::MAX_INTERFACE_NAME * 2 + 1);
    let byte = u8::arbitrary(unstructured).unwrap_or(b'a');
    let letter = char::from(0x20 + (byte % 0x5F));
    core::iter::repeat_n(letter, len).collect()
}
