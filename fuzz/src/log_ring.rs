//! `wire`'s log ring under a byzantine neighbour PD on both sides at once.
//!
//! # The adversary and the surface
//!
//! The ring is laid across two regions with opposite permissions (CONCEPT
//! §7.1): a writing domain maps the records region read-write and the consume
//! region read-only, and the console domain maps them the other way round. So
//! there are two adversaries here, not one, and the code under test is *both*
//! halves — `LogWriter`, which a writing domain drives against a console that
//! may forge the consume cursor, and `LogReader`, which the console drives
//! against a writing domain that may put anything in any slot and forge the
//! records cursor and the drop count.
//!
//! [`crate::log_ring_abi::LogRingPeer`] is one view over both regions for
//! exactly that reason: each is independently hostile, and the inputs worth
//! finding are the ones where a forged consume cursor and a rewritten slot
//! arrive in the same run.
//!
//! # What each adversary may express here
//!
//! Both published cursors and the drop count take a full, unreduced `u32` —
//! rewound, advanced past the ring, `u32::MAX`, anything. Any slot may be
//! overwritten whole with 192 unreduced bytes, **or one atomic at a time**,
//! which is the peer's real granularity and the only way a torn record is
//! expressible (see [`crate::log_ring_abi`]). The record a writing domain
//! publishes through `LogWriter::write` is equally unreduced — the whole
//! region image, laid out by [`crate::log_record::read_record`]. All of it
//! interleaves freely with this side's writes and reads, including a cursor
//! forged *between two steps of one drain*, which is the case a whole-drain
//! prediction could not reach.
//!
//! # What is asserted
//!
//! * **Each side reads and writes its own private position.** Before each read
//!   the harness loads, through the peer's own view of the shared image, the
//!   slot at the reader's shadow position — tracked from this side's history
//!   alone — and what `read` hands back must be exactly `check` of those bytes.
//!   The writer's slot is asserted the same way after each accepted write.
//! * **Exact flow control, against an independent model.** Both published
//!   cursors and the published drop count are predicted from this harness's own
//!   history — this side's publishes and the peer's forges — never read back
//!   out of a region, and the prediction is compared with the image after every
//!   operation. Whether a write is refused and whether a read yields is then
//!   decided from that model rather than from the very word the peer forged.
//! * **Nothing is invented.** An untorn slot reads back *exactly* the record
//!   the write that stamped it put there, byte for byte; an untouched slot
//!   reads back the zeroed record, which is what lets a console meet a slot
//!   before anything has been published.
//! * **A record is whole or absent, unless the peer tore it.** Every delivery
//!   whose locations did not all come from one write is counted, and the count
//!   is asserted to have a **cause**: a peer store of a single atomic. With a
//!   peer that stores only whole records, no record is ever assembled from two
//!   writes.
//! * **Delivery multiplicity, bounded rather than predicted.** Every record
//!   this side writes is tracked by provenance, so a record handed out twice is
//!   counted rather than inferred. Redelivery has a cause too — a forged
//!   records cursor — and under a peer that forges none, no record is ever
//!   delivered twice however it forges the consume cursor or rewrites slots.
//! * **Bounded by the capacity const, never by a published cursor.** A drain
//!   never yields more than its `limit`, never more than `capacity()`, and
//!   never more than [`LOG_RING_SLOTS`] — asserted after the peer has set the
//!   records cursor to an arbitrary value, and with `usize::MAX` as the limit,
//!   which is the case where the only thing left standing between the console
//!   and a non-terminating drain is the crate's own clamp (ENG-4).
//! * **The two estimates never contradict.** `len()` never exceeds
//!   `capacity()` and `is_empty()` agrees with it, on both handles after every
//!   operation — the property a caller sizing a batch from a peer-influenced
//!   number would rest on, which is why the crate tells it not to.
//!
//! # The limit that is not a capability filter
//!
//! The drain limit is folded into `0..=2 * LOG_RING_SLOTS + 1`, with `u32::MAX`
//! kept as a sentinel for `usize::MAX`. The limit is the **caller's** budget
//! per scheduling round — this domain's own number, never the peer's — so
//! choosing it from a small band is not a restriction on any adversary, and the
//! one value that matters for the clamp is preserved exactly.

use std::vec::Vec;

use arbitrary::{Arbitrary as _, Unstructured};
use wire::{LOG_RING_SLOTS, LogConsume, LogRecord, LogRecords};

use crate::log_record::read_record;
use crate::log_ring_abi::{LOCATION_COUNT, Location, LogRingPeer};
use crate::{MAX_OPERATIONS, any_u32, next_op};

/// The mask both sides reduce a cursor by; one below [`LOG_RING_SLOTS`] because
/// one slot is always left unused to tell a full ring from an empty one.
///
/// Restated from the ABI contract rather than read out of `wire`, which is the
/// code under test.
const MASK: u32 = (LOG_RING_SLOTS - 1) as u32;

/// Records the ring holds at once — the capacity `LogWriter` and `LogReader`
/// both report, restated on [`MASK`]'s terms.
const CAPACITY: usize = MASK as usize;

/// Which write put a given atomic into a given slot.
///
/// Identity by *provenance* rather than by value, because the peer may store
/// any bytes it likes into any slot — including bytes this side also wrote. A
/// value-matching ledger would then have to guess, and would guess in whichever
/// direction hid a redelivery; provenance cannot collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wrote {
    /// The zero of a location no one has written since the region was zeroed.
    Zeroed,
    /// This side's `n`-th accepted write, which stamped every location at once.
    Writer(u64),
    /// The peer's `n`-th store, whether of one location or of a whole record.
    Peer(u64),
}

/// What one run of the harness observed.
///
/// Returned so the tests below can *demonstrate* that a shape is generable — a
/// claim that an adversary capability is reachable is worth nothing without an
/// input that reaches it (TEST-8). Every invariant resting on these counters is
/// asserted inside [`observe`] as it runs, not here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Observed {
    /// Records handed to the console by `read` or `drain`.
    pub(crate) deliveries: u64,
    /// Deliveries whose locations did not all come from one write.
    pub(crate) torn: u64,
    /// Deliveries of a record this side had already been handed once.
    pub(crate) redeliveries: u64,
    /// Deliveries the record check refused.
    pub(crate) undecodable: u64,
    /// Records the writer refused for want of a slot.
    pub(crate) refused_writes: u64,
    /// Records the writer accepted.
    pub(crate) accepted_writes: u64,
    /// Peer writes to each shared word.
    pub(crate) tail_forges: u64,
    pub(crate) head_forges: u64,
    pub(crate) dropped_forges: u64,
    /// Peer stores of a whole record into a slot of its choosing.
    pub(crate) record_stores: u64,
    /// Peer stores of a single atomic, leaving the other 146 alone.
    pub(crate) location_stores: u64,
}

/// The harness's independent model of both shared images: what wrote each
/// atomic of each slot, where each side's private position stands, and what
/// each published word holds.
struct Model {
    /// Provenance of every location of every slot.
    wrote: Vec<[Wrote; LOCATION_COUNT]>,
    /// The three published words as this harness's own history says they are —
    /// never read back out of a region, which is what makes comparing them with
    /// the image a claim rather than a tautology.
    published_tail: u32,
    published_head: u32,
    published_dropped: u32,
    /// The writer's private position and its own drop count.
    writer_tail: u32,
    writer_dropped: u32,
    /// The reader's private position and its own tally of refused records.
    reader_head: u32,
    reader_undecodable: u32,
}

impl Model {
    /// The model of two freshly zeroed regions.
    fn zeroed() -> Self {
        Self {
            wrote: vec![[Wrote::Zeroed; LOCATION_COUNT]; LOG_RING_SLOTS],
            published_tail: 0,
            published_head: 0,
            published_dropped: 0,
            writer_tail: 0,
            writer_dropped: 0,
            reader_head: 0,
            reader_undecodable: 0,
        }
    }

    /// Stamp every location of one slot with one write.
    fn stamp_slot(&mut self, slot: usize, wrote: Wrote) {
        self.wrote[slot % LOG_RING_SLOTS] = [wrote; LOCATION_COUNT];
    }
}

/// Drive both halves of a log ring against a peer that owns the cursors, the
/// drop count and every atomic of every slot.
pub fn log_ring_harness(data: &[u8]) {
    let _ = observe(data);
}

/// The harness body, returning what it saw so a test can prove a shape
/// reachable.
#[expect(
    clippy::too_many_lines,
    reason = "the operation table is one match over one shared model; splitting an arm out would \
              hand it the model, the peer, the handles and the ledger as arguments and make the \
              order the assertions run in harder to read than it is inline"
)]
pub(crate) fn observe(data: &[u8]) -> Observed {
    let mut unstructured = Unstructured::new(data);
    // Heap rather than stack: a records region is over 12 KiB, and a libFuzzer
    // worker's stack under AddressSanitizer is not the place for it.
    let records_region = Box::new(LogRecords::zero());
    let consume_region = Box::new(LogConsume::zero());
    let records: &LogRecords = &records_region;
    let consume: &LogConsume = &consume_region;

    let peer = LogRingPeer::new(records, consume);
    let mut writer = records.writer(consume);
    let mut reader = consume.reader(records);

    assert_eq!(writer.capacity(), CAPACITY, "the writer's capacity moved");
    assert_eq!(reader.capacity(), CAPACITY, "the reader's capacity moved");

    let mut model = Model::zeroed();
    let mut observed = Observed::default();
    // Every record this side wrote, indexed by the ordinal `Wrote::Writer`
    // carries, so an untorn delivery can be compared with the write that
    // stamped it rather than merely counted.
    let mut written: Vec<LogRecord> = Vec::new();
    // How many times each of this side's writes has been handed out.
    let mut handed_out: Vec<u64> = Vec::new();
    // Every peer store, `None` for a single-location one which is no whole
    // record. Its own ordinal sequence, so two locations of one slot compare
    // equal exactly when the same peer store wrote both.
    let mut peer_stores: Vec<Option<LogRecord>> = Vec::new();

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 9 {
            0 => {
                // A writing domain publishes. The record is the whole region
                // image unreduced: the writing side is an adversary too, and
                // the console is what has to survive whatever it publishes.
                let record = read_record(&mut unstructured);
                let ordinal = written.len() as u64;
                let slot = model.writer_tail as usize;
                // Fullness is judged against the modelled consume cursor, not
                // against one read back out of the region the peer owns.
                let refused =
                    (model.writer_tail.wrapping_add(1) & MASK) == (model.published_head & MASK);
                let outcome = writer.write(&record);
                if refused {
                    model.writer_dropped = model.writer_dropped.saturating_add(1);
                    model.published_dropped = model.writer_dropped;
                    assert_eq!(
                        outcome.err().map(|full| full.dropped),
                        Some(model.writer_dropped),
                        "a refused write did not report the drop count the writer holds"
                    );
                    observed.refused_writes += 1;
                } else {
                    assert_eq!(outcome, Ok(()), "the ring had room but refused the write");
                    assert_eq!(
                        peer.load_record(slot),
                        record,
                        "the writer wrote somewhere other than its own private position"
                    );
                    model.stamp_slot(slot, Wrote::Writer(ordinal));
                    written.push(record);
                    handed_out.push(0);
                    model.writer_tail = model.writer_tail.wrapping_add(1) & MASK;
                    model.published_tail = model.writer_tail;
                    observed.accepted_writes += 1;
                }
            }
            1 => {
                let empty = model.reader_head == (model.published_tail & MASK);
                let slot = model.reader_head as usize;
                let held = peer.load_record(slot);
                let outcome = reader.read();
                if empty {
                    assert_eq!(outcome, None, "the ring appeared empty but yielded anyway");
                } else {
                    assert_eq!(
                        outcome,
                        Some(held.check()),
                        "the reader read somewhere other than its own private position, or \
                         decoded the slot differently from the check applied to the same bytes"
                    );
                    model.reader_head = model.reader_head.wrapping_add(1) & MASK;
                    model.published_head = model.reader_head;
                    account(
                        slot,
                        &held,
                        &model,
                        &written,
                        &peer_stores,
                        &mut handed_out,
                        &mut observed,
                    );
                    if held.check().is_err() {
                        model.reader_undecodable = model.reader_undecodable.saturating_add(1);
                    }
                }
            }
            2 => {
                // Predict the whole drain before running it: nothing in the
                // iterator changes a slot or either published cursor, so the
                // sequence the private position must produce is fully
                // determined here, from the model rather than from the image.
                let limit = drain_limit(&mut unstructured);
                let clamped = limit.min(CAPACITY);
                let modelled_tail = model.published_tail & MASK;
                let mut predicted = Vec::new();
                let mut position = model.reader_head;
                for _ in 0..clamped {
                    if position == modelled_tail {
                        break;
                    }
                    predicted.push((position as usize, peer.load_record(position as usize)));
                    position = position.wrapping_add(1) & MASK;
                }
                let taken: Vec<_> = reader.drain(limit).collect();
                assert!(
                    taken.len() <= clamped,
                    "drain yielded {} records for a limit of {limit} against a capacity of \
                     {CAPACITY}",
                    taken.len()
                );
                assert!(
                    taken.len() <= LOG_RING_SLOTS,
                    "one drain yielded more records than the ring has slots"
                );
                assert_eq!(
                    taken,
                    predicted
                        .iter()
                        .map(|(_, record)| record.check())
                        .collect::<Vec<_>>(),
                    "drain diverged from the private position"
                );
                model.reader_head = position;
                if !predicted.is_empty() {
                    model.published_head = position;
                }
                for (slot, record) in predicted {
                    account(
                        slot,
                        &record,
                        &model,
                        &written,
                        &peer_stores,
                        &mut handed_out,
                        &mut observed,
                    );
                    if record.check().is_err() {
                        model.reader_undecodable = model.reader_undecodable.saturating_add(1);
                    }
                }
            }
            3 => {
                let forged = any_u32(&mut unstructured);
                peer.set_tail(forged);
                model.published_tail = forged;
                observed.tail_forges += 1;
            }
            4 => {
                let forged = any_u32(&mut unstructured);
                peer.set_head(forged);
                model.published_head = forged;
                observed.head_forges += 1;
            }
            5 => {
                let forged = any_u32(&mut unstructured);
                peer.set_dropped(forged);
                model.published_dropped = forged;
                observed.dropped_forges += 1;
            }
            6 => {
                // A whole record into any slot the peer likes, which is not
                // the slot its own cursor names — a conforming writer publishes
                // where its cursor points and only a byzantine one does not.
                let slot = any_u32(&mut unstructured) as usize;
                let record = read_record(&mut unstructured);
                peer.store_record(slot, &record);
                let ordinal = peer_stores.len() as u64;
                peer_stores.push(Some(record));
                model.stamp_slot(slot, Wrote::Peer(ordinal));
                observed.record_stores += 1;
            }
            7 => {
                // One atomic, leaving the other 146 as they were: the torn
                // record, which a whole-record store cannot express.
                let slot = any_u32(&mut unstructured) as usize;
                let location = Location::from_selector(any_u32(&mut unstructured));
                let value = u64::arbitrary(&mut unstructured).unwrap_or(0);
                peer.store_location(slot, location, value);
                let ordinal = peer_stores.len() as u64;
                peer_stores.push(None);
                model.wrote[slot % LOG_RING_SLOTS][location.index()] = Wrote::Peer(ordinal);
                observed.location_stores += 1;
            }
            _ => {
                drain_while_the_cursor_moves(
                    &mut unstructured,
                    &peer,
                    &mut reader,
                    &mut model,
                    &written,
                    &peer_stores,
                    &mut handed_out,
                    &mut observed,
                );
            }
        }

        // The publication claim: each side writes its own private position into
        // the region it owns, the writer publishes its own drop count, and
        // nothing else writes any of the three. The model was built from this
        // side's history and the peer's forges alone, so agreeing with the
        // image is a statement about the code.
        assert_eq!(
            peer.tail(),
            model.published_tail,
            "the records cursor holds a value nothing in this run published"
        );
        assert_eq!(
            peer.head(),
            model.published_head,
            "the consume cursor holds a value nothing in this run published"
        );
        assert_eq!(
            peer.dropped(),
            model.published_dropped,
            "the drop count holds a value nothing in this run published"
        );
        assert_eq!(
            writer.dropped(),
            model.writer_dropped,
            "the writer's own drop count diverged from its refusals"
        );
        assert_eq!(
            reader.undecodable(),
            model.reader_undecodable,
            "the reader's own tally diverged from the records the check refused"
        );
        assert_eq!(
            reader.dropped_by_writer(),
            model.published_dropped,
            "the reader reported a drop count other than the one in the region"
        );

        // The two estimates are snapshots of a peer-influenced quantity, so
        // nothing is claimed about their *value* — only that they stay inside
        // the ring and cannot contradict each other, which is what a consumer
        // sizing a batch from them would rely on and what the crate tells it
        // not to do.
        let writer_len = writer.len();
        assert!(
            writer_len <= CAPACITY,
            "the writer's estimate left the ring"
        );
        assert_eq!(writer.is_empty(), writer_len == 0);
        let reader_len = reader.len();
        assert!(
            reader_len <= CAPACITY,
            "the reader's estimate left the ring"
        );
        assert_eq!(reader.is_empty(), reader_len == 0);
        assert!(model.writer_tail < LOG_RING_SLOTS as u32);
        assert!(model.reader_head < LOG_RING_SLOTS as u32);
    }

    // A peer that keeps advancing the records cursor keeps the ring looking
    // non-empty forever; `drain` is the bounded form that must stop anyway.
    // Assert the bound holds rather than assuming it: an unbounded
    // `while let Some(..)` here would hang instead of failing, which is the
    // shape of harness that proves nothing.
    //
    // `usize::MAX` is the case that matters: at that limit the caller's own
    // budget has stopped bounding anything and the crate's clamp against
    // `capacity()` is the only thing left.
    //
    // Neither this forge nor what the four drains yield is accounted: the claim
    // under test here is the bound on the iterator and nothing else, `account`
    // is deliberately not reached again, and leaving `tail_forges` alone keeps
    // "this run forged no records cursor" a statement a demonstration can make.
    peer.set_tail(any_u32(&mut unstructured));
    for limit in [0usize, 1, LOG_RING_SLOTS, usize::MAX] {
        let count = reader.drain(limit).count();
        assert!(count <= limit, "drain exceeded its limit");
        assert!(
            count <= CAPACITY,
            "drain yielded {count} records past the {CAPACITY} the ring holds"
        );
        assert!(
            count <= LOG_RING_SLOTS,
            "drain yielded more records than the ring has slots"
        );
    }

    observed
}

/// Drain with the records cursor forged between every two steps.
///
/// A whole-drain prediction cannot reach this: it computes the sequence once,
/// from a cursor that then stands still. Here the peer moves the cursor while
/// the iterator is live — which is exactly what a writing domain publishing
/// into the ring does — so each step is predicted on its own, and the bound the
/// iterator promises is asserted at every one of them.
#[expect(
    clippy::too_many_arguments,
    reason = "the model, the ledger and the observation counters are one state the caller owns; \
              bundling them into a struct here would only move the same eight bindings behind a \
              name that adds nothing"
)]
fn drain_while_the_cursor_moves(
    unstructured: &mut Unstructured<'_>,
    peer: &LogRingPeer<'_>,
    reader: &mut wire::LogReader<'_>,
    model: &mut Model,
    written: &[LogRecord],
    peer_stores: &[Option<LogRecord>],
    handed_out: &mut [u64],
    observed: &mut Observed,
) {
    let limit = drain_limit(unstructured);
    let clamped = limit.min(CAPACITY);
    let mut taken: Vec<(usize, LogRecord)> = Vec::new();
    {
        let mut drain = reader.drain(limit);
        loop {
            assert_eq!(
                drain.size_hint(),
                (0, Some(clamped - taken.len())),
                "the drain's own upper bound stopped agreeing with what it has yielded"
            );
            let forged = any_u32(unstructured);
            peer.set_tail(forged);
            model.published_tail = forged;
            observed.tail_forges += 1;

            let position = model.reader_head;
            let empty = position == (model.published_tail & MASK);
            let held = peer.load_record(position as usize);
            match drain.next() {
                None => {
                    assert!(
                        empty || taken.len() == clamped,
                        "the drain stopped with {} of {clamped} taken while the ring was not \
                         observed empty",
                        taken.len()
                    );
                    break;
                }
                Some(item) => {
                    assert!(!empty, "the drain yielded from a ring it observed empty");
                    assert_eq!(
                        item,
                        held.check(),
                        "a mid-drain read came from somewhere other than the private position"
                    );
                    model.reader_head = position.wrapping_add(1) & MASK;
                    model.published_head = model.reader_head;
                    if held.check().is_err() {
                        model.reader_undecodable = model.reader_undecodable.saturating_add(1);
                    }
                    taken.push((position as usize, held));
                }
            }
            assert!(
                taken.len() <= clamped,
                "a drain whose cursor kept moving yielded {} records for a limit of {limit}",
                taken.len()
            );
        }
    }
    for (slot, record) in taken {
        account(
            slot,
            &record,
            model,
            written,
            peer_stores,
            handed_out,
            observed,
        );
    }
}

/// The caller's own per-round budget, folded into a band that reaches both
/// sides of the capacity clamp, with `u32::MAX` kept as the sentinel for
/// `usize::MAX`.
///
/// Not a capability filter: the limit is this domain's number and never the
/// peer's, and the one value the clamp is *for* is preserved exactly.
fn drain_limit(unstructured: &mut Unstructured<'_>) -> usize {
    let raw = any_u32(unstructured);
    if raw == u32::MAX {
        usize::MAX
    } else {
        raw as usize % (2 * LOG_RING_SLOTS + 2)
    }
}

/// Account for one record handed to the console, and assert what the ring
/// promises about where it came from and how often that may happen.
///
/// Split out only because a read, a drain and a moving-cursor drain must
/// account identically; the assertions stay with the accounting so the three
/// cannot drift.
fn account(
    slot: usize,
    record: &LogRecord,
    model: &Model,
    written: &[LogRecord],
    peer_stores: &[Option<LogRecord>],
    handed_out: &mut [u64],
    observed: &mut Observed,
) {
    observed.deliveries += 1;
    if record.check().is_err() {
        observed.undecodable += 1;
    }

    let wrote = &model.wrote[slot % LOG_RING_SLOTS];
    let first = wrote[0];
    if wrote.iter().any(|stamp| *stamp != first) {
        // A record assembled from more than one write — exactly what a peer
        // store landing between two of `LogSlot::load`'s relaxed loads
        // produces. Well-formed, in bounds, and untrusted, which is all the
        // crate claims for it: `LogRecord::check` is what stands between it and
        // a rendered line. It is not one of this side's records any more, so it
        // is deliberately outside the multiplicity ledger below.
        observed.torn += 1;
        assert!(
            observed.location_stores > 0,
            "a record was assembled from two different writes with no single-atomic peer store \
             in this run — a whole-record store cannot tear a slot, so the slot image was \
             mixed by something else"
        );
        return;
    }

    match first {
        Wrote::Zeroed => assert_eq!(
            *record,
            LogRecord::ZERO,
            "a slot nothing ever wrote read back as something other than the zeroed record"
        ),
        Wrote::Peer(ordinal) => {
            if let Some(stored) = peer_stores[ordinal as usize] {
                assert_eq!(
                    *record, stored,
                    "a slot the peer wrote whole read back as a different record"
                );
            }
        }
        Wrote::Writer(ordinal) => {
            assert_eq!(
                *record, written[ordinal as usize],
                "an untorn slot read back a record other than the one the write that stamped it \
                 put there"
            );
            let count = &mut handed_out[ordinal as usize];
            *count += 1;
            if *count > 1 {
                observed.redeliveries += 1;
                // The claim the split of the ring into two regions rests on,
                // stated as a bound rather than predicted away: the reader's
                // position is private, so the only lever that can walk it back
                // over a record it already took is the records cursor — the one
                // word the *writing* domain owns. Forging the consume cursor
                // buys the peer nothing here, and neither does rewriting a slot.
                assert!(
                    observed.tail_forges > 0,
                    "write {ordinal} was delivered {} times with no forged records cursor — the \
                     reader's private position failed to prevent redelivery",
                    *count
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_record::region_from_record;
    use std::fs;
    use std::path::PathBuf;

    /// Build one harness input, so a demonstration reads as the operation
    /// stream it drives rather than as a hex blob.
    #[derive(Default)]
    struct Input(Vec<u8>);

    impl Input {
        /// Select the operation `op % 9` runs.
        fn op(mut self, op: u8) -> Self {
            self.0.push(op);
            self
        }

        /// Append one `any_u32` argument, little-endian, as `arbitrary` reads it.
        fn arg(mut self, value: u32) -> Self {
            self.0.extend_from_slice(&value.to_le_bytes());
            self
        }

        /// Append one `u64` argument.
        fn quad(mut self, value: u64) -> Self {
            self.0.extend_from_slice(&value.to_le_bytes());
            self
        }

        /// Append one whole region image, as `read_record` reads it.
        fn record(mut self, record: &LogRecord) -> Self {
            self.0.extend_from_slice(&region_from_record(record));
            self
        }

        fn write(self, record: &LogRecord) -> Self {
            self.op(0).record(record)
        }

        fn read(self) -> Self {
            self.op(1)
        }

        fn drain(self, limit: u32) -> Self {
            self.op(2).arg(limit)
        }

        fn forge_tail(self, value: u32) -> Self {
            self.op(3).arg(value)
        }

        fn forge_head(self, value: u32) -> Self {
            self.op(4).arg(value)
        }

        fn forge_dropped(self, value: u32) -> Self {
            self.op(5).arg(value)
        }

        fn store_record(self, slot: u32, record: &LogRecord) -> Self {
            self.op(6).arg(slot).record(record)
        }

        fn store_location(self, slot: u32, selector: u32, value: u64) -> Self {
            self.op(7).arg(slot).arg(selector).quad(value)
        }

        /// Drain with the records cursor forged to `forges` in turn between
        /// steps.
        fn drain_while_moving(self, limit: u32, forges: &[u32]) -> Self {
            let mut input = self.op(8).arg(limit);
            for &forge in forges {
                input = input.arg(forge);
            }
            input
        }

        fn bytes(self) -> Vec<u8> {
            self.0
        }
    }

    /// The committed seed of that name, so a demonstration and the corpus entry
    /// that preserves it cannot drift apart.
    fn seed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join("log_ring")
            .join(name);
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// A well-formed record carrying `generation`, so a delivery is traceable
    /// to the write that produced it.
    fn stamped(generation: u32) -> LogRecord {
        LogRecord {
            kind: 2,
            generation,
            changes: generation,
            ..LogRecord::ZERO
        }
    }

    /// An untouched ring yields nothing, however it is asked.
    fn empty_ring() -> Vec<u8> {
        Input::default()
            .read()
            .drain(0)
            .drain(1)
            .drain(u32::MAX)
            .read()
            .bytes()
    }

    /// The ring filled to capacity refuses the newest record and counts it.
    ///
    /// Reached by forging the consume cursor rather than by writing 63 records:
    /// the fullness rule is `next == head`, and the head is the console's word,
    /// so a forged one is the shortest input that stands on the boundary.
    fn full_ring_refuses_the_newest() -> Vec<u8> {
        let mut input = Input::default().forge_head(5);
        for generation in 0..4 {
            input = input.write(&stamped(generation));
        }
        // Tail now stands at 4, so the next write's `next` is 5 — the forged
        // head — and the ring is full.
        input.write(&stamped(4)).write(&stamped(5)).bytes()
    }

    /// Cursors past the end of the ring wrap into it rather than leaving it,
    /// and a drain over the whole wrapped range is still bounded by capacity.
    fn wrapped_cursors() -> Vec<u8> {
        Input::default()
            .forge_tail(u32::MAX)
            .drain(u32::MAX)
            .forge_head(u32::MAX)
            .forge_tail(u32::MAX - 1)
            .drain(u32::MAX)
            .bytes()
    }

    /// A forged records cursor walks the reader back over records it has
    /// already taken: the redelivery the two-region split bounds rather than
    /// prevents, and the one shape that reaches `account`'s multiplicity claim.
    fn forged_cursors_redeliver() -> Vec<u8> {
        let mut input = Input::default();
        for generation in 0..7 {
            input = input.write(&stamped(generation));
        }
        for _ in 0..7 {
            input = input.read();
        }
        // Head and tail both stand at 7. Rewinding the records cursor to 4
        // makes every slot from 7 round to 3 look published again, so a single
        // unbounded drain walks the reader the long way round the ring and back
        // over the four records it has already taken. One drain rather than a
        // run of reads because the ring is 64 slots wide: the lap is 61 steps,
        // and the redelivery only appears on the last four of them.
        input.forge_tail(4).drain(u32::MAX).bytes()
    }

    /// A peer store of one atomic after a whole-record write: the console is
    /// handed a record assembled from two different writes, which is what a
    /// store landing between two of `LogSlot::load`'s relaxed loads produces
    /// and what a whole-record-only peer could not express.
    fn torn_record_from_two_writes() -> Vec<u8> {
        Input::default()
            .write(&stamped(9))
            // Location 5 is `kind`, the word that decides what every other
            // field of the record means.
            .store_location(0, 5, u64::from(u32::MAX))
            .read()
            .bytes()
    }

    /// Both regions set to every byte the peer can set: every slot rewritten,
    /// both cursors and the drop count at `u32::MAX`.
    fn every_byte_set_region_pair() -> Vec<u8> {
        let all_set = LogRecord {
            features: u64::MAX,
            operands: [u64::MAX; 2],
            kind: u32::MAX,
            generation: u32::MAX,
            sequence: u32::MAX,
            changes: u32::MAX,
            reject_offset: u32::MAX,
            receive_posted: u32::MAX,
            domain: u8::MAX,
            state: u8::MAX,
            detail: u8::MAX,
            operand_count: u8::MAX,
            signalled: u8::MAX,
            change: u8::MAX,
            object: u8::MAX,
            field: u8::MAX,
            outcome: u8::MAX,
            reason: u8::MAX,
            _pad: [u8::MAX; 6],
            cause: wire::CauseImage {
                bytes: [u8::MAX; wire::LOG_CAUSE_BYTES],
                len: u8::MAX,
                _pad: [u8::MAX; 3],
            },
            key: wire::IdentifierImage {
                bytes: [u8::MAX; wire::LOG_IDENTIFIER_BYTES],
                len: u8::MAX,
                _pad: [u8::MAX; 3],
            },
            from: all_set_value(),
            to: all_set_value(),
            tsc_hz: u64::MAX,
            unix_nanos: u64::MAX,
        };
        // Every slot, not a sample of them: the seed stands for a region pair
        // in which the peer has set every byte it can reach, and a drain that
        // met a zeroed slot part-way through would be exercising a different
        // input from the one this is committed as.
        let mut input = Input::default();
        for slot in 0..LOG_RING_SLOTS as u32 {
            input = input.store_record(slot, &all_set);
        }
        input
            .forge_tail(u32::MAX)
            .forge_head(u32::MAX)
            .forge_dropped(u32::MAX)
            .drain(u32::MAX)
            .bytes()
    }

    /// A value slot with every byte set; see [`every_byte_set_region_pair`].
    fn all_set_value() -> wire::ValueImage {
        wire::ValueImage {
            number: u32::MAX,
            kind: u8::MAX,
            octets: [u8::MAX; 6],
            _pad: u8::MAX,
            id: wire::IdentifierImage {
                bytes: [u8::MAX; wire::LOG_IDENTIFIER_BYTES],
                len: u8::MAX,
                _pad: [u8::MAX; 3],
            },
        }
    }

    /// The records cursor advancing while a drain is live: the case a
    /// whole-drain prediction cannot reach, and the one where the crate's clamp
    /// against `capacity()` is the only thing that ends the iteration.
    fn cursor_advances_mid_drain() -> Vec<u8> {
        let mut input = Input::default();
        for generation in 0..8 {
            input = input.write(&stamped(generation));
        }
        // A cursor that keeps moving ahead of the reader at every step: without
        // the clamp this drain would never end.
        let forges: Vec<u32> = (1..=70u32).collect();
        input
            .drain_while_moving(u32::MAX, &forges)
            .drain_while_moving(3, &forges)
            .bytes()
    }

    /// Every committed seed, as the operation stream it stands for.
    fn demonstrations() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty_ring", empty_ring()),
            (
                "full_ring_refuses_the_newest",
                full_ring_refuses_the_newest(),
            ),
            ("wrapped_cursors", wrapped_cursors()),
            ("forged_cursors_redeliver", forged_cursors_redeliver()),
            ("torn_record_from_two_writes", torn_record_from_two_writes()),
            ("every_byte_set_region_pair", every_byte_set_region_pair()),
            ("cursor_advances_mid_drain", cursor_advances_mid_drain()),
        ]
    }

    /// Each demonstration is committed as the seed of the same name, byte for
    /// byte, so a cold fuzz run starts from the shapes above and an edit that
    /// changed the operation encoding could not leave the corpus silently
    /// meaning something else.
    #[test]
    fn every_demonstration_is_the_committed_seed_of_its_name() {
        for (name, built) in demonstrations() {
            assert!(!built.is_empty(), "seed {name} is empty");
            assert_eq!(
                seed(name),
                built,
                "seed {name} is not the input it stands for"
            );
        }
    }

    #[test]
    fn an_untouched_ring_yields_nothing() {
        let observed = observe(&empty_ring());
        assert_eq!(observed.deliveries, 0);
        assert_eq!(observed.accepted_writes, 0);
    }

    #[test]
    fn a_full_ring_refuses_the_newest_record_and_counts_it() {
        let observed = observe(&full_ring_refuses_the_newest());
        assert_eq!(observed.accepted_writes, 4, "{observed:?}");
        assert_eq!(observed.refused_writes, 2, "{observed:?}");
    }

    #[test]
    fn a_forged_records_cursor_walks_the_reader_back_over_what_it_took() {
        let observed = observe(&forged_cursors_redeliver());
        assert!(
            observed.redeliveries > 0,
            "the rewound cursor delivered nothing twice: {observed:?}"
        );
        assert_eq!(observed.tail_forges, 1);
        assert_eq!(observed.location_stores, 0);
        assert_eq!(observed.torn, 0);
    }

    /// The other half of the multiplicity claim: with no forged records cursor,
    /// an arbitrary stream of consume-cursor forges and whole-record peer
    /// stores delivers nothing twice. `account`'s assertion would fire if it
    /// did; this states the same thing as a positive result so the bound is not
    /// merely vacuously satisfied.
    #[test]
    fn without_a_forged_records_cursor_nothing_is_delivered_twice() {
        let mut input = Input::default();
        for generation in 0..7 {
            input = input.write(&stamped(generation));
        }
        for round in 0..7u32 {
            input = input.forge_head(round.wrapping_mul(0x9E37_79B9));
            input = input.read();
        }
        let observed = observe(&input.bytes());
        assert_eq!(observed.redeliveries, 0);
        assert!(
            observed.head_forges > 0 && observed.deliveries > 0,
            "{observed:?}"
        );
    }

    #[test]
    fn a_single_atomic_peer_store_tears_a_delivered_record() {
        let observed = observe(&torn_record_from_two_writes());
        assert_eq!(observed.location_stores, 1);
        assert_eq!(
            observed.torn, 1,
            "the single-atomic store did not tear a delivery: {observed:?}"
        );
    }

    /// Every byte of both regions set: the console is handed records, every one
    /// of them is refused by the check, and the drain is still bounded.
    #[test]
    fn a_region_pair_of_every_byte_set_yields_only_refusals() {
        let observed = observe(&every_byte_set_region_pair());
        assert!(observed.deliveries > 0, "{observed:?}");
        assert_eq!(
            observed.undecodable, observed.deliveries,
            "a record of every byte set decoded to something: {observed:?}"
        );
        assert!(observed.deliveries <= CAPACITY as u64);
    }

    /// A cursor the peer keeps advancing does not extend a drain: the clamp is
    /// the crate's own capacity and never the published cursor (ENG-4).
    #[test]
    fn a_cursor_that_keeps_moving_does_not_extend_a_drain() {
        let observed = observe(&cursor_advances_mid_drain());
        assert!(observed.tail_forges > 0, "{observed:?}");
        assert!(observed.deliveries > 0, "{observed:?}");
        // Two drains, each bounded by capacity and the second by its own
        // smaller limit; the assertions inside `observe` are what enforce it.
        assert!(observed.deliveries <= CAPACITY as u64 + 3, "{observed:?}");
    }

    /// The wrapped-cursor seed reaches the capacity bound from the other side:
    /// a cursor at `u32::MAX` names a slot inside the ring, and the drain over
    /// it yields the whole capacity and not one record more.
    #[test]
    fn a_cursor_past_the_end_of_the_ring_wraps_into_it() {
        let observed = observe(&wrapped_cursors());
        assert!(observed.deliveries > 0, "{observed:?}");
        assert!(
            observed.deliveries <= 2 * CAPACITY as u64,
            "two drains yielded more than two ring-fulls: {observed:?}"
        );
    }
}
