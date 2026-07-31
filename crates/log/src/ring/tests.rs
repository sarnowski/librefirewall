use super::*;

use proptest::prelude::*;
use std::{boxed::Box, vec::Vec};
use wire::{LogConsume, LogRecords};

use crate::detail::{Cause, DomainDetail, Refusal, RefusalDetail};
use crate::event::{Domain, DomainState, GenerationOutcome};
use crate::record::DecodeError;
use crate::stamp::{
    Stamp,
    testing::{FixedClock, utc},
};

/// The two regions one ring is, on the heap: `LogRecords` is larger than a
/// comfortable stack frame in a test binary. Held together here because a test
/// drives both ends; on a node they are two grants to two domains.
struct Ring {
    records: Box<LogRecords>,
    consume: Box<LogConsume>,
}

fn ring() -> Ring {
    Ring {
        records: Box::new(LogRecords::zero()),
        consume: Box::new(LogConsume::zero()),
    }
}

impl Ring {
    fn writer(&self) -> wire::LogWriter<'_> {
        self.records.writer(&self.consume)
    }

    fn reader(&self) -> wire::LogReader<'_> {
        self.consume.reader(&self.records)
    }
}

fn generation(n: u32) -> Event {
    Event::ConfigGeneration {
        generation: n,
        outcome: GenerationOutcome::Applied,
        changes: 0,
    }
}

/// Every event the reader could pull, decoded — the console domain's whole side
/// of the region.
fn drain(ring: &Ring) -> Vec<Result<Event<Cause>, DecodeError>> {
    stamped_drain(ring)
        .into_iter()
        .map(|decoded| decoded.map(|(_, event)| event))
        .collect()
}

/// As [`drain`], keeping each record's instant, for the tests that are about it.
fn stamped_drain(ring: &Ring) -> Vec<Result<(Stamp, Event<Cause>), DecodeError>> {
    let mut reader = ring.reader();
    let capacity = reader.capacity();
    reader
        .drain(capacity)
        .map(|record| {
            let record = record.expect("every record here was written by the encoder");
            Event::decode(&record)
        })
        .collect()
}

#[test]
fn a_fresh_sink_has_refused_nothing() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    assert_eq!(sink.dropped(), 0);
    assert_eq!(sink.refused(), 0);
    assert!(drain(&ring).is_empty());
}

#[test]
fn records_that_fit_are_readable_in_the_order_they_were_emitted() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    for n in 0..8 {
        sink.emit(&generation(n));
    }
    assert_eq!(sink.dropped(), 0);
    assert_eq!(sink.refused(), 0);
    let drained = drain(&ring);
    assert_eq!(drained.len(), 8);
    for (n, decoded) in drained.into_iter().enumerate() {
        let n = u32::try_from(n).expect("eight fits");
        assert_eq!(
            decoded,
            Ok(Event::<Cause>::try_from(generation(n)).expect("no cause to bound"))
        );
    }
}

/// The whole point of the ring: a domain enqueues during its own `init` and the
/// console domain drains whenever it comes up, so a writer that fills the ring
/// before anything reads must not block and must not fault.
#[test]
fn a_full_ring_refuses_and_counts_rather_than_blocking() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    let capacity = ring.reader().capacity();
    let overrun = 5u32;
    let offered = u32::try_from(capacity).expect("the capacity fits") + overrun;
    for n in 0..offered {
        sink.emit(&generation(n));
    }
    assert_eq!(
        sink.dropped(),
        overrun,
        "the ring should have refused exactly what did not fit"
    );
    assert_eq!(sink.refused(), 0, "nothing here was unencodable");

    // What did fit is the *oldest*, which is the bias the ring is built for:
    // the records that explain a failed bring-up are the first ones.
    let drained = drain(&ring);
    assert_eq!(drained.len(), capacity);
    assert_eq!(
        drained.first(),
        Some(&Ok(
            Event::<Cause>::try_from(generation(0)).expect("no cause to bound")
        ))
    );
}

/// Draining frees slots, so a sink that hit a full ring keeps working rather
/// than latching refused.
#[test]
fn a_drained_ring_takes_records_again() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    let capacity = u32::try_from(ring.reader().capacity()).expect("the capacity fits");
    for n in 0..capacity + 1 {
        sink.emit(&generation(n));
    }
    assert_eq!(sink.dropped(), 1);

    let mut reader = ring.reader();
    let read = reader.drain(4).count();
    assert_eq!(read, 4);

    sink.emit(&generation(1000));
    assert_eq!(sink.dropped(), 1, "a freed slot is not another drop");
}

/// An event this build cannot encode is the domain's own defect, so it is
/// counted apart from a flood — and it does not disturb the records around it.
#[test]
fn an_unencodable_event_is_refused_without_touching_the_ring() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    let unencodable = Event::Domain {
        domain: Domain::NicDriver,
        state: DomainState::Refused,
        detail: DomainDetail::Refusal(Refusal {
            cause: "a cause token with spaces in it",
            detail: RefusalDetail::None,
            signalled: false,
        }),
    };
    sink.emit(&generation(1));
    sink.emit(&unencodable);
    sink.emit(&generation(2));

    assert_eq!(sink.refused(), 1);
    assert_eq!(sink.dropped(), 0);
    let drained = drain(&ring);
    assert_eq!(drained.len(), 2, "the refused event took no slot");
    assert_eq!(
        drained,
        [
            Ok(Event::<Cause>::try_from(generation(1)).expect("no cause")),
            Ok(Event::<Cause>::try_from(generation(2)).expect("no cause")),
        ]
    );
}

/// A sink already in use further up the same stack refuses rather than
/// panicking: a protection domain has no unwinder, so a `borrow_mut` that could
/// fault would trade a log line for the domain (ENG-5).
#[test]
fn a_sink_already_in_use_refuses_rather_than_faulting() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    {
        let _held = sink.writer.borrow_mut();
        sink.emit(&generation(1));
    }
    assert_eq!(sink.refused(), 1);
    assert_eq!(sink.dropped(), 0);
    assert!(drain(&ring).is_empty());

    sink.emit(&generation(2));
    assert_eq!(drain(&ring).len(), 1, "the sink works again once released");
}

/// Both counters saturate rather than wrapping, so a sustained flood cannot
/// read back as a small number.
#[test]
fn the_counters_saturate_rather_than_wrapping() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    sink.refused.set(u32::MAX);
    sink.refuse();
    assert_eq!(sink.refused(), u32::MAX);
}

/// The refusal a domain reports is the one the region carries, so the number an
/// operator reads and the number the console domain reads are the same number.
#[test]
fn the_drop_count_a_domain_reports_is_the_one_the_region_carries() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    let capacity = u32::try_from(ring.reader().capacity()).expect("the capacity fits");
    for n in 0..capacity + 3 {
        sink.emit(&generation(n));
    }
    assert_eq!(sink.dropped(), 3);
    assert_eq!(ring.reader().dropped_by_writer(), sink.dropped());
}

/// A sink taken by reference is what a subsystem that only logs sees, so a
/// domain hands out `&dyn Sink` and nothing downstream knows about a ring.
#[test]
fn a_ring_sink_is_usable_through_the_trait_alone() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    fn announce(sink: &dyn Sink) {
        sink.emit(&Event::Domain {
            domain: Domain::Console,
            state: DomainState::Ready,
            detail: DomainDetail::None,
        });
    }
    announce(&sink);
    assert_eq!(drain(&ring).len(), 1);
}

/// The instant is the sink's, taken at the moment of the call: a call site
/// emits an event and never an event and a time, so a record cannot be stamped
/// with one the emitting domain did not hold.
#[test]
fn a_record_carries_the_instant_the_sinks_clock_gave_it() {
    let ring = ring();
    let at = utc(1_785_443_220_123_456_789);
    let sink = RingSink::new(ring.writer(), FixedClock(at));
    sink.emit(&generation(1));
    let [Ok((stamped, _))] = stamped_drain(&ring)[..] else {
        panic!("one record was emitted");
    };
    assert_eq!(stamped, at);
}

/// A domain emitting before this node has established a time produces the
/// absence rather than the epoch, which is most of a boot transcript (ENG-12).
#[test]
fn a_domain_with_no_clock_yet_emits_the_absence_and_not_nineteen_seventy() {
    let ring = ring();
    let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
    sink.emit(&generation(1));
    let [Ok((stamped, _))] = stamped_drain(&ring)[..] else {
        panic!("one record was emitted");
    };
    assert_eq!(stamped, Stamp::Unsynchronized);
    assert_ne!(stamped, utc(0));
}

proptest! {
    /// However many records a domain offers, the sink accounts for every one of
    /// them: what the reader sees plus what was counted is what was emitted.
    /// Bounded work and no loss that is not counted (ENG-4, ENG-12).
    #[test]
    fn every_emitted_record_is_either_readable_or_counted(count in 0usize..200) {
        let ring = ring();
        let sink = RingSink::new(ring.writer(), FixedClock(Stamp::Unsynchronized));
        for n in 0..count {
            sink.emit(&generation(u32::try_from(n).expect("the bound fits")));
        }
        let readable = drain(&ring).len();
        let accounted = readable
            + usize::try_from(sink.dropped()).expect("a count fits")
            + usize::try_from(sink.refused()).expect("a count fits");
        prop_assert_eq!(accounted, count);
        prop_assert!(readable <= ring.reader().capacity());
    }
}
