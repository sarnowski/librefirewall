use super::*;

use proptest::prelude::*;
use std::{boxed::Box, string::String, vec, vec::Vec};
use wire::{CheckedDetail, LogConsume, LogRecord, LogRecords, LogWriter};

use crate::Sink;
use crate::detail::{DomainDetail, Refusal, RefusalDetail};
use crate::event::{Domain, DomainState, GenerationOutcome};
use crate::ring::RingSink;

/// A writer that keeps every byte, and that can be told to start refusing.
///
/// The refusal is a *count* rather than a flag because the interesting case is
/// a device that takes a prefix of a burst and then wedges — which is what the
/// UART's `write_bytes` does on a controller that stops asserting THRE.
struct FakeSink {
    written: Vec<u8>,
    /// Calls this writer accepts before every later one is refused.
    accepts: Option<usize>,
    calls: usize,
}

impl FakeSink {
    fn new() -> Self {
        Self {
            written: Vec::new(),
            accepts: None,
            calls: 0,
        }
    }

    fn wedging_after(calls: usize) -> Self {
        Self {
            written: Vec::new(),
            accepts: Some(calls),
            calls: 0,
        }
    }

    /// What reached the device, as the lines an operator would read.
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.written.clone())
            .expect("every rendered line is UTF-8")
            .split("\r\n")
            .filter(|line| !line.is_empty())
            .map(String::from)
            .collect()
    }
}

/// The refusal is a unit: this crate never inspects it, which is the whole
/// point of the associated type.
#[derive(Debug, PartialEq, Eq)]
struct Wedged;

impl ByteSink for FakeSink {
    type Error = Wedged;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.calls += 1;
        if self.accepts.is_some_and(|accepts| self.calls > accepts) {
            return Err(Wedged);
        }
        self.written.extend_from_slice(bytes);
        Ok(())
    }
}

/// The two regions one ring is, on the heap: `LogRecords` is larger than a
/// comfortable stack frame. Held together here because a test drives both ends;
/// on a node they are two grants to two domains, each writable in one.
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
    fn writer(&self) -> LogWriter<'_> {
        self.records.writer(&self.consume)
    }

    fn reader(&self) -> LogReader<'_> {
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

fn domain_event(domain: Domain, state: DomainState) -> Event {
    Event::Domain {
        domain,
        state,
        detail: DomainDetail::None,
    }
}

/// Publish `events` through one writing half, which is what
/// [`LogRecords::writer`] says to take once and keep. Taking a second per call
/// would restart at slot zero and overwrite what the first published, so every
/// test here threads one writer per ring.
fn put(writer: &mut LogWriter<'_>, events: &[Event]) {
    for event in events {
        let bounded = Event::<Cause>::try_from(*event).expect("no cause to bound");
        writer.write(&bounded.encode()).expect("the ring has room");
    }
}

/// Publish records a peer built by hand. `LogRecord` is a public POD, so this
/// is exactly the authority a byzantine writer has over its own slots.
fn put_raw(writer: &mut LogWriter<'_>, records: &[LogRecord]) {
    for record in records {
        writer.write(record).expect("the ring has room");
    }
}

/// A record whose `kind` names no variant `wire` has, which is the crudest
/// thing a peer can leave in a slot.
fn unreadable() -> LogRecord {
    LogRecord {
        kind: 0xFFFF_FFFF,
        ..LogRecord::ZERO
    }
}

/// The line the renderer produces for `event`, so an expectation is the
/// renderer's own output rather than a string restated here — which would
/// agree with itself whichever of the two was wrong.
fn rendered(event: &Event) -> String {
    let mut line = [0u8; MAX_LINE_LEN];
    let written = render(event, &mut line).expect("MAX_LINE_LEN holds every line");
    String::from_utf8(line[..written].to_vec()).expect("a rendered line is UTF-8")
}

#[test]
fn a_fresh_printer_has_printed_nothing_and_starts_at_the_first_ring() {
    let printer = ConsolePrinter::new(FakeSink::new());
    assert_eq!(printer.counters(), ConsoleCounters::default());
    assert_eq!(printer.next_ring(), 0);
}

#[test]
fn an_event_the_domain_mints_itself_reaches_the_device_as_its_console_line() {
    // The console's own lifecycle record, through the same call a peer's
    // decoded record takes (ENG-7).
    let mut printer = ConsolePrinter::new(FakeSink::new());
    let event = domain_event(Domain::Console, DomainState::Ready);
    assert!(printer.print(&event));
    assert_eq!(printer.counters().printed, 1);
    assert_eq!(
        printer.writer.lines(),
        vec![String::from("LFW-PD domain=console state=ready")]
    );
}

#[test]
fn every_line_is_terminated_so_a_transcript_is_lines_and_not_one_run_on_string() {
    let mut printer = ConsolePrinter::new(FakeSink::new());
    printer.print(&generation(1));
    printer.print(&generation(2));
    let written = printer.writer.written;
    assert!(written.ends_with(LINE_END));
    assert_eq!(
        written
            .windows(LINE_END.len())
            .filter(|window| *window == LINE_END)
            .count(),
        2,
        "one terminator per line, and no line left unterminated"
    );
}

#[test]
fn a_records_journey_is_the_writing_domains_sink_to_the_console_line() {
    // The whole path in one test, through the sink a domain actually holds:
    // a domain emits, the region carries it, and the console renders exactly
    // what the domain said.
    let ring = ring();
    let event = domain_event(Domain::Forwarder, DomainState::Starting);
    let sink = RingSink::new(ring.writer());
    sink.emit(&event);
    sink.emit(&generation(7));

    let mut printer = ConsolePrinter::new(FakeSink::new());
    let mut readers = [ring.reader()];
    assert_eq!(printer.drain(&mut readers), 2);
    assert_eq!(
        printer.writer.lines(),
        vec![rendered(&event), rendered(&generation(7))]
    );
}

#[test]
fn a_pass_takes_no_more_than_the_burst_from_one_ring() {
    let ring = ring();
    let events: Vec<Event> = (0..BURST_PER_RING as u32 * 3).map(generation).collect();
    let mut writer = ring.writer();
    put(&mut writer, &events);

    let mut printer = ConsolePrinter::new(FakeSink::new());
    let mut readers = [ring.reader()];
    assert_eq!(printer.drain(&mut readers), BURST_PER_RING);
    assert_eq!(printer.writer.lines().len(), BURST_PER_RING);
    // And the rest is still queued, in order: a bounded pass loses nothing.
    assert_eq!(printer.drain(&mut readers), BURST_PER_RING);
    assert_eq!(
        printer.writer.lines(),
        events[..BURST_PER_RING * 2]
            .iter()
            .map(rendered)
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_ring_that_floods_does_not_starve_another_domains_records() {
    // The fairness property, and the reason the burst exists at all. One
    // domain fills its ring; another has a single record to say. That record
    // must appear in the very first pass.
    let flooding = ring();
    let quiet = ring();
    let flood: Vec<Event> = (0..40u32).map(generation).collect();
    put(&mut flooding.writer(), &flood);
    let only = domain_event(Domain::Config, DomainState::Refused);
    put(&mut quiet.writer(), &[only]);

    let mut printer = ConsolePrinter::new(FakeSink::new());
    let mut readers = [flooding.reader(), quiet.reader()];
    printer.drain(&mut readers);
    assert!(
        printer.writer.lines().contains(&rendered(&only)),
        "the quiet domain's one record must not queue behind a flood"
    );
}

#[test]
fn each_pass_starts_one_ring_further_along() {
    // A burst limit alone still serves ring 0 first on every pass, so a
    // flooding ring 0 would keep a later ring permanently behind it. The
    // rotation is what closes that, and this is the assertion that it happens.
    let regions = [ring(), ring(), ring()];
    for (index, region) in regions.iter().enumerate() {
        put(&mut region.writer(), &[generation(index as u32)]);
    }

    let mut printer = ConsolePrinter::new(FakeSink::new());
    let mut readers: Vec<LogReader<'_>> = regions.iter().map(|r| r.reader()).collect();
    assert_eq!(printer.next_ring(), 0);
    printer.drain(&mut readers);
    assert_eq!(printer.next_ring() % readers.len(), 1);
    printer.drain(&mut readers);
    assert_eq!(printer.next_ring() % readers.len(), 2);
    printer.drain(&mut readers);
    assert_eq!(printer.next_ring() % readers.len(), 0, "and it wraps");
    // Every record was printed exactly once across the three passes.
    assert_eq!(printer.counters().printed, 3);
}

#[test]
fn the_rotation_serves_the_later_ring_first_when_its_turn_comes() {
    // Not merely that the cursor moves: that the *output order* follows it.
    let first = ring();
    let second = ring();
    let a = domain_event(Domain::NicDriver, DomainState::Starting);
    let b = domain_event(Domain::Forwarder, DomainState::Starting);
    let mut first_writer = first.writer();
    let mut second_writer = second.writer();

    let mut printer = ConsolePrinter::new(FakeSink::new());
    let mut readers = [first.reader(), second.reader()];
    // Pass one starts at ring 0.
    put(&mut first_writer, &[a]);
    put(&mut second_writer, &[b]);
    printer.drain(&mut readers);
    assert_eq!(printer.writer.lines(), vec![rendered(&a), rendered(&b)]);
    // Pass two starts at ring 1, so the second domain's record leads.
    put(&mut first_writer, &[a]);
    put(&mut second_writer, &[b]);
    printer.drain(&mut readers);
    assert_eq!(
        printer.writer.lines(),
        vec![rendered(&a), rendered(&b), rendered(&b), rendered(&a)]
    );
}

#[test]
fn a_console_granted_no_rings_at_all_does_nothing_rather_than_faulting() {
    // A system description defect, but not one this function may fault over:
    // the domain would take the whole console down for a grant it cannot fix.
    let mut printer = ConsolePrinter::new(FakeSink::new());
    assert_eq!(printer.drain(&mut []), 0);
    assert_eq!(printer.counters(), ConsoleCounters::default());
}

#[test]
fn a_record_that_is_no_record_is_counted_and_skipped() {
    // The byzantine writer: a slot holding bytes `wire` refuses outright. It
    // must cost one counter and nothing else — the records around it still get
    // out.
    let ring = ring();
    let good = generation(1);
    let mut writer = ring.writer();
    put(&mut writer, &[good]);
    put_raw(&mut writer, &[unreadable()]);
    put(&mut writer, &[generation(2)]);

    let mut printer = ConsolePrinter::new(FakeSink::new());
    let mut readers = [ring.reader()];
    assert_eq!(printer.drain(&mut readers), 2);
    assert_eq!(printer.counters().malformed, 1);
    assert_eq!(printer.counters().unknown, 0);
    assert_eq!(
        printer.writer.lines(),
        vec![rendered(&good), rendered(&generation(2))],
        "a refused record must not disturb the ones around it"
    );
}

#[test]
fn a_record_naming_a_variant_this_build_does_not_have_is_counted_apart() {
    // `wire` bounds a token against its own `LOG_*_COUNT`, and `record.rs`
    // holds that count equal to this crate's variant list, so the two agree by
    // build assertion and no ring can carry this. What can is a peer built
    // from a *different* build of the ABI, which is what a hand-made
    // `CheckedBody` stands in for — the shape `wire` would hand over if its
    // vocabulary were the wider one. It must accuse the vocabulary rather than
    // the bytes, because the operator's action differs: one is a rebuild, the
    // other is a misbehaving domain.
    let mut printer = ConsolePrinter::new(FakeSink::new());
    let body = CheckedBody::Domain {
        domain: u8::MAX,
        state: 0,
        detail: CheckedDetail::None,
    };
    assert!(!printer.print_record(Ok(body)));
    assert_eq!(printer.counters().unknown, 1);
    assert_eq!(printer.counters().malformed, 0);
    assert_eq!(printer.counters().printed, 0);
    assert!(printer.writer.written.is_empty());
}

#[test]
fn a_device_that_wedges_costs_the_lines_and_not_the_pass() {
    // The console's own failure mode: the controller stops taking bytes. Every
    // later line is counted lost, the drain still returns, and the records are
    // consumed rather than left to fill the ring for a device that is gone.
    let ring = ring();
    put(
        &mut ring.writer(),
        &[generation(1), generation(2), generation(3)],
    );

    // Two calls per line — the text and the terminator — so one accepted call
    // wedges partway through the first line.
    let mut printer = ConsolePrinter::new(FakeSink::wedging_after(1));
    let mut readers = [ring.reader()];
    assert_eq!(printer.drain(&mut readers), 0);
    assert_eq!(printer.counters().printed, 0);
    assert_eq!(printer.counters().write_failed, 3);
    assert!(
        readers[0].is_empty(),
        "the records were consumed, not requeued"
    );
}

#[test]
fn a_line_refused_halfway_is_counted_once_and_not_twice() {
    let mut printer = ConsolePrinter::new(FakeSink::wedging_after(1));
    assert!(!printer.print(&generation(1)));
    assert_eq!(printer.counters().write_failed, 1);
    assert_eq!(printer.counters().printed, 0);
}

#[test]
fn the_counters_saturate_rather_than_wrapping_at_the_top() {
    // A wrap would turn a sustained fault back into a small number exactly
    // when the number matters, so the top is a fixed point.
    let mut printer = ConsolePrinter::new(FakeSink::wedging_after(0));
    printer.counters.write_failed = u64::MAX;
    assert!(!printer.print(&generation(1)));
    assert_eq!(printer.counters().write_failed, u64::MAX);

    let mut good = ConsolePrinter::new(FakeSink::new());
    good.counters.printed = u64::MAX;
    assert!(good.print(&generation(1)));
    assert_eq!(good.counters().printed, u64::MAX);

    let ring = ring();
    put_raw(&mut ring.writer(), &[unreadable()]);
    let mut malformed = ConsolePrinter::new(FakeSink::new());
    malformed.counters.malformed = u64::MAX;
    malformed.drain(&mut [ring.reader()]);
    assert_eq!(malformed.counters().malformed, u64::MAX);

    let mut unknown = ConsolePrinter::new(FakeSink::new());
    unknown.counters.unknown = u64::MAX;
    assert!(!unknown.print_record(Ok(CheckedBody::Domain {
        domain: u8::MAX,
        state: 0,
        detail: CheckedDetail::None,
    })));
    assert_eq!(unknown.counters().unknown, u64::MAX);
}

#[test]
fn a_refusal_cause_survives_the_crossing_into_the_line_it_is_read_as() {
    // The one event whose text a peer chooses. It crosses as bounded bytes and
    // must reach the console as the same token, since a bring-up failure's
    // cause is the whole of what an operator gets (CONCEPT §11).
    let ring = ring();
    let refusal = Event::Domain {
        domain: Domain::NicDriver,
        state: DomainState::Refused,
        detail: DomainDetail::Refusal(Refusal {
            cause: "receive-pool-dma-base",
            detail: RefusalDetail::One(0),
            signalled: false,
        }),
    };
    put(&mut ring.writer(), &[refusal]);

    let mut printer = ConsolePrinter::new(FakeSink::new());
    printer.drain(&mut [ring.reader()]);
    let lines = printer.writer.lines();
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("receive-pool-dma-base"),
        "the cause token must reach the line: {}",
        lines[0]
    );
}

/// Every domain's whole vocabulary of lifecycle records, so the console is
/// exercised over what the system actually emits rather than one variant.
#[test]
fn every_domain_and_state_a_build_can_emit_reaches_the_device() {
    let ring = ring();
    let mut events = Vec::new();
    for domain in Domain::ALL {
        for state in DomainState::ALL {
            events.push(domain_event(domain, state));
        }
    }
    assert!(
        events.len() <= ring.reader().capacity(),
        "they fit in one ring"
    );
    put(&mut ring.writer(), &events);

    let mut printer = ConsolePrinter::new(FakeSink::new());
    let mut readers = [ring.reader()];
    while printer.drain(&mut readers) > 0 {}
    assert_eq!(
        printer.writer.lines(),
        events.iter().map(rendered).collect::<Vec<_>>()
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The termination property. Whatever a peer has put in its rings — any
    /// bytes at all, in any slot — a pass returns, and it consumes at most
    /// `rings * BURST_PER_RING` records. A peer that could make it spin would
    /// hang this test rather than fail it, which is the failure mode being
    /// excluded (ENG-4).
    #[test]
    fn a_pass_is_bounded_by_this_domains_own_constants_whatever_a_peer_wrote(
        words in prop::collection::vec(any::<u64>(), 1..64),
        rings in 1usize..4,
    ) {
        let regions: Vec<Ring> = (0..rings).map(|_| ring()).collect();
        for region in &regions {
            let mut writer = region.writer();
            for word in &words {
                // Every field a `check` looks at, driven from arbitrary bytes:
                // the kind, the vocabularies, the detail discriminant and the
                // operand count are what decide whether a record is refused.
                let bytes = word.to_le_bytes();
                let record = LogRecord {
                    kind: u32::from(bytes[0]),
                    domain: bytes[1],
                    state: bytes[2],
                    detail: bytes[3],
                    operand_count: bytes[4],
                    change: bytes[5],
                    object: bytes[6],
                    field: bytes[7],
                    ..LogRecord::ZERO
                };
                if writer.write(&record).is_err() {
                    break;
                }
            }
        }
        let mut readers: Vec<LogReader<'_>> = regions.iter().map(|r| r.reader()).collect();
        let mut printer = ConsolePrinter::new(FakeSink::new());
        let printed = printer.drain(&mut readers);
        prop_assert!(printed <= rings * BURST_PER_RING);
        let counters = printer.counters();
        let accounted = counters.printed
            + counters.malformed
            + counters.unknown
            + counters.unrenderable
            + counters.write_failed;
        prop_assert!(accounted <= (rings * BURST_PER_RING) as u64);
    }

    /// Nothing a peer writes goes unaccounted: every record a pass consumed is
    /// in exactly one counter. A record that vanished without a number behind
    /// it is the silent loss ENG-12 forbids.
    #[test]
    fn every_record_a_pass_consumes_lands_in_exactly_one_counter(
        kinds in prop::collection::vec(any::<u8>(), 0..BURST_PER_RING),
    ) {
        let ring = ring();
        let mut writer = ring.writer();
        for kind in &kinds {
            let record = LogRecord { kind: u32::from(*kind), ..LogRecord::ZERO };
            writer.write(&record).expect("fewer than one ring's worth");
        }
        let mut printer = ConsolePrinter::new(FakeSink::new());
        let mut reader = ring.reader();
        let queued = reader.len();
        printer.drain(core::slice::from_mut(&mut reader));
        let counters = printer.counters();
        let accounted = counters.printed
            + counters.malformed
            + counters.unknown
            + counters.unrenderable
            + counters.write_failed;
        prop_assert_eq!(accounted, queued.min(BURST_PER_RING) as u64);
    }

    /// A pass over any number of rings visits every one of them, so no ring is
    /// reachable only from a particular starting position.
    #[test]
    fn every_ring_is_visited_in_every_pass(rings in 1usize..6, start in 0usize..12) {
        let regions: Vec<Ring> = (0..rings).map(|_| ring()).collect();
        for (index, region) in regions.iter().enumerate() {
            put(&mut region.writer(), &[generation(index as u32)]);
        }
        let mut printer = ConsolePrinter::new(FakeSink::new());
        printer.next = start;
        let mut readers: Vec<LogReader<'_>> = regions.iter().map(|r| r.reader()).collect();
        prop_assert_eq!(printer.drain(&mut readers), rings);
        let lines = printer.writer.lines();
        for index in 0..rings {
            prop_assert!(lines.contains(&rendered(&generation(index as u32))));
        }
    }
}
