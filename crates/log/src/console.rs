//! Turning the records several domains published into the bytes one serial
//! line carries: the whole of what the console domain decides, in the crate
//! that already owns [`Event`] and [`render`].
//!
//! # Adversary
//!
//! The byzantine peer protection domain (CONCEPT §7.1). Every record here came
//! out of a region a writing domain owns and the console maps read-only, so its
//! bytes, its vocabulary tokens and the cursor that published it were all
//! chosen by that domain and none of them can be corrected here. A console that
//! could be stopped by one of them would be a console that goes quiet exactly
//! when a domain misbehaves, which is the one moment it is read.
//!
//! # Why this is not in `pds/console`
//!
//! Drain order, how much of one ring a pass may take, what becomes of a record
//! that decodes to nothing, and which counter accuses whom are decisions, and a
//! decision inside a protection domain is reachable by no host test (LAY-2).
//! What is left for the domain is mapping the regions, claiming the port and
//! calling [`ConsolePrinter::drain`] in a loop.
//!
//! # Why the writer is a trait rather than the UART
//!
//! [`ByteSink`] keeps `crates/log` free of `uart-16550`, which is the ENG-11
//! boundary seen from the other side: this crate would otherwise depend on the
//! one crate in the workspace that executes `in`/`out`, and a host test of the
//! fairness rule below would be a test that cannot link. It is also what lets
//! every property here be asserted against a writer that fails on demand.
//!
//! # One printing mechanism, not two
//!
//! [`ConsolePrinter::print`] is generic over the cause type, so a record
//! decoded out of a peer's ring and the console domain's own lifecycle event
//! reach the device through the same call (ENG-7). There is deliberately no
//! second path for "the console's own output".
//!
//! # Why this is not a [`Sink`](crate::Sink)
//!
//! [`Sink::emit`](crate::Sink::emit) takes `&self`, because a sink is shared by
//! every subsystem of a domain that has anything to say. Writing a byte needs
//! the device exclusively, and wrapping it in a `RefCell` to satisfy a trait
//! nothing here calls through would buy a fallible borrow and no caller.

use core::fmt;

use lfw_metrics::{ConsoleSample, UartSample};

use wire::{CheckedRecord, LogReader, LogRecordError};

use crate::detail::Cause;
use crate::event::Event;
use crate::render::{MAX_LINE_LEN, render};
use crate::stamp::Stamp;

/// Records one pass may take from a single ring before it moves to the next.
///
/// The fairness bound, and it is a constant of this crate rather than anything
/// read out of a region (ENG-4): a domain that fills its ring faster than the
/// line drains must cost the other domains a delay and never their records.
/// Sized at half the transmit FIFO so a full burst is bytes the controller
/// takes without the caller waiting on it — the FIFO is 16 bytes and a rendered
/// line is longer than one, so the ratio is a bias and not an arithmetic claim.
pub const BURST_PER_RING: usize = 8;

/// What ends a console line.
///
/// CR and LF rather than LF alone: this is a raw 16550 with no line discipline
/// in front of it, so nothing else will supply the carriage return, and a
/// terminal that does not get one prints the transcript as a staircase.
const LINE_END: &[u8] = b"\r\n";

/// Somewhere to put the bytes of a rendered line.
///
/// `uart_16550::Transmitter::write_bytes` is the implementation that ships;
/// the associated error keeps *why* a write failed the writer's own vocabulary,
/// which is what lets this crate count a refusal without naming a device.
pub trait ByteSink {
    type Error;

    /// Hand every byte over in order. A refusal need not say how much of the
    /// slice preceded it: a partial line is already lost either way, and the
    /// caller's response is the same.
    ///
    /// # Errors
    /// Whatever the writer's own refusal is.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// What the console can say about itself, in the shape the metrics endpoint
/// (CONCEPT §11) scrapes.
///
/// Four failure counters rather than one, because they accuse four different
/// parties and an operator's next action differs for each: the peer's bytes,
/// the peer's vocabulary, this build's own renderer, and the device. Every
/// field is monotonic for the domain's life and saturates at [`u64::MAX`]; a
/// scrape differences successive samples, so a reset would forge a negative
/// rate and a wrap would turn a sustained fault back into a small number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConsoleCounters {
    /// Lines rendered and handed to the writer in full.
    pub printed: u64,
    /// Records whose bytes are no record at all — `wire` refused the shape.
    /// Non-zero accuses the writing domain of publishing something the ABI
    /// cannot carry, or of writing a slot it had not been given.
    pub malformed: u64,
    /// Records `wire` accepted whose vocabulary token names no variant this
    /// build has. Non-zero accuses the writing domain of being a different
    /// build from this one — the two halves of the ABI having parted.
    pub unknown: u64,
    /// Events that decoded and would not fit [`MAX_LINE_LEN`]. Non-zero is this
    /// build's own defect: the renderer and the buffer disagree, and no peer
    /// can cause it (`render`'s own `every_event_fits_the_advertised_maximum`).
    pub unrenderable: u64,
    /// Lines the writer would not take. Non-zero means console output has been
    /// lost, and it is the one counter with nowhere to be reported *to* — the
    /// console is the reporting mechanism.
    pub write_failed: u64,
}

impl ConsoleCounters {
    /// This path in the shape `lfw_metrics` publishes, slot for slot, with the
    /// device's own three beside it.
    ///
    /// The conversion is here because this is where both halves are visible:
    /// `lfw_metrics` carries plain data and depends on neither this crate nor
    /// `uart_16550`, and the console protection domain holds one of each. The
    /// order below is the metric catalogue's, held to it by the test at the end
    /// of this module.
    #[must_use]
    pub const fn to_sample(&self, uart: UartSample) -> ConsoleSample {
        ConsoleSample {
            records: [
                self.printed,
                self.malformed,
                self.unknown,
                self.unrenderable,
                self.write_failed,
            ],
            uart_bytes_written: uart.bytes_written,
            uart_transmitter_timeouts: uart.thre_timeouts,
            uart_init_failures: uart.init_failures,
        }
    }
}

/// Saturating rather than wrapping, on [`ConsoleCounters`]'s terms.
fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The console's renderer and its position in the round-robin over the rings.
///
/// It owns the writer outright. The device has exactly one owner in this system
/// — that is the whole reason the console is a domain — and a borrowed writer
/// would make a second printer expressible in a type (DOC-9).
pub struct ConsolePrinter<W> {
    writer: W,
    /// Which ring the next pass starts at. Rotating the *start* rather than
    /// draining one ring to empty is what makes the bound above fair: a burst
    /// limit alone still serves ring 0 first every time, and a flooding ring 0
    /// would then keep a later ring's records permanently behind it.
    next: usize,
    counters: ConsoleCounters,
}

impl<W: ByteSink> ConsolePrinter<W> {
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            next: 0,
            // Field by field rather than `Default::default()`, which is not a
            // `const` trait: a printer that could not be built in a `const`
            // would have to be built inside `init`, where the very first record
            // is the one this domain most wants out.
            counters: ConsoleCounters {
                printed: 0,
                malformed: 0,
                unknown: 0,
                unrenderable: 0,
                write_failed: 0,
            },
        }
    }

    /// Render one event, stamped `at`, and put the line on the device. Answers
    /// whether the whole line reached the writer.
    ///
    /// Generic over the cause type so this is the single call both a decoded
    /// peer record ([`Event<Cause>`]) and the console domain's own event
    /// ([`Event`], whose cause is a literal) travel through.
    pub fn print<C: fmt::Display>(&mut self, at: Stamp, event: &Event<C>) -> bool {
        let mut line = [0u8; MAX_LINE_LEN];
        let Ok(written) = render(at, event, &mut line) else {
            bump(&mut self.counters.unrenderable);
            return false;
        };
        // `render` never reports more than it was given, so this cannot be
        // `None`; it is a `get` rather than a range index because a slice index
        // on the path a peer's record travels is what ENG-5 forbids, and the
        // rule is worth more than the one branch it costs.
        let Some(text) = line.get(..written) else {
            bump(&mut self.counters.unrenderable);
            return false;
        };
        if self.writer.write_bytes(text).is_err() || self.writer.write_bytes(LINE_END).is_err() {
            bump(&mut self.counters.write_failed);
            return false;
        }
        bump(&mut self.counters.printed);
        true
    }

    /// One round-robin pass over every ring: at most [`BURST_PER_RING`] records
    /// from each, starting one ring further along than the last pass did.
    /// Answers how many lines reached the device.
    ///
    /// Bounded by `readers.len() * BURST_PER_RING`, both of which are this
    /// domain's own — the slice is the set of regions the system description
    /// granted it, and the burst is the constant above. Nothing a writing
    /// domain publishes can extend a pass, which is what keeps a flooding peer
    /// from starving the rest (ENG-4).
    pub fn drain(&mut self, readers: &mut [LogReader<'_>]) -> usize {
        let Some(start) = self.next.checked_rem(readers.len()) else {
            // No rings to read. A console domain granted none is a system
            // description defect, but it is not this function's to fault over.
            return 0;
        };
        // `split_at_mut` rather than an index and a modulo: `start` is already
        // inside the slice, and the two halves visited tail-first *are* the
        // rotation, with no arithmetic per ring to get wrong.
        let (head, tail) = readers.split_at_mut(start);
        let mut printed = 0;
        for reader in tail.iter_mut().chain(head.iter_mut()) {
            printed += self.burst(reader);
        }
        self.next = start.wrapping_add(1);
        printed
    }

    /// Up to [`BURST_PER_RING`] records from one ring, stopping early when the
    /// ring is observed empty.
    fn burst(&mut self, reader: &mut LogReader<'_>) -> usize {
        let mut printed = 0;
        for _ in 0..BURST_PER_RING {
            let Some(record) = reader.read() else {
                break;
            };
            if self.print_record(record) {
                printed += 1;
            }
        }
        printed
    }

    /// One record from a peer's ring, through both refusals it can meet.
    ///
    /// Neither refusal stops the pass. A byzantine writer that filled its ring
    /// with rubbish would otherwise take the console down with it, and the
    /// records worth reading at that moment are the *other* domains'.
    fn print_record(&mut self, record: Result<CheckedRecord, LogRecordError>) -> bool {
        let Ok(checked) = record else {
            bump(&mut self.counters.malformed);
            return false;
        };
        let Ok((at, event)) = Event::<Cause>::decode(&checked) else {
            bump(&mut self.counters.unknown);
            return false;
        };
        self.print(at, &event)
    }

    /// The writer this printer owns, for a caller that has to ask the device
    /// about itself.
    ///
    /// It exists because the printer owns the writer outright (see the type's
    /// own note on why) and the console domain's shard carries both halves: the
    /// device's three counters are reachable only through the borrow this
    /// printer holds.
    #[must_use]
    pub const fn writer(&self) -> &W {
        &self.writer
    }

    /// A snapshot of the counters.
    #[must_use]
    pub const fn counters(&self) -> ConsoleCounters {
        self.counters
    }

    /// The ring the next [`drain`](Self::drain) will start at, modulo the ring
    /// count. Exposed so the rotation is assertable rather than inferred from
    /// output order.
    #[must_use]
    pub const fn next_ring(&self) -> usize {
        self.next
    }
}

#[cfg(test)]
mod tests;
