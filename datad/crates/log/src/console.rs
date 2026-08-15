//! Turning the records several domains published into the bytes one serial
//! line carries: the whole of what the console domain decides, in the crate
//! that already owns [`Event`] and [`render`].
//!
//! # Adversary
//!
//! The byzantine peer protection domain. Every record here came
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
//! decision inside a protection domain is reachable by no host test.
//! What is left for the domain is mapping the regions, claiming the port and
//! calling [`ConsolePrinter::drain`] in a loop.
//!
//! # Why the writer is a trait rather than the UART
//!
//! [`ByteSink`] keeps `crates/log` free of `uart-16550` — keeping `unsafe` in
//! the hardware crate, seen from the other side: this crate would otherwise depend on the
//! one crate in the workspace that executes `in`/`out`, and a host test of the
//! fairness rule below would be a test that cannot link. It is also what lets
//! every property here be asserted against a writer that fails on demand.
//!
//! # One printing mechanism, not two
//!
//! [`ConsolePrinter::print`] is generic over the cause type, so a record
//! decoded out of a peer's ring and the console domain's own lifecycle event
//! reach the device through the same call. There is deliberately no
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

use wire::{CheckedRecord, LogReader, LogRecordError, LogRelayWriter};

use crate::detail::Cause;
use crate::event::{Domain, Event};
use crate::render::{MAX_LINE_LEN, render};
use crate::stamp::Stamp;

/// Records one pass may take from a single ring before it moves to the next.
///
/// The fairness bound, and it is a constant of this crate rather than anything
/// read out of a region: a domain that fills its ring faster than the
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

/// What the console can say about itself, in the shape the metric catalogue
/// counts it.
///
/// Four failure counters rather than one, because they accuse four different
/// parties and an operator's next action differs for each: the peer's bytes,
/// the peer's vocabulary, this build's own renderer, and the device. Every
/// field is monotonic for the domain's life and saturates at [`u64::MAX`]; a
/// consumer differences successive readings, so a reset would forge a negative
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
    /// Lines the relay took, and so lines a recording can carry.
    ///
    /// It is deliberately not the same number as [`Self::printed`]: a line the
    /// device refused is still published, because the transcript is worth having
    /// on the surface that still works, and a line the relay refused is still
    /// printed.
    pub relayed: u64,
    /// Lines the relay had no slot for, the domain that writes the medium not
    /// draining it fast enough. Non-zero means the recorded transcript has a gap.
    ///
    /// It is a **counted drop and never a wait**: the console is the appliance's
    /// only diagnostic surface, and one that stalled on the recorder would go
    /// quiet exactly when the recorder is the thing that is wrong.
    pub relay_dropped: u64,
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
            transcript: [self.relayed, self.relay_dropped],
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

/// One writing domain's log ring, paired with the identity of the domain that
/// owns it.
///
/// The pairing is a capability fact and it is why this type exists. *Which*
/// region a record came out of is decided by the system description — a writing
/// domain cannot publish into a peer's ring — whereas the `domain=` token inside
/// a record is a field of a region its own domain writes, so a byzantine domain
/// can claim to be any of them. A transcript stored elsewhere wants the
/// unforgeable half, so the console carries it alongside the line.
///
/// Three of the eleven rings belong to the three instances of one driver, so
/// three of these carry the same [`Domain`] — the vocabulary having no instance
/// index rather than an ambiguity introduced here: the line for all three
/// already reads `domain=nic-driver`.
pub struct Ring<'ring> {
    origin: Domain,
    reader: LogReader<'ring>,
}

impl<'ring> Ring<'ring> {
    /// Pair a reader with the domain whose ring it drains.
    #[must_use]
    pub const fn new(origin: Domain, reader: LogReader<'ring>) -> Self {
        Self { origin, reader }
    }

    /// Which domain owns the ring this drains.
    #[must_use]
    pub const fn origin(&self) -> Domain {
        self.origin
    }

    /// Whether the ring is observed empty *at this instant*, judged against the
    /// writing domain's published cursor and so that domain's to influence.
    /// Exposed so a caller can see that a pass consumed what it read, which is
    /// not visible from the outside otherwise: the position this drained from is
    /// private to the reader and a second one would start over.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reader.is_empty()
    }
}

/// The console's renderer and its position in the round-robin over the rings.
///
/// It owns the writer outright. The device has exactly one owner in this system
/// — that is the whole reason the console is a domain — and a borrowed writer
/// would make a second printer expressible in a type.
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
                relayed: 0,
                relay_dropped: 0,
            },
        }
    }

    /// Render one event, stamped `at`, put the line on the device, and publish it
    /// to the relay the domain that writes the medium drains. Answers whether the
    /// whole line reached the writer.
    ///
    /// Generic over the cause type so this is the single call both a decoded
    /// peer record ([`Event<Cause>`]) and the console domain's own event
    /// ([`Event`], whose cause is a literal) travel through.
    ///
    /// `origin` is which domain's ring the record came out of, and it is
    /// deliberately not read off the record: a writing domain owns its own ring
    /// and may put any `domain=` token it likes in a record it publishes, whereas
    /// which ring a record was drained from is a fact of the capability topology
    /// that no writing domain can forge. The line carries the peer's own claim,
    /// as printed; this carries the ring.
    ///
    /// **The relay never decides whether a line is printed.** It is offered the
    /// line after the device has had it, and a relay with no room costs a counted
    /// drop; a device that refused costs the relay nothing. Two surfaces, and
    /// neither is allowed to silence the other.
    pub fn print<C: fmt::Display>(
        &mut self,
        origin: Domain,
        at: Stamp,
        event: &Event<C>,
        relay: &mut LogRelayWriter<'_>,
    ) -> bool {
        let mut line = [0u8; MAX_LINE_LEN];
        let Ok(written) = render(at, event, &mut line) else {
            bump(&mut self.counters.unrenderable);
            return false;
        };
        // `render` never reports more than it was given, so this cannot be
        // `None`; it is a `get` rather than a range index because a slice index
        // on the path a peer's record travels is a forbidden panic path, and the
        // rule is worth more than the one branch it costs.
        let Some(text) = line.get(..written) else {
            bump(&mut self.counters.unrenderable);
            return false;
        };
        let printed =
            self.writer.write_bytes(text).is_ok() && self.writer.write_bytes(LINE_END).is_ok();
        if printed {
            bump(&mut self.counters.printed);
        } else {
            bump(&mut self.counters.write_failed);
        }
        // The instant goes over as a number rather than as the text just
        // rendered: the line states an unsynchronized stamp in words, and a
        // reader that had to parse those words back would be parsing this
        // build's own prose to recover a field it could have been handed.
        let stamped = match at {
            Stamp::Unsynchronized => None,
            Stamp::Utc(utc) => Some(utc.as_nanos()),
        };
        if relay.publish(origin as u8, stamped, text) {
            bump(&mut self.counters.relayed);
        } else {
            bump(&mut self.counters.relay_dropped);
        }
        printed
    }

    /// One round-robin pass over every ring: at most [`BURST_PER_RING`] records
    /// from each, starting one ring further along than the last pass did.
    /// Answers how many lines reached the device.
    ///
    /// Bounded by `readers.len() * BURST_PER_RING`, both of which are this
    /// domain's own — the slice is the set of regions the system description
    /// granted it, and the burst is the constant above. Nothing a writing
    /// domain publishes can extend a pass, which is what keeps a flooding peer
    /// from starving the rest.
    pub fn drain(&mut self, rings: &mut [Ring<'_>], relay: &mut LogRelayWriter<'_>) -> usize {
        let Some(start) = self.next.checked_rem(rings.len()) else {
            // No rings to read. A console domain granted none is a system
            // description defect, but it is not this function's to fault over.
            return 0;
        };
        // `split_at_mut` rather than an index and a modulo: `start` is already
        // inside the slice, and the two halves visited tail-first *are* the
        // rotation, with no arithmetic per ring to get wrong.
        let (head, tail) = rings.split_at_mut(start);
        let mut printed = 0;
        for ring in tail.iter_mut().chain(head.iter_mut()) {
            printed += self.burst(ring, relay);
        }
        self.next = start.wrapping_add(1);
        printed
    }

    /// Up to [`BURST_PER_RING`] records from one ring, stopping early when the
    /// ring is observed empty.
    fn burst(&mut self, ring: &mut Ring<'_>, relay: &mut LogRelayWriter<'_>) -> usize {
        let mut printed = 0;
        for _ in 0..BURST_PER_RING {
            let Some(record) = ring.reader.read() else {
                break;
            };
            if self.print_record(ring.origin, record, relay) {
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
    fn print_record(
        &mut self,
        origin: Domain,
        record: Result<CheckedRecord, LogRecordError>,
        relay: &mut LogRelayWriter<'_>,
    ) -> bool {
        let Ok(checked) = record else {
            bump(&mut self.counters.malformed);
            return false;
        };
        let Ok((at, event)) = Event::<Cause>::decode(&checked) else {
            bump(&mut self.counters.unknown);
            return false;
        };
        self.print(origin, at, &event, relay)
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
