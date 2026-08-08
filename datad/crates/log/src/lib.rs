//! Typed events for the console today and OpenTelemetry later: a call site
//! names *what happened* and a backend decides how it reads.
//!
//! An OpenTelemetry log record is an attribute map rather than a line, so a
//! call site that formats its own text has already discarded the structure an
//! exporter needs, and there is no recovering it afterwards short of rewriting
//! every site. Emitting an [`Event`] defers that choice to the [`Sink`].
//!
//! # Adversary
//!
//! The byzantine peer protection domain, on one path: a record
//! decoded out of a shared region was written by another domain, and `record.rs`
//! is where that is refused. Everything else faces the management-plane attacker
//! at one remove — values derived from a configuration document are rendered
//! here, which is what shapes [`Value`]: already-parsed domain types with no
//! arbitrary-bytes variant, so a byte string out of a document reaches no
//! console line as itself, [`Identifier`] excepted for its alphabet.
//!
//! # Every record is stamped, and half of them with nothing
//!
//! A [`Sink`] stamps each record with a [`Stamp`] at the moment of emission,
//! and both cases are ordinary: a domain emitting before this node established
//! a time gets [`Stamp::Unsynchronized`], which is most of a boot transcript.
//! The absence is a case of the type rather than a zero, so no reader can take
//! it for 1970. What it is not is a *trusted* time — the epoch behind
//! it is an unauthenticated CMOS reading, a known open point — nor
//! an ordering: a change is attributed by `generation` and `sequence`, and an
//! instant is not an attribution.
//!
//! # Why `Identifier` is defined here
//!
//! An identifier is a configuration concept and would otherwise sit beside the
//! parser that validates one. The dependency runs `config → log` and never
//! back, so a record could not carry a type the configuration crate owns; it is
//! defined here and re-exported there.
//!
//! # Rendering without an allocator
//!
//! `format!` needs one and there is none, so [`render`] writes into a buffer
//! the caller owns and refuses one too small rather than truncating a line an
//! operator would read as complete.
//!
//! # The console backend, less its device
//!
//! Writing to the console needs a serial device, which one domain owns. Every
//! other domain puts the typed event in a shared region through [`RingSink`]
//! and that domain renders it, so the structure crosses and the text is
//! produced once — one grammar rather than one per writer. What that domain
//! then *decides* is here too, in [`ConsolePrinter`]: how it shares attention
//! between the rings, and what becomes of a record that decodes to nothing.
//! Only bytes leave, through [`ByteSink`], so the path stays host-testable.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod console;
mod detail;
mod event;
mod identifier;
mod record;
mod render;
mod ring;
mod stamp;

use core::cell::Cell;

pub use console::{BURST_PER_RING, ByteSink, ConsoleCounters, ConsolePrinter};
pub use detail::{
    Cause, CauseError, DomainDetail, MAX_CAUSE_LEN, MAX_OFFERED_POINTS, Refusal, RefusalDetail,
};
pub use event::{
    ChangeKind, DialOutcome, Domain, DomainState, Event, Field, GenerationOutcome, NextHopVia,
    ObjectKind, OnboardEnd, OnboardOutcome, OnboardRefusal, OnboardRoute, Primitive, RejectReason,
    TlsIncompatible, TlsRefusal, Value,
};
pub use identifier::{Identifier, IdentifierError, MAX_IDENTIFIER_LEN};
pub use record::{DecodeError, Vocabulary};
pub use render::{MAX_LINE_LEN, RenderError, render};
// Re-exported because this crate's own vocabulary names it: three details carry
// an address, so a caller composing one needs the type, and reaching past this
// crate for it would make every emitting domain depend on a networking crate
// whether it touches a frame or not.
pub use net_headers::Ipv4Address;
pub use ring::RingSink;
pub use stamp::{Clock, Stamp};

/// Where events go.
///
/// `&self` rather than `&mut self` because a sink is shared by every subsystem
/// of a domain that has anything to say, and threading a mutable borrow of it
/// through them would make what is logged a question of who holds the sink.
pub trait Sink {
    fn emit(&self, event: &Event);
}

/// A [`Sink`] that keeps what it was given, for host tests in this crate and in
/// every crate that emits events.
///
/// Bounded by `CAPACITY` with no allocator behind it, and what does not fit is
/// counted by [`RecordingSink::dropped`] rather than dropped silently — a test
/// that overran its sink and a test that emitted nothing must not look alike.
pub struct RecordingSink<const CAPACITY: usize> {
    events: Cell<[Option<Event>; CAPACITY]>,
    len: Cell<usize>,
    dropped: Cell<usize>,
}

impl<const CAPACITY: usize> RecordingSink<CAPACITY> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Cell::new([None; CAPACITY]),
            len: Cell::new(0),
            dropped: Cell::new(0),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len.get()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len.get() == 0
    }

    /// How many events arrived after `CAPACITY` was full.
    #[must_use]
    pub fn dropped(&self) -> usize {
        self.dropped.get()
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<Event> {
        if index >= self.len.get() {
            return None;
        }
        self.events.get().get(index).copied().flatten()
    }
}

impl<const CAPACITY: usize> Default for RecordingSink<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> Sink for RecordingSink<CAPACITY> {
    fn emit(&self, event: &Event) {
        let len = self.len.get();
        let mut events = self.events.get();
        match events.get_mut(len) {
            Some(slot) => {
                *slot = Some(*event);
                self.events.set(events);
                self.len.set(len.saturating_add(1));
            }
            None => self.dropped.set(self.dropped.get().saturating_add(1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(n: u32) -> Event {
        Event::ConfigGeneration {
            generation: n,
            outcome: GenerationOutcome::Applied,
            changes: 0,
        }
    }

    #[test]
    fn a_fresh_sink_holds_nothing() {
        let sink = RecordingSink::<4>::new();
        assert!(sink.is_empty());
        assert_eq!(sink.len(), 0);
        assert_eq!(sink.dropped(), 0);
        assert_eq!(sink.get(0), None);
    }

    #[test]
    fn events_come_back_in_the_order_they_were_emitted() {
        let sink = RecordingSink::<4>::default();
        for n in 0..3 {
            sink.emit(&generation(n));
        }
        assert_eq!(sink.len(), 3);
        assert!(!sink.is_empty());
        for n in 0..3 {
            assert_eq!(sink.get(n as usize), Some(generation(n)));
        }
        assert_eq!(sink.get(3), None);
    }

    #[test]
    fn what_does_not_fit_is_counted_rather_than_lost_quietly() {
        let sink = RecordingSink::<2>::new();
        for n in 0..5 {
            sink.emit(&generation(n));
        }
        assert_eq!(sink.len(), 2);
        assert_eq!(sink.dropped(), 3);
        assert_eq!(sink.get(0), Some(generation(0)));
        assert_eq!(sink.get(1), Some(generation(1)));
        assert_eq!(sink.get(2), None);
    }

    #[test]
    fn a_zero_capacity_sink_records_nothing_and_says_so() {
        let sink = RecordingSink::<0>::new();
        sink.emit(&generation(1));
        assert!(sink.is_empty());
        assert_eq!(sink.dropped(), 1);
        assert_eq!(sink.get(0), None);
    }

    #[test]
    fn a_sink_and_the_renderer_agree_on_what_was_emitted() {
        let sink = RecordingSink::<1>::new();
        sink.emit(&Event::Domain {
            domain: Domain::Config,
            state: DomainState::Refused,
            detail: DomainDetail::None,
        });
        let recorded = sink.get(0).expect("one event was emitted");
        let mut buffer = [0u8; MAX_LINE_LEN];
        let written = render(Stamp::Unsynchronized, &recorded, &mut buffer)
            .expect("MAX_LINE_LEN holds every line");
        assert_eq!(
            &buffer[..written],
            b"LFW-PD time=unsynchronized domain=config state=refused"
        );
    }

    /// A sink taken by reference is what a subsystem that only logs sees.
    #[test]
    fn a_sink_is_usable_through_the_trait_alone() {
        fn announce(sink: &dyn Sink) {
            sink.emit(&generation(9));
        }
        let sink = RecordingSink::<1>::new();
        announce(&sink);
        assert_eq!(sink.get(0), Some(generation(9)));
    }
}
