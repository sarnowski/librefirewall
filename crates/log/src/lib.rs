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
//! None reaches this crate directly (CONCEPT §7.1). It is, however, the surface
//! on which values derived from the management-plane attacker's configuration
//! document are rendered, which is what shapes [`Value`]: a closed set of
//! already-parsed domain types with no arbitrary-bytes variant, so a byte
//! string out of a document has no representation that reaches a console line
//! (OBS-5). [`Identifier`] is the single exception and carries an alphabet
//! narrow enough to print.
//!
//! # No timestamps
//!
//! There is no clock anywhere in this system — no timer, no interrupt, no
//! trusted time source — so a record carries the configuration `generation` it
//! belongs to and a `sequence` counting from zero within that generation's own
//! records, rather than a reading. That is
//! a real limitation, not a simplification: records cannot be correlated
//! against an external system's timeline, and they are ordered and attributed
//! only within one boot. It is preferred to inventing a time base a reader
//! would then trust.
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
//! # No console backend here
//!
//! Writing to the console needs `sel4_microkit::debug_println`, which would
//! make this crate un-testable on the host and drag the Microkit target into
//! every consumer. The [`Sink`] implementation that prints therefore belongs in
//! a protection domain rather than here; [`RecordingSink`] is what a host test
//! uses in its place.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod detail;
mod event;
mod identifier;
mod render;

use core::cell::Cell;

pub use detail::{DomainDetail, MAX_CAUSE_LEN, Refusal, RefusalDetail};
pub use event::{
    ChangeKind, Domain, DomainState, Event, Field, GenerationOutcome, ObjectKind, RejectReason,
    Value,
};
pub use identifier::{Identifier, IdentifierError, MAX_IDENTIFIER_LEN};
pub use render::{MAX_LINE_LEN, RenderError, render};

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
        let written = render(&recorded, &mut buffer).expect("MAX_LINE_LEN holds every line");
        assert_eq!(&buffer[..written], b"LFW-PD domain=config state=refused");
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
