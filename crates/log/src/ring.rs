//! The [`Sink`] that puts an event in a shared region for the console to render.
//!
//! # Why it publishes and does not wake
//!
//! There is nothing to wake. The console busy-polls the cursors every writing
//! domain publishes and never reaches the Microkit event loop, so a send
//! capability on it would be authority granted for nothing (ENG-1).
//!
//! # Why it can only refuse, never wait
//!
//! A full records region means the console has not drained it, and the domains
//! that log the most are the ones logging *because* something went wrong.
//! Waiting would park a driver inside its own refusal path (ENG-4).
//!
//! # Two counters, because they accuse different parties
//!
//! [`RingSink::dropped`] is a flood or a console that is not draining;
//! [`RingSink::refused`] is this domain's own defect, an event it minted that
//! the ABI cannot carry. One number would leave an operator unable to tell "we
//! log faster than the console reads" from "this build emits records nothing
//! can read" (MONITORING.md's attribution rule).

use core::cell::{Cell, RefCell};

use wire::LogWriter;

use crate::Sink;
use crate::event::Event;
use crate::record::{SendError, send};
use crate::stamp::Clock;

/// A [`Sink`] that encodes each event into a domain's log ring, stamped with
/// the instant its [`Clock`] reports at the moment of the call.
pub struct RingSink<'ring, C> {
    /// `RefCell` because [`Sink::emit`] takes `&self` — a sink is shared by
    /// every subsystem with something to say — while publishing needs the
    /// writer's private position. Every borrow is fallible because a protection
    /// domain has no unwinder: a panicking `borrow_mut` would fault the domain
    /// over a log line (ENG-5).
    writer: RefCell<LogWriter<'ring>>,
    clock: C,
    dropped: Cell<u32>,
    refused: Cell<u32>,
}

impl<'ring, C: Clock> RingSink<'ring, C> {
    /// Takes the half [`LogRecords::writer`](wire::LogRecords::writer) says to take once.
    #[must_use]
    pub const fn new(writer: LogWriter<'ring>, clock: C) -> Self {
        Self {
            writer: RefCell::new(writer),
            clock,
            dropped: Cell::new(0),
            refused: Cell::new(0),
        }
    }

    /// Records the ring had no slot for, as the writer counts them.
    #[must_use]
    pub fn dropped(&self) -> u32 {
        self.dropped.get()
    }

    /// Records that never reached the ring at all: an event this build cannot
    /// encode, or a sink already in use further up the same stack. Saturating,
    /// because a wrap would read a sustained defect back as a small number.
    #[must_use]
    pub fn refused(&self) -> u32 {
        self.refused.get()
    }

    fn refuse(&self) {
        self.refused.set(self.refused.get().saturating_add(1));
    }
}

impl<C: Clock> Sink for RingSink<'_, C> {
    fn emit(&self, event: &Event) {
        let Ok(mut writer) = self.writer.try_borrow_mut() else {
            self.refuse();
            return;
        };
        match send(&mut writer, &self.clock, event) {
            Ok(()) => {}
            Err(SendError::Full { dropped }) => self.dropped.set(dropped),
            Err(SendError::Unencodable(_)) => self.refuse(),
        }
    }
}

#[cfg(test)]
mod tests;
