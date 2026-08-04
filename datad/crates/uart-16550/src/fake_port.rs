//! A recording stand-in for a 16550 controller, for host tests only.
//!
//! What the driver does to a UART is *ordering*, and ordering is not observable
//! through a register file: a plain byte array reads back exactly what was
//! written, so a controller that refuses the divisor, never reports its FIFOs
//! enabled, never empties its transmitter, or answers a different byte on every
//! read cannot be expressed at all — and neither can "was the divisor written
//! before the latch bit was set". This type implements [`PortIo`] as a
//! controller *chooses* to answer, and appends every operation to a shared
//! [`Log`], so a test asserts the sequence rather than the end state.
//!
//! It models the *authority a device has* — any byte, at any register, on any
//! read, changing between two reads of the same register — and constrains none
//! of it to what a conforming part would do.
//! [`FakePort::conforming`] is the well-behaved baseline; every builder method
//! takes one capability away from it.

use core::cell::RefCell;
use std::rc::Rc;
use std::vec::Vec;

use crate::{IIR_FIFOS_ENABLED, LCR_DLAB, LSR_THRE, PortIo, Register};

/// One thing the driver did to the controller, in the order it did it. A read
/// carries what the controller answered, because that is what the driver
/// decided on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Read { register: Register, value: u8 },
    Write { register: Register, value: u8 },
}

/// The shared, ordered record. Cloning shares the same log, which is what lets
/// a test hold it after the port has been moved into a [`crate::Uart`].
#[derive(Clone, Default)]
pub(crate) struct Log(Rc<RefCell<Vec<Op>>>);

impl Log {
    /// Everything recorded so far, oldest first.
    pub(crate) fn ops(&self) -> Vec<Op> {
        self.0.borrow().clone()
    }

    /// How many port operations have been recorded — the quantity every
    /// termination assertion is made against.
    pub(crate) fn len(&self) -> usize {
        self.0.borrow().len()
    }

    /// Everything recorded since the last call, clearing the log, so a test
    /// asserts one write's sequence rather than initialisation's as well.
    pub(crate) fn take(&self) -> Vec<Op> {
        core::mem::take(&mut self.0.borrow_mut())
    }

    fn record(&self, op: Op) {
        self.0.borrow_mut().push(op);
    }
}

/// A 16550 that answers however a test tells it to.
pub(crate) struct FakePort {
    log: Log,
    /// What the interrupt-enable register latched, while the divisor-latch bit
    /// is clear.
    ier: u8,
    /// What the line-control register latched. The divisor-latch bit is read
    /// out of this rather than tracked beside it, so the two cannot disagree.
    lcr: u8,
    divisor_low: u8,
    divisor_high: u8,
    /// Reads of the line status that report the transmitter busy before it is
    /// reported empty; `None` is a transmitter that never empties.
    thre_after: Option<u32>,
    /// Reads of the interrupt-identification register that report the FIFOs off
    /// before they are reported on; `None` is a reset that never completes.
    fifos_after: Option<u32>,
    /// Bytes handed to the transmitter after which it stops emptying, for a
    /// controller that accepts a burst and then wedges.
    wedge_after: Option<u32>,
    /// A register that always *reads* this value however the write latched — a
    /// controller that takes a setting and reports a different one.
    misreported: Option<(Register, u8)>,
    /// Line status answered from this sequence, cycled: every read may answer
    /// anything, and two reads of the same register need not agree.
    line_status: Option<Vec<u8>>,
    /// *Every* read answered from this sequence, cycled — the wholly arbitrary
    /// controller, which overrides every model above.
    answers: Option<Vec<u8>>,
    /// Whether the line-control register keeps reporting the divisor-latch bit
    /// after it has been written clear.
    holds_dlab: bool,
    lsr_reads: u32,
    iir_reads: u32,
    reads: usize,
    data_writes: u32,
}

impl FakePort {
    /// A controller that does what the part's datasheet says: it latches every
    /// register written to it, reports its FIFOs enabled as soon as they are,
    /// and always has room in its transmitter.
    pub(crate) fn conforming() -> Self {
        Self {
            log: Log::default(),
            ier: 0,
            lcr: 0,
            divisor_low: 0,
            divisor_high: 0,
            thre_after: Some(0),
            fifos_after: Some(0),
            wedge_after: None,
            misreported: None,
            line_status: None,
            answers: None,
            holds_dlab: false,
            lsr_reads: 0,
            iir_reads: 0,
            reads: 0,
            data_writes: 0,
        }
    }

    /// A handle on the shared log, taken before the port is moved into the
    /// driver.
    pub(crate) fn log(&self) -> Log {
        self.log.clone()
    }

    /// `register` always reads back `value`, whatever was written to it. The
    /// write still latches internally, so a step that depends on an earlier one
    /// having taken effect is unaffected and exactly one step is refused.
    pub(crate) fn misreporting(mut self, register: Register, value: u8) -> Self {
        self.misreported = Some((register, value));
        self
    }

    /// The line-control register keeps reporting the divisor-latch bit after it
    /// is written clear, so offsets 0 and 1 would stay the divisor latches.
    pub(crate) fn never_clearing_dlab(mut self) -> Self {
        self.holds_dlab = true;
        self
    }

    /// The transmitter never reports itself empty.
    pub(crate) fn never_asserting_thre(mut self) -> Self {
        self.thre_after = None;
        self
    }

    /// The transmitter reports itself busy for `reads` line-status reads and
    /// empty from the next one on.
    pub(crate) fn asserting_thre_after(mut self, reads: u32) -> Self {
        self.thre_after = Some(reads);
        self
    }

    /// The transmitter empties for `bytes` bytes and then never again.
    pub(crate) fn wedging_after(mut self, bytes: u32) -> Self {
        self.wedge_after = Some(bytes);
        self
    }

    /// The FIFOs are never reported enabled: a reset that never completes.
    pub(crate) fn never_enabling_fifos(mut self) -> Self {
        self.fifos_after = None;
        self
    }

    /// The FIFOs are reported off for `reads` reads of the
    /// interrupt-identification register and on from the next one.
    pub(crate) fn enabling_fifos_after(mut self, reads: u32) -> Self {
        self.fifos_after = Some(reads);
        self
    }

    /// The line status answers these bytes in turn, cycling — arbitrary status,
    /// changing on every read.
    pub(crate) fn with_line_status(mut self, status: Vec<u8>) -> Self {
        self.line_status = Some(status);
        self
    }

    /// *Every* register answers these bytes in turn, cycling. The fully
    /// arbitrary controller: no register is stable and none is truthful.
    pub(crate) fn answering(mut self, answers: Vec<u8>) -> Self {
        self.answers = Some(answers);
        self
    }

    /// Whether the divisor latches are currently addressed at offsets 0 and 1,
    /// derived from what the line-control register holds.
    fn dlab(&self) -> bool {
        self.lcr & LCR_DLAB != 0
    }

    /// The `nth` byte of a cycled answer sequence. An empty sequence answers
    /// zero, so a test may hand over any vector at all.
    fn cycled(sequence: &[u8], nth: usize) -> u8 {
        match sequence.len() {
            0 => 0,
            len => sequence.get(nth % len).copied().unwrap_or(0),
        }
    }

    /// What the controller answers for `register`, before it is logged.
    fn answer(&mut self, register: Register) -> u8 {
        let nth = self.reads;
        self.reads = self.reads.wrapping_add(1);
        if let Some(answers) = &self.answers {
            return Self::cycled(answers, nth);
        }
        if let Some((misreported, value)) = self.misreported
            && misreported == register
        {
            return value;
        }
        match register {
            Register::LineStatus => self.line_status_answer(),
            Register::FifoControl => self.iir_answer(),
            Register::LineControl if self.holds_dlab => self.lcr | LCR_DLAB,
            Register::LineControl => self.lcr,
            Register::InterruptEnable if self.dlab() => self.divisor_high,
            Register::InterruptEnable => self.ier,
            Register::Data if self.dlab() => self.divisor_low,
            // The receive buffer, which nothing on this link ever fills.
            Register::Data => 0,
        }
    }

    fn line_status_answer(&mut self) -> u8 {
        let nth = self.lsr_reads;
        self.lsr_reads = self.lsr_reads.wrapping_add(1);
        if let Some(status) = &self.line_status {
            return Self::cycled(status, nth as usize);
        }
        if self
            .wedge_after
            .is_some_and(|bytes| self.data_writes >= bytes)
        {
            return 0;
        }
        match self.thre_after {
            Some(after) if nth >= after => LSR_THRE,
            _ => 0,
        }
    }

    fn iir_answer(&mut self) -> u8 {
        let nth = self.iir_reads;
        self.iir_reads = self.iir_reads.wrapping_add(1);
        match self.fifos_after {
            Some(after) if nth >= after => IIR_FIFOS_ENABLED,
            _ => 0,
        }
    }
}

impl PortIo for FakePort {
    fn read(&mut self, register: Register) -> u8 {
        let value = self.answer(register);
        self.log.record(Op::Read { register, value });
        value
    }

    fn write(&mut self, register: Register, value: u8) {
        self.log.record(Op::Write { register, value });
        match register {
            Register::LineControl => self.lcr = value,
            Register::InterruptEnable if self.dlab() => self.divisor_high = value,
            Register::InterruptEnable => self.ier = value,
            Register::Data if self.dlab() => self.divisor_low = value,
            // The transmitter-holding register: the byte goes out of the part,
            // so the log is where a test sees it, not a register file.
            Register::Data => self.data_writes = self.data_writes.wrapping_add(1),
            // Write-only; a read of this offset is the interrupt-identification
            // register, which `iir_answer` models.
            Register::FifoControl => {}
            // Read-only on the real part.
            Register::LineStatus => {}
        }
    }
}
