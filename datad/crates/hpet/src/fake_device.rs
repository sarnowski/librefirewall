//! A recording stand-in for an HPET register block, for host tests only.
//!
//! What this crate does to the block is *ordering* and *judgement*, and neither
//! is observable through a register file: plain host memory mapped at the
//! block's offsets reads back exactly what was written, so a block that claims
//! an impossible period, claims a 32-bit counter, refuses the bit that starts
//! its counter, never advances it, or answers a different number on every read
//! cannot be expressed at all — and neither can "was the configuration register
//! written before the capabilities register had been accepted". This type
//! implements [`HpetMmio`] as a block *chooses* to answer, and appends every
//! access to a shared [`Log`], so a test asserts the sequence rather than the
//! end state.
//!
//! It models the *authority a device has* — any capabilities word at all, any
//! counter reading, a different one on every read, a configuration register
//! that drops the bit written to it — and constrains none of it to what a
//! conforming part would do. [`FakeHpet::conforming`] is the
//! well-behaved baseline; every builder method takes one capability away from
//! it.

use core::cell::{Cell, RefCell};
use std::rc::Rc;
use std::vec::Vec;

use crate::{
    COUNT_SIZE_CAP, COUNTER_CLK_PERIOD_SHIFT, ENABLE_CNF, HpetMmio, INTERRUPT_PIN, Register,
    TN_INT_ENB_CNF, TN_INT_ROUTE_CAP_SHIFT, TN_PER_INT_CAP, TN_TYPE_CNF,
};

/// The period of the 14.31818 MHz crystal a PC-compatible chipset derives its
/// HPET from, in femtoseconds — what [`FakeHpet::conforming`] reports, and what
/// a test reads an expected frequency or tick count off.
pub(crate) const CRYSTAL_PERIOD_FEMTOSECONDS: u32 = 69_841_279;

/// The inputs [`FakeHpet::conforming`]'s comparator says it may drive: the one
/// this crate routes to, and a handful around it, so a test that widens or
/// narrows the bitmap states a change rather than the whole of it.
pub(crate) const CONFORMING_ROUTE_CAP: u32 = 0x00ff_0004;

// The baseline block must offer the input the crate under test asks for, or
// every arming test would be exercising the refusal instead of the sequence.
const _: () = assert!(CONFORMING_ROUTE_CAP & (1 << INTERRUPT_PIN) != 0);

/// One access this crate made to the block, in the order it made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Read { register: Register, value: u64 },
    Write { register: Register, value: u64 },
}

/// The shared, ordered record. Cloning shares the same log, which is what lets
/// a test hold it after the device has been moved into an [`crate::Hpet`].
#[derive(Clone, Default)]
pub(crate) struct Log(Rc<RefCell<Vec<Op>>>);

impl Log {
    /// Everything recorded so far, oldest first.
    pub(crate) fn ops(&self) -> Vec<Op> {
        self.0.borrow().clone()
    }

    /// How many accesses have been recorded — the quantity every termination
    /// assertion is made against, and cheaper to ask for than the accesses
    /// themselves when a bounded poll has just run to its limit.
    pub(crate) fn len(&self) -> usize {
        self.0.borrow().len()
    }

    /// Everything recorded since the last call, clearing the log, so a test
    /// asserts one wait's sequence rather than the probe's as well.
    pub(crate) fn take(&self) -> Vec<Op> {
        core::mem::take(&mut self.0.borrow_mut())
    }

    fn record(&self, op: Op) {
        self.0.borrow_mut().push(op);
    }
}

/// A General Capabilities and ID word built from the three fields this crate
/// reads, so a test states what a block claims rather than a hex constant.
pub(crate) const fn capabilities_word(
    revision: u8,
    wide_counter: bool,
    period_femtoseconds: u32,
) -> u64 {
    let identity = revision as u64 | ((period_femtoseconds as u64) << COUNTER_CLK_PERIOD_SHIFT);
    if wide_counter {
        identity | COUNT_SIZE_CAP
    } else {
        identity
    }
}

/// An HPET block that answers however a test tells it to.
pub(crate) struct FakeHpet {
    log: Log,
    /// The whole General Capabilities and ID word, so a test may claim anything
    /// at all — including a word no conforming part could produce.
    capabilities: u64,
    /// What the General Configuration register holds, and answers.
    configuration: u64,
    /// Whether a write to the configuration register latches [`ENABLE_CNF`]. A
    /// block that drops it is one whose counter never runs.
    accepts_enable: bool,
    /// What Timer 0's Configuration and Capability register holds, and answers:
    /// the read-only capability bits a block chooses, and whatever the crate
    /// under test wrote into the rest.
    timer_configuration: u64,
    /// Whether a write to that register latches the bits that arm it. A block
    /// that drops them is one whose comparator never raises an input.
    accepts_arming: bool,
    /// What Timer 0's Comparator register holds. Written twice by an arming and
    /// read by nothing, so it exists for the log to carry both values.
    timer_comparator: u64,
    /// The first reading of the main counter.
    counter_base: u64,
    /// Ticks the counter advances per read; zero is a counter that never moves.
    ticks_per_read: u64,
    counter_reads: Cell<u64>,
    /// Main-counter readings answered from this cycled sequence: any number, a
    /// different one on every read, including one lower than the last.
    counter_answers: Option<Vec<u64>>,
    /// *Every* read answered from this cycled sequence — the wholly arbitrary
    /// block, which overrides every model above.
    answers: Option<Vec<u64>>,
    reads: Cell<u64>,
}

impl FakeHpet {
    /// A block that does what the specification says: revision 1, a 64-bit
    /// counter, the crystal's period, a configuration register that latches
    /// what is written to it, and a counter that advances by one tick per read.
    pub(crate) fn conforming() -> Self {
        Self {
            log: Log::default(),
            capabilities: capabilities_word(1, true, CRYSTAL_PERIOD_FEMTOSECONDS),
            configuration: 0,
            accepts_enable: true,
            timer_configuration: TN_PER_INT_CAP
                | (u64::from(CONFORMING_ROUTE_CAP) << TN_INT_ROUTE_CAP_SHIFT),
            accepts_arming: true,
            timer_comparator: 0,
            counter_base: 0,
            ticks_per_read: 1,
            counter_reads: Cell::new(0),
            counter_answers: None,
            answers: None,
            reads: Cell::new(0),
        }
    }

    /// A handle on the shared log, taken before the device is moved into the
    /// crate under test.
    pub(crate) fn log(&self) -> Log {
        self.log.clone()
    }

    /// Answer this General Capabilities and ID word, whatever it claims.
    pub(crate) fn with_capabilities(mut self, capabilities: u64) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Claim this `COUNTER_CLK_PERIOD`, leaving the rest of the word alone.
    pub(crate) fn with_period(mut self, femtoseconds: u32) -> Self {
        let identity = self.capabilities & u64::from(u32::MAX);
        self.capabilities = identity | (u64::from(femtoseconds) << COUNTER_CLK_PERIOD_SHIFT);
        self
    }

    /// Claim a 32-bit main counter.
    pub(crate) fn without_64_bit_counter(mut self) -> Self {
        self.capabilities &= !COUNT_SIZE_CAP;
        self
    }

    /// Hold this General Configuration word before the probe touches it — the
    /// bits firmware left set.
    pub(crate) fn with_configuration(mut self, configuration: u64) -> Self {
        self.configuration = configuration;
        self
    }

    /// Drop [`ENABLE_CNF`] from every write to the configuration register, so
    /// the counter is never started.
    pub(crate) fn refusing_enable(mut self) -> Self {
        self.accepts_enable = false;
        self
    }

    /// Hold this Timer 0 Configuration and Capability word before the arming
    /// touches it — any word at all, including one no conforming part could
    /// produce.
    pub(crate) fn with_timer_configuration(mut self, configuration: u64) -> Self {
        self.timer_configuration = configuration;
        self
    }

    /// Claim a comparator that cannot re-arm itself.
    pub(crate) fn without_periodic_capability(mut self) -> Self {
        self.timer_configuration &= !TN_PER_INT_CAP;
        self
    }

    /// Claim this set of routable inputs, leaving the rest of the word alone.
    pub(crate) fn routable_to(mut self, route_cap: u32) -> Self {
        self.timer_configuration &= u64::from(u32::MAX);
        self.timer_configuration |= u64::from(route_cap) << TN_INT_ROUTE_CAP_SHIFT;
        self
    }

    /// Drop the bits that arm the comparator from every write to its
    /// configuration register, so no input is ever raised.
    pub(crate) fn refusing_arming(mut self) -> Self {
        self.accepts_arming = false;
        self
    }

    /// Start the main counter at this reading, so a test can place it just
    /// below the top of `u64` and drive the wrap.
    pub(crate) fn counting_from(mut self, base: u64) -> Self {
        self.counter_base = base;
        self
    }

    /// Advance the counter by this many ticks per read.
    pub(crate) fn ticking_per_read(mut self, ticks: u64) -> Self {
        self.ticks_per_read = ticks;
        self
    }

    /// A counter that answers the same number forever.
    pub(crate) fn with_stuck_counter(mut self) -> Self {
        self.ticks_per_read = 0;
        self
    }

    /// The main counter answers these readings in turn, cycling — arbitrary
    /// readings, including ones that go backwards.
    pub(crate) fn answering_counter(mut self, readings: Vec<u64>) -> Self {
        self.counter_answers = Some(readings);
        self
    }

    /// *Every* register answers these words in turn, cycling. The fully
    /// arbitrary block: no register is stable and none is truthful.
    pub(crate) fn answering(mut self, answers: Vec<u64>) -> Self {
        self.answers = Some(answers);
        self
    }

    /// The `nth` word of a cycled answer sequence. An empty sequence answers
    /// zero, so a test may hand over any vector at all.
    fn cycled(sequence: &[u64], nth: u64) -> u64 {
        match sequence.len() {
            0 => 0,
            len => sequence
                .get((nth % len as u64) as usize)
                .copied()
                .unwrap_or(0),
        }
    }

    /// What the block answers for `register`, before it is logged.
    fn answer(&self, register: Register) -> u64 {
        let nth = self.reads.get();
        self.reads.set(nth.wrapping_add(1));
        if let Some(answers) = &self.answers {
            return Self::cycled(answers, nth);
        }
        match register {
            Register::Capabilities => self.capabilities,
            Register::Configuration => self.configuration,
            Register::MainCounter => self.counter_answer(),
            Register::Timer0Configuration => self.timer_configuration,
            Register::Timer0Comparator => self.timer_comparator,
        }
    }

    /// The next main-counter reading. Wrapping, so a base near the top of `u64`
    /// carries the sequence through zero exactly as the part does.
    fn counter_answer(&self) -> u64 {
        let nth = self.counter_reads.get();
        self.counter_reads.set(nth.wrapping_add(1));
        if let Some(readings) = &self.counter_answers {
            return Self::cycled(readings, nth);
        }
        self.counter_base
            .wrapping_add(nth.wrapping_mul(self.ticks_per_read))
    }
}

impl HpetMmio for FakeHpet {
    fn read_u64(&self, register: Register) -> u64 {
        let value = self.answer(register);
        self.log.record(Op::Read { register, value });
        value
    }

    fn write_u64(&mut self, register: Register, value: u64) {
        self.log.record(Op::Write { register, value });
        // Three registers latch: a write to the read-only capabilities
        // register, or to the main counter, is dropped exactly as the part
        // drops one it does not take. That the crate under test never makes
        // either write is asserted by
        // `no_path_writes_a_register_the_part_does_not_take`.
        match register {
            Register::Configuration => {
                self.configuration = if self.accepts_enable {
                    value
                } else {
                    value & !ENABLE_CNF
                };
            }
            // The read-only capability bits are the part's and survive whatever
            // is written over them, which is what lets a refusing block keep
            // claiming it could have been armed.
            Register::Timer0Configuration => {
                const READ_ONLY: u64 =
                    TN_PER_INT_CAP | ((u32::MAX as u64) << TN_INT_ROUTE_CAP_SHIFT);
                let taken = if self.accepts_arming {
                    value
                } else {
                    value & !(TN_INT_ENB_CNF | TN_TYPE_CNF)
                };
                self.timer_configuration =
                    (self.timer_configuration & READ_ONLY) | (taken & !READ_ONLY);
            }
            Register::Timer0Comparator => self.timer_comparator = value,
            Register::Capabilities | Register::MainCounter => {}
        }
    }
}
