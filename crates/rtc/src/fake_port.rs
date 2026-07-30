//! A recording stand-in for an MC146818-compatible CMOS clock, for host tests
//! only.
//!
//! What this crate does to the part is *waiting*, *ordering* and *judgement*,
//! and none of the three is observable through a register file: a plain byte
//! array answers whatever was written to it, so a part that never reports its
//! update complete, that ticks between two passes, that encodes its values the
//! other way, that answers a byte no decimal names, or that answers a different
//! byte on every read cannot be expressed at all — and neither can "was status B
//! read inside the pass it decodes". This type implements [`CmosPortIo`] as a
//! part *chooses* to answer, and appends every port operation to a shared
//! [`Log`], so a test asserts the sequence rather than the end state.
//!
//! It models the *authority a device has* — any byte, for any index, a different
//! one on every read, and an index register that was never written — and
//! constrains none of it to what a conforming part would do (TEST-8).
//! [`FakeCmos::conforming`] is the well-behaved baseline; every builder method
//! takes one capability away from it.

use core::cell::{Cell, RefCell};
use std::rc::Rc;
use std::vec::Vec;

use crate::{
    CmosPortIo, DataMode, HOURS_PM, HourFormat, Register, STATUS_A_UIP, STATUS_B_24_HOUR,
    STATUS_B_BINARY,
};
use lfw_clock::CivilTime;

/// What an I/O port nothing decodes answers, and so what this part answers for
/// an index it has no register at — or for a data read taken before any index
/// was selected.
pub(crate) const UNDECODED: u8 = 0xFF;

/// Status A's low bits on a conforming part: the divider and periodic-interrupt
/// rate a PC-compatible BIOS programs. Present so that a test reading a
/// quiescent part reads them back, which is what makes the update-in-progress
/// bit's mask load-bearing rather than incidental.
pub(crate) const CONFORMING_DIVIDER_BITS: u8 = 0x26;

const _: () = assert!(CONFORMING_DIVIDER_BITS & STATUS_A_UIP == 0);

/// The instant [`FakeCmos::conforming`] holds: 2026-07-30T20:27:05Z, whose every
/// field is distinct enough that a transposed pair changes the answer.
pub(crate) const CONFORMING_INSTANT: CivilTime = CivilTime {
    year: 2026,
    month: 7,
    day: 30,
    hour: 20,
    minute: 27,
    second: 5,
    nanosecond: 0,
};

/// One port operation this crate made, in the order it made it. A data read
/// carries no index because the part it stands in for does not either: which
/// register answered is whatever the preceding [`Op::WriteIndex`] selected,
/// which is exactly the coupling a test needs to be able to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    WriteIndex { index: u8 },
    ReadData { value: u8 },
}

/// The shared, ordered record. Cloning shares the same log, which is what lets a
/// test hold it after the port has been moved into an [`crate::Rtc`].
#[derive(Clone, Default)]
pub(crate) struct Log(Rc<RefCell<Vec<Op>>>);

impl Log {
    /// Everything recorded so far, oldest first.
    pub(crate) fn ops(&self) -> Vec<Op> {
        self.0.borrow().clone()
    }

    /// How many port operations have been recorded — the quantity every
    /// termination assertion is made against, and cheaper to ask for than the
    /// operations themselves when a bounded poll has just run to its limit.
    pub(crate) fn len(&self) -> usize {
        self.0.borrow().len()
    }

    fn record(&self, op: Op) {
        self.0.borrow_mut().push(op);
    }
}

/// A CMOS clock that answers however a test tells it to.
pub(crate) struct FakeCmos {
    log: Log,
    /// The instant the register file holds, before any tick the builders add.
    time: CivilTime,
    mode: DataMode,
    format: HourFormat,
    /// Status A's bits other than [`STATUS_A_UIP`], which this part answers and
    /// this crate must ignore.
    status_a_noise: u8,
    /// Status B's bits other than the two that select the encoding, likewise.
    status_b_noise: u8,
    /// Reads of status A that report an update in progress before one reports
    /// the file quiescent; `None` never reports it quiescent.
    uip_clear_after: Option<u32>,
    /// Reads of the seconds register after which the file stops advancing;
    /// `None` advances on every read, so no two passes can ever agree.
    settles_after: Option<u32>,
    /// One register answers this cycled sequence instead of the model above,
    /// raw — so a test may make a single register answer a byte no encoding
    /// produces, or a different byte on every read.
    register_answers: Option<(Register, Vec<u8>)>,
    /// *Every* read answers this cycled sequence — the wholly arbitrary part,
    /// which overrides every model above.
    answers: Option<Vec<u8>>,
    /// The index the last write selected; `None` before any write.
    selected: Option<u8>,
    status_a_reads: Cell<u32>,
    seconds_reads: Cell<u32>,
    register_answer_reads: Cell<usize>,
    reads: Cell<usize>,
}

impl FakeCmos {
    /// A part that does what the datasheet says: packed decimal, 24-hour
    /// counting, the divider bits a BIOS leaves, a file that is quiescent on the
    /// first status-A read and does not move while it is being read.
    pub(crate) fn conforming() -> Self {
        Self {
            log: Log::default(),
            time: CONFORMING_INSTANT,
            mode: DataMode::Bcd,
            format: HourFormat::TwentyFour,
            status_a_noise: CONFORMING_DIVIDER_BITS,
            status_b_noise: 0,
            uip_clear_after: Some(0),
            settles_after: Some(0),
            register_answers: None,
            answers: None,
            selected: None,
            status_a_reads: Cell::new(0),
            seconds_reads: Cell::new(0),
            register_answer_reads: Cell::new(0),
            reads: Cell::new(0),
        }
    }

    /// A handle on the shared log, taken before the port is moved into the crate
    /// under test.
    pub(crate) fn log(&self) -> Log {
        self.log.clone()
    }

    /// Hold this instant instead of [`CONFORMING_INSTANT`].
    pub(crate) fn holding(mut self, time: CivilTime) -> Self {
        self.time = time;
        self
    }

    /// Report plain binary values, with status B's `DM` bit set to say so.
    pub(crate) fn in_binary_mode(mut self) -> Self {
        self.mode = DataMode::Binary;
        self
    }

    /// Count twelve hours to a half-day, with status B's 24/12 bit clear to say
    /// so and [`HOURS_PM`] carrying the afternoon.
    pub(crate) fn in_twelve_hour_mode(mut self) -> Self {
        self.format = HourFormat::Twelve;
        self
    }

    /// Answer these bits in status A alongside the update-in-progress bit.
    pub(crate) fn with_status_a_noise(mut self, noise: u8) -> Self {
        self.status_a_noise = noise;
        self
    }

    /// Answer these bits in status B alongside the two that select the encoding.
    pub(crate) fn with_status_b_noise(mut self, noise: u8) -> Self {
        self.status_b_noise = noise;
        self
    }

    /// Report an update in progress on every status-A read: a part whose update
    /// never ends, or whose bit is stuck.
    pub(crate) fn never_completing_update(mut self) -> Self {
        self.uip_clear_after = None;
        self
    }

    /// Report an update in progress for `reads` status-A reads and a quiescent
    /// file from the next one on.
    pub(crate) fn completing_update_after(mut self, reads: u32) -> Self {
        self.uip_clear_after = Some(reads);
        self
    }

    /// Advance the file by a second on every read of the seconds register, so no
    /// two consecutive passes can ever agree.
    pub(crate) fn never_settling(mut self) -> Self {
        self.settles_after = None;
        self
    }

    /// Advance the file by a second for `reads` reads of the seconds register,
    /// then hold still — a part caught mid-tick that then stops moving.
    pub(crate) fn settling_after(mut self, reads: u32) -> Self {
        self.settles_after = Some(reads);
        self
    }

    /// `register` answers this cycled sequence, raw, whatever the model holds.
    pub(crate) fn answering_register(mut self, register: Register, values: Vec<u8>) -> Self {
        self.register_answers = Some((register, values));
        self
    }

    /// `register` always answers this byte, raw — the one-element case of
    /// [`answering_register`](Self::answering_register), which is how a test
    /// drives a single register to a value no encoding of the model produces.
    pub(crate) fn misreporting(self, register: Register, value: u8) -> Self {
        self.answering_register(register, std::vec![value])
    }

    /// *Every* read answers these bytes in turn, cycling. The fully arbitrary
    /// part: no register is stable and none is truthful.
    pub(crate) fn answering(mut self, answers: Vec<u8>) -> Self {
        self.answers = Some(answers);
        self
    }

    /// The `nth` byte of a cycled answer sequence. An empty sequence answers
    /// [`UNDECODED`], so a test may hand over any vector at all.
    fn cycled(sequence: &[u8], nth: usize) -> u8 {
        match sequence.len() {
            0 => UNDECODED,
            len => sequence.get(nth % len).copied().unwrap_or(UNDECODED),
        }
    }

    /// What the part answers for whichever index is selected, before it is
    /// logged.
    fn answer(&self) -> u8 {
        let nth = self.reads.get();
        self.reads.set(nth.wrapping_add(1));
        if let Some(answers) = &self.answers {
            return Self::cycled(answers, nth);
        }
        let Some(index) = self.selected else {
            return UNDECODED;
        };
        if let Some((register, values)) = &self.register_answers
            && register.index() == index
        {
            let nth = self.register_answer_reads.get();
            self.register_answer_reads.set(nth.wrapping_add(1));
            return Self::cycled(values, nth);
        }
        if index == Register::StatusA.index() {
            return self.status_a();
        }
        if index == Register::StatusB.index() {
            return self.status_b();
        }
        if index == Register::Seconds.index() {
            return self.encode(self.seconds());
        }
        if index == Register::Minutes.index() {
            return self.encode(self.time.minute);
        }
        if index == Register::Hours.index() {
            return self.hours();
        }
        if index == Register::DayOfMonth.index() {
            return self.encode(self.time.day);
        }
        if index == Register::Month.index() {
            return self.encode(self.time.month);
        }
        if index == Register::Year.index() {
            return self.encode((self.time.year % 100) as u8);
        }
        if index == Register::Century.index() {
            return self.encode((self.time.year / 100) as u8);
        }
        // An index outside the closed vocabulary — an alarm register, a status
        // register this crate never reads, or general-purpose CMOS. A real part
        // answers whatever is there; `every_index_written_names_a_register_and_leaves_nmi_enabled`
        // is what says the crate under test never asks.
        UNDECODED
    }

    /// Status A: the noise bits, plus the update-in-progress bit for as long as
    /// this part reports one. The noise cannot forge quiescence and cannot
    /// prevent it, so a test may set every bit of it.
    fn status_a(&self) -> u8 {
        let nth = self.status_a_reads.get();
        self.status_a_reads.set(nth.wrapping_add(1));
        let quiescent = self.status_a_noise & !STATUS_A_UIP;
        match self.uip_clear_after {
            Some(after) if nth >= after => quiescent,
            _ => quiescent | STATUS_A_UIP,
        }
    }

    /// Status B: the noise bits, with the two that select the encoding forced to
    /// what this part actually does, so noise can never contradict the values
    /// the other registers answer.
    fn status_b(&self) -> u8 {
        let mut value = self.status_b_noise & !(STATUS_B_BINARY | STATUS_B_24_HOUR);
        if self.mode == DataMode::Binary {
            value |= STATUS_B_BINARY;
        }
        if self.format == HourFormat::TwentyFour {
            value |= STATUS_B_24_HOUR;
        }
        value
    }

    /// The seconds field, advanced by one per read until this part settles.
    /// Taken modulo a minute so every answer is a second a clock could hold.
    fn seconds(&self) -> u8 {
        let nth = self.seconds_reads.get();
        self.seconds_reads.set(nth.wrapping_add(1));
        let advance = match self.settles_after {
            Some(after) => nth.min(after),
            None => nth,
        };
        ((u32::from(self.time.second) + advance) % 60) as u8
    }

    /// The hours register, in whichever counting status B claims — and with
    /// [`HOURS_PM`] set over the encoded value rather than added to it, which is
    /// what the part does.
    fn hours(&self) -> u8 {
        match self.format {
            HourFormat::TwentyFour => self.encode(self.time.hour),
            HourFormat::Twelve => {
                let pm = self.time.hour >= 12;
                let twelve = match self.time.hour % 12 {
                    0 => 12,
                    hour => hour,
                };
                let encoded = self.encode(twelve);
                if pm { encoded | HOURS_PM } else { encoded }
            }
        }
    }

    /// One field in whichever encoding this part claims. The `% 10` keeps the
    /// tens nibble a nibble for any input, so a test holding an instant with a
    /// field above 99 gets a wrong-but-defined byte rather than an arithmetic
    /// fault in the double.
    fn encode(&self, value: u8) -> u8 {
        match self.mode {
            DataMode::Bcd => ((value / 10 % 10) << 4) | (value % 10),
            DataMode::Binary => value,
        }
    }
}

impl CmosPortIo for FakeCmos {
    fn write_index(&mut self, index: u8) {
        self.log.record(Op::WriteIndex { index });
        self.selected = Some(index);
    }

    fn read_data(&mut self) -> u8 {
        let value = self.answer();
        self.log.record(Op::ReadData { value });
        value
    }
}
