//! The High Precision Event Timer: the register protocol that decides whether
//! the block at [`MMIO_BASE`] is one, starts its main counter, and measures a
//! bounded span of that counter's ticks.
//!
//! It exists to be the reference oscillator a node calibrates its timestamp
//! counter against — the tick delta and frequency `lfw_clock::calibrate` takes
//! as its reference arguments. What earns it that role over every other timer
//! on the part is that its rate is *self-describing*: the capabilities register
//! states its own tick period in femtoseconds, so no frequency is configured
//! here and none is assumed. The design leaves the trusted-time mechanism
//! open; this crate is the measurement half of what would settle it, and it
//! exposes no signal of its own.
//!
//! # The adversary
//!
//! A **hostile or malfunctioning device**. Every number this crate
//! sees is one the block chose: its revision, the period it claims, the width
//! it claims for its counter, whether the configuration register keeps the bit
//! that starts the counter, and every counter reading. A block that answers
//! nothing — an unclaimed window reads all-ones — is indistinguishable from one
//! that answers wrongly, and both are met the same way: nothing is believed
//! without being ranged, every wait is bounded by a named constant of this
//! crate's own rather than by anything the device reports, and every
//! refusal is its own [`HpetError`]. A timer that never ticks must cost a
//! calibration, not the domain that attempted it.
//!
//! # Why no memory access lives here
//!
//! Reaching the block under seL4 means a volatile access through a pointer into
//! a region Microkit mapped into the domain — authority no portable crate can
//! hold, and `unsafe` besides. [`HpetMmio`] is the seam that authority is
//! supplied behind, for the reason `uart_16550::PortIo` is one: the interesting
//! behaviours are *disagreements* between what the driver wrote and what it
//! reads back, and the instruction that produces them cannot run in a host test
//! at all. A protection domain implements the trait over its mapped region;
//! here there is no `unsafe` and no seL4 dependency.
//!
//! # Why there is nothing to configure
//!
//! [`MMIO_BASE`] and [`MMIO_LENGTH`] are constants rather than parameters
//! because they are hardware topology, and hardware is fixed in the
//! system description at build time: the region this crate may touch is granted
//! by a `<memory_region>` element, so a runtime base would be a value the
//! capability could not follow. The build-time constant and the grant are one
//! fact stated twice, and the second statement is checked by the assertions
//! beside [`Register::offset`].
//!
//! Reading the base from the ACPI HPET description table was rejected for
//! exactly that reason. ACPI is the authoritative source and 0xFED00000 is only
//! the address every x86 chipset has in fact placed the block at — but a base
//! discovered at run time is one no statically granted capability could map, so
//! the authoritative answer is unusable and the conventional one is checkable.
//!
//! # Rejected alternatives
//!
//! * **Assuming a timestamp-counter frequency**, from CPUID leaf 0x15 or from
//!   the brand string. Neither is universally populated, a hypervisor is free to
//!   report a nominal value it does not deliver, and a wrong frequency is not a
//!   refusal but a clock that drifts — the failure mode that reaches TLS
//!   validation as an expiry judged against the wrong instant. A
//!   measured interval against a self-describing reference is checkable;
//!   an assumed constant is not.
//! * **The 8254 PIT.** It is reachable at legacy I/O ports, which would mean a
//!   second `<ioport>` grant and a wider port authority for the domain, and it
//!   counts *down* from a divisor at a rate this crate would have to hard-code
//!   because the part does not state it. The HPET is a plain memory region and
//!   states its own rate, so it costs one `<memory_region>` and no assumption.
//! * **A comparator-driven interrupt** instead of the polled wait below. It is
//!   the right end state and would remove the polling entirely, but it would
//!   introduce the system's first IRQ and a new capability class — a change to
//!   the capability topology, not to a driver.
//! * **Programming any comparator at all.** Only the main counter is read, so
//!   the timer block's comparators, their routing, and `NUM_TIM_CAP` are never
//!   touched and nothing here reports them: an accessor for a field no caller
//!   acts on would be surface without a purpose.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::num::NonZeroU64;

use lfw_clock::{Duration, NANOS_PER_SECOND};

#[cfg(test)]
mod fake_device;

/// The physical address x86 chipsets place the HPET register block at, and so
/// the address the `<memory_region>` granting it carries.
pub const MMIO_BASE: usize = 0xFED0_0000;

/// Bytes the register block occupies — 1 KiB, fixed by the HPET specification —
/// and the width every access this crate makes stays inside.
pub const MMIO_LENGTH: usize = 0x400;

/// Bytes of an x86_64 page, the granularity a `<memory_region>` is granted at.
const PAGE_SIZE: usize = 0x1000;

/// Bytes the system description reserves, which is not [`MMIO_LENGTH`]: a
/// grant is whole pages. Derived here so the gate compares one fact, not two.
pub const MMIO_REGION_SIZE: usize = MMIO_LENGTH.next_multiple_of(PAGE_SIZE);

/// Femtoseconds in a second: the scale `COUNTER_CLK_PERIOD` is stated in.
pub const FEMTOSECONDS_PER_SECOND: u64 = 1_000_000_000_000_000;

/// Femtoseconds in a nanosecond, which is what makes [`Hpet::ticks_for`] an
/// exact division rather than a rescaling.
pub const FEMTOSECONDS_PER_NANOSECOND: u64 = 1_000_000;

/// The largest `COUNTER_CLK_PERIOD` the specification permits: 100 ns, stated
/// in femtoseconds. A block reporting more than this is reporting a counter
/// slower than the specification allows one to be, which is the same evidence
/// as a period of zero — that the register read is not a capabilities register.
pub const MAX_CLOCK_PERIOD_FEMTOSECONDS: u32 = 0x05F5_E100;

// The ceiling is a spec constant given as a hex literal, so the identity it
// encodes is restated as a product: a wrong literal would shift the whole
// plausible band and break no other assertion.
const _: () = assert!(MAX_CLOCK_PERIOD_FEMTOSECONDS as u64 == 100 * FEMTOSECONDS_PER_NANOSECOND);

/// The slowest counter a period inside the band can name, in hertz — the
/// frequency [`MAX_CLOCK_PERIOD_FEMTOSECONDS`] yields.
pub const MIN_FREQUENCY_HZ: u64 = FEMTOSECONDS_PER_SECOND / MAX_CLOCK_PERIOD_FEMTOSECONDS as u64;

/// The fastest counter a period inside the band can name, in hertz — the
/// frequency a period of one femtosecond yields.
pub const MAX_FREQUENCY_HZ: u64 = FEMTOSECONDS_PER_SECOND;

// A band whose floor were zero would admit a stopped counter as a calibrated
// one, and `ClockPeriod::new` rests on the floor being above zero for its
// `NonZeroU64` to exist at all.
const _: () = assert!(MIN_FREQUENCY_HZ > 0);
const _: () = assert!(MIN_FREQUENCY_HZ < MAX_FREQUENCY_HZ);

/// Reads of the main counter one [`Hpet::wait_ticks`] may make while waiting
/// for it to advance far enough.
///
/// A read of an uncached device register costs at least a bus cycle and in
/// practice hundreds of nanoseconds, while the slowest counter the band admits
/// ticks every 100 ns, so a working block advances by at least one tick per
/// read — which makes this bound a span as well as a count, and
/// [`WORST_CASE_SERVICEABLE_WAIT`] states that span. It is a constant of this
/// crate rather than anything derived from the device, which is what makes the
/// loop bounded by a value the adversary does not choose.
pub const COUNTER_POLL_LIMIT: u32 = 1_000_000;

/// The most main-counter reads one [`Hpet::wait_ticks`] can make, whatever the
/// device answers: the bounded poll, and the one reading it started from.
/// Asserting a run against this is how a test proves the wait terminates rather
/// than merely that it terminated this time.
pub const WAIT_READS_MAX: u32 = COUNTER_POLL_LIMIT + 1;

/// The longest span [`Hpet::wait_ticks`] can serve on the least favourable
/// block the specification admits — one advancing its counter by a single tick
/// per read, at the slowest frequency [`MAX_CLOCK_PERIOD_FEMTOSECONDS`] names.
///
/// A caller sizing a calibration window compares it against this rather than
/// against [`COUNTER_POLL_LIMIT`], which is a count and not a duration.
pub const WORST_CASE_SERVICEABLE_WAIT: Duration =
    Duration::from_nanos(COUNTER_POLL_LIMIT as u64 * NANOS_PER_SECOND / MIN_FREQUENCY_HZ);

// A calibration interval of about a millisecond resolves a gigahertz-class
// counter to better than a part in ten thousand, so the bound is checked to
// leave an order of magnitude over one rather than argued to be generous.
const _: () =
    assert!(WORST_CASE_SERVICEABLE_WAIT.as_nanos() >= Duration::from_millis(10).as_nanos());

/// General Capabilities and ID bits 7:0, the revision. Zero for no block at
/// all: the specification requires a present HPET to report a non-zero one.
const REV_ID_MASK: u64 = 0xFF;

/// General Capabilities and ID bit 13, `COUNT_SIZE_CAP`: set for a 64-bit main
/// counter, clear for a 32-bit one.
const COUNT_SIZE_CAP: u64 = 1 << 13;

/// Bit position of General Capabilities and ID bits 63:32,
/// `COUNTER_CLK_PERIOD` — the block's tick period in femtoseconds.
const COUNTER_CLK_PERIOD_SHIFT: u32 = 32;

/// General Configuration bit 0, `ENABLE_CNF`: set, the main counter runs.
const ENABLE_CNF: u64 = 1 << 0;

/// One addressable register of the block, named by the offset it sits at within
/// the granted [`MMIO_LENGTH`] bytes.
///
/// It is also the whole of what [`HpetMmio`] accepts, so an offset outside the
/// block is unrepresentable rather than rejected: nothing validates a bound
/// here because nothing can name a value that would fail one. Only the three
/// registers this crate uses are declared, so the timer comparators and their
/// configuration — which lie in the same granted region — cannot be addressed
/// at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum Register {
    /// Offset 0x000. General Capabilities and ID, read-only: the revision, the
    /// counter width, and the tick period.
    Capabilities = 0x000,
    /// Offset 0x010. General Configuration, read/write: [`ENABLE_CNF`] and the
    /// legacy-routing bit this crate preserves without interpreting.
    Configuration = 0x010,
    /// Offset 0x0F0. Main Counter Value — the free-running count
    /// [`Hpet::wait_ticks`] measures.
    MainCounter = 0x0F0,
}

impl Register {
    /// Every register this crate can address, so an [`HpetMmio`] proving its
    /// authority spans the whole demand enumerates it rather than restating it.
    pub const ALL: [Self; 3] = [Self::Capabilities, Self::Configuration, Self::MainCounter];

    /// This register's offset from the base of the block.
    ///
    /// `pub` for the reason `uart_16550::Register::port` is: an [`HpetMmio`]
    /// implementation composes its mapped base with this, so it need not
    /// restate — unchecked — a register map the assertions below range.
    #[must_use]
    pub const fn offset(self) -> usize {
        self as usize
    }
}

// The HPET register map is fixed by the specification, and a wrong discriminant
// would address a different register rather than fail: 0x0F0 read as 0x0F8
// answers the upper half of a comparator, which on a conforming part is a
// plausible-looking number that never advances.
const _: () = assert!(Register::Capabilities.offset() == 0x000);
const _: () = assert!(Register::Configuration.offset() == 0x010);
const _: () = assert!(Register::MainCounter.offset() == 0x0F0);

// Every access is one aligned 64-bit quantity wholly inside the block, and the
// block is wholly inside one page — which is what makes a single
// `<memory_region>` of one page the complete grant this crate needs.
const _: () = assert!(
    Register::Capabilities
        .offset()
        .is_multiple_of(size_of::<u64>())
);
const _: () = assert!(
    Register::Configuration
        .offset()
        .is_multiple_of(size_of::<u64>())
);
const _: () = assert!(
    Register::MainCounter
        .offset()
        .is_multiple_of(size_of::<u64>())
);
const _: () = assert!(Register::MainCounter.offset() + size_of::<u64>() <= MMIO_LENGTH);
const _: () = assert!(MMIO_BASE.is_multiple_of(MMIO_LENGTH));
const _: () = assert!(MMIO_BASE % PAGE_SIZE + MMIO_LENGTH <= PAGE_SIZE);
// One page and not two, the line above having put the whole block inside one.
const _: () = assert!(MMIO_REGION_SIZE == PAGE_SIZE);

/// Aligned 64-bit access to the block's registers.
///
/// `read_u64` takes `&self` because reading any of the three is free of effect
/// on the part: unlike a UART's receive buffer, the main counter does not pop
/// and the capabilities register does not clear.
pub trait HpetMmio {
    fn read_u64(&self, register: Register) -> u64;

    fn write_u64(&mut self, register: Register, value: u64);
}

/// Why the block was not accepted, or why a wait over its counter was not
/// completed.
///
/// Every variant carries what the device answered, because an operator with no
/// shell separates an absent block — every read answering
/// all-ones — from one that claims an impossible period, and a dead counter
/// from a slow one, only if the cases produce different console lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpetError {
    /// `REV_ID` is zero, which the specification forbids a present block from
    /// reporting. The whole capabilities word is carried because it is what
    /// separates a window nothing decodes (all-ones) from one backed by memory
    /// that was never a register (zero).
    NotPresent { capabilities: u64 },
    /// `COUNTER_CLK_PERIOD` is zero or above the specification's 100 ns
    /// ceiling, so the register read is not a capabilities register — and a
    /// period of zero is besides the one value no frequency can be derived
    /// from.
    ImplausibleClockPeriod { femtoseconds: u32 },
    /// `COUNT_SIZE_CAP` is clear: the main counter is 32 bits wide, so it wraps
    /// every few minutes at any rate the band admits and the upper half of
    /// every reading is a constant. The wrapping difference [`Hpet::wait_ticks`]
    /// measures is defined over the whole of `u64` and would read such a wrap
    /// as an advance of nearly 2^64 ticks.
    CounterTooNarrow { capabilities: u64 },
    /// The configuration register did not report `ENABLE_CNF` after it was
    /// written set, so the main counter is not running and every reading of it
    /// would be the same number.
    NotEnabled { read_back: u64 },
    /// The main counter did not advance at all across [`COUNTER_POLL_LIMIT`]
    /// reads, carrying the value it kept answering.
    CounterStalled { polls: u32, counter: u64 },
    /// The main counter advanced, but by less than was asked for within
    /// [`COUNTER_POLL_LIMIT`] reads. Distinct from [`Self::CounterStalled`]
    /// because the block is alive: what is wrong is the window, and `observed`
    /// against `wanted` is what says by how much.
    CounterTooSlow {
        polls: u32,
        observed: u64,
        wanted: u64,
    },
    /// The span names more ticks of this counter than `u64` can count.
    /// Reachable only for spans of hours against the fastest period the band
    /// admits, and refused rather than truncated because a silently shortened
    /// calibration window is one whose result is wrong without saying so.
    DurationTooLong { nanoseconds: u64 },
}

/// A `COUNTER_CLK_PERIOD` the specification's band admits, and the frequency it
/// names.
///
/// The two travel together in one value produced by one constructor, so they
/// cannot disagree and no caller can compose a frequency from a period the band
/// refused. It is also what makes [`Hpet::frequency_hz`] a
/// [`NonZeroU64`] with no failure path: the type is the one
/// `lfw_clock::calibrate` takes for its reference rate, so a caller reaches
/// that function with nothing left to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClockPeriod {
    femtoseconds: u32,
    frequency_hz: NonZeroU64,
}

impl ClockPeriod {
    /// The only constructor: `None` for a period outside the band.
    const fn new(femtoseconds: u32) -> Option<Self> {
        if femtoseconds == 0 || femtoseconds > MAX_CLOCK_PERIOD_FEMTOSECONDS {
            return None;
        }
        // A period in `1..=MAX_CLOCK_PERIOD_FEMTOSECONDS` divides
        // `FEMTOSECONDS_PER_SECOND` to at least `MIN_FREQUENCY_HZ`, which the
        // assertion above holds above zero — so this `None` is unreachable, and
        // it funnels into the same refusal as the range check above rather than
        // inventing a second cause for one that cannot happen.
        match NonZeroU64::new(FEMTOSECONDS_PER_SECOND / femtoseconds as u64) {
            Some(frequency_hz) => Some(Self {
                femtoseconds,
                frequency_hz,
            }),
            None => None,
        }
    }
}

/// A block that has answered as an HPET and whose main counter has been
/// confirmed running.
///
/// Only [`probe`](Self::probe) produces one, so reading a counter that was
/// never started, or scaling a span by a period the band refused, cannot be
/// written rather than being a rule to remember.
pub struct Hpet<M: HpetMmio> {
    mmio: M,
    period: ClockPeriod,
}

impl<M: HpetMmio> Hpet<M> {
    /// Decide whether the block is an HPET this crate can use, start its main
    /// counter, and confirm the start by reading the configuration register
    /// back.
    ///
    /// Three reads and one write, and no loop at all: every question asked here
    /// is answered by the first read of the register that answers it, so there
    /// is nothing for a device to answer forever without agreeing. The checks
    /// run identity first — is it a block, does it state a possible period —
    /// then capability, then the enable, so a window that decodes nothing is
    /// refused before anything is written into it.
    ///
    /// A refusal leaves the block wherever the failing step left it. There is
    /// no state to unwind to: what preceded the call is whatever the firmware
    /// left, and it is no better.
    pub fn probe(mut mmio: M) -> Result<Self, HpetError> {
        let capabilities = mmio.read_u64(Register::Capabilities);
        if capabilities & REV_ID_MASK == 0 {
            return Err(HpetError::NotPresent { capabilities });
        }

        let femtoseconds = (capabilities >> COUNTER_CLK_PERIOD_SHIFT) as u32;
        let Some(period) = ClockPeriod::new(femtoseconds) else {
            return Err(HpetError::ImplausibleClockPeriod { femtoseconds });
        };

        if capabilities & COUNT_SIZE_CAP == 0 {
            return Err(HpetError::CounterTooNarrow { capabilities });
        }

        // Read-modify-write, not a bare store: every other bit of this register
        // selects behaviour of the comparators, which this crate never programs
        // and so has no basis to change. Whatever the firmware set is preserved
        // rather than reinterpreted.
        let configuration = mmio.read_u64(Register::Configuration);
        mmio.write_u64(Register::Configuration, configuration | ENABLE_CNF);
        let read_back = mmio.read_u64(Register::Configuration);
        if read_back & ENABLE_CNF == 0 {
            return Err(HpetError::NotEnabled { read_back });
        }

        Ok(Self { mmio, period })
    }

    /// The tick period the block reported, in femtoseconds.
    #[must_use]
    pub const fn period_femtoseconds(&self) -> u32 {
        self.period.femtoseconds
    }

    /// The counter's frequency: `10^15 / period_femtoseconds`, truncated.
    ///
    /// Bounded by [`MIN_FREQUENCY_HZ`] and [`MAX_FREQUENCY_HZ`] because the
    /// period it was derived from was ranged before this value existed.
    #[must_use]
    pub const fn frequency_hz(&self) -> NonZeroU64 {
        self.period.frequency_hz
    }

    /// One reading of the main counter.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.mmio.read_u64(Register::MainCounter)
    }

    /// Wait until the main counter has advanced by at least `ticks`, and report
    /// the first and last readings taken.
    ///
    /// On success `end.wrapping_sub(start) >= ticks`. The difference is wrapping
    /// throughout, which is the whole of the handling a 64-bit counter's
    /// rollover needs: a counter that crosses the top of `u64` mid-wait yields
    /// the true delta, and nothing here compares two readings for order.
    ///
    /// The converse costs something, and it is the honest price of a reference
    /// oscillator having nothing to be checked against. A counter that moves
    /// *backwards* — a different reading of a 32-bit part, a restored virtual
    /// machine — produces a wrapping difference near `u64::MAX`, which satisfies
    /// any `ticks` at once, and no timer on the part could tell the two apart.
    /// **The implausibility is judged downstream:** the pair reaches
    /// `lfw_clock::calibrate` as its `reference_elapsed`, where a difference
    /// that large derives a frequency below `lfw_clock::MIN_PLAUSIBLE_TSC_HZ`
    /// and is refused as `CalibrationError::ImplausiblySlow`; the refusal is
    /// exercised from this crate's readings by
    /// `a_counter_that_moved_backwards_is_refused_by_the_calibration_it_feeds`.
    ///
    /// Bounded by [`WAIT_READS_MAX`] reads whatever the device answers. A wait
    /// for no ticks is satisfied by the first reading alone and takes exactly
    /// one.
    pub fn wait_ticks(&self, ticks: u64) -> Result<(u64, u64), HpetError> {
        let start = self.counter();
        if ticks == 0 {
            return Ok((start, start));
        }

        let mut end = start;
        // The greatest advance any reading has shown, not the last one's: a
        // block whose counter oscillates would otherwise show progress on every
        // second read forever, and a high-water mark cannot be walked back.
        let mut observed = 0;
        for _ in 0..COUNTER_POLL_LIMIT {
            end = self.counter();
            let elapsed = end.wrapping_sub(start);
            if elapsed > observed {
                observed = elapsed;
            }
            if observed >= ticks {
                return Ok((start, end));
            }
        }

        if observed == 0 {
            return Err(HpetError::CounterStalled {
                polls: COUNTER_POLL_LIMIT,
                counter: end,
            });
        }
        Err(HpetError::CounterTooSlow {
            polls: COUNTER_POLL_LIMIT,
            observed,
            wanted: ticks,
        })
    }

    /// Ticks of this counter in `duration`, for a caller choosing a calibration
    /// window.
    ///
    /// Computed as `nanoseconds * 10^6 / period_femtoseconds` rather than
    /// against [`frequency_hz`](Self::frequency_hz): the period is what the
    /// block reported and the frequency is already a truncation of it, so
    /// dividing by the period keeps the one rounding instead of compounding
    /// two. The numerator leaves `u64` at a span of about five hours, so it is
    /// formed in `u128` and narrowed once, after the division — the same
    /// widening `lfw_clock` applies to its tick conversion and for the same
    /// reason.
    ///
    /// A span shorter than one tick is zero ticks, not an error: a wait for none
    /// is well defined, and it is the caller's window that is too short to
    /// measure anything, which the returned zero says.
    pub fn ticks_for(&self, duration: Duration) -> Result<u64, HpetError> {
        let nanoseconds = duration.as_nanos();
        let span_femtoseconds = nanoseconds as u128 * FEMTOSECONDS_PER_NANOSECOND as u128;
        let ticks = span_femtoseconds / u128::from(self.period.femtoseconds);
        if ticks > u64::MAX as u128 {
            return Err(HpetError::DurationTooLong { nanoseconds });
        }
        Ok(ticks as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_device::{CRYSTAL_PERIOD_FEMTOSECONDS, FakeHpet, Log, Op, capabilities_word};
    use lfw_clock::{CalibrationError, MIN_PLAUSIBLE_TSC_HZ, calibrate};
    use proptest::prelude::*;
    use std::vec;
    use std::vec::Vec;

    /// Probe against a fake, returning the shared log and the outcome. The
    /// probed block is dropped: tests that read a counter take [`running`].
    fn probe(device: FakeHpet) -> (Log, Result<(), HpetError>) {
        let log = device.log();
        let outcome = Hpet::probe(device).map(|_| ());
        (log, outcome)
    }

    /// Probe a fake that accepts the sequence and run `body` against the block,
    /// with the log cleared of the probe's own operations first.
    fn running(device: FakeHpet, body: impl FnOnce(&Hpet<FakeHpet>)) -> Log {
        let log = device.log();
        let hpet = Hpet::probe(device).expect("the fake accepts the sequence");
        log.take();
        body(&hpet);
        log
    }

    /// Every operation a conforming block sees during a probe, in order.
    fn conforming_probe_sequence(capabilities: u64) -> Vec<Op> {
        vec![
            Op::Read {
                register: Register::Capabilities,
                value: capabilities,
            },
            Op::Read {
                register: Register::Configuration,
                value: 0,
            },
            Op::Write {
                register: Register::Configuration,
                value: ENABLE_CNF,
            },
            Op::Read {
                register: Register::Configuration,
                value: ENABLE_CNF,
            },
        ]
    }

    #[test]
    fn every_register_sits_at_the_offset_the_specification_puts_it_at() {
        // The claim a protection domain's pointer arithmetic rests on: every
        // offset this crate can form is aligned and wholly inside the granted
        // block. Asserted rather than argued, because an offset that leaves the
        // block reads a register the driver did not ask for — or memory that is
        // not the device at all.
        for register in Register::ALL {
            let offset = register.offset();
            assert!(
                offset.is_multiple_of(size_of::<u64>()),
                "{register:?} is misaligned"
            );
            assert!(
                offset + size_of::<u64>() <= MMIO_LENGTH,
                "{register:?} leaves the block"
            );
        }
        assert_eq!(Register::Capabilities.offset(), 0x000);
        assert_eq!(Register::Configuration.offset(), 0x010);
        assert_eq!(Register::MainCounter.offset(), 0x0F0);
    }

    #[test]
    fn every_register_is_in_all() {
        // `Register::ALL` is what an `HpetMmio` implementation probes its
        // authority against, so a variant missing from it is a register this
        // crate would reach having proven nothing about it. The match is
        // exhaustive, so a new variant fails to compile until it is listed;
        // this then fails until it is listed *here*.
        for register in [
            Register::Capabilities,
            Register::Configuration,
            Register::MainCounter,
        ] {
            let listed = match register {
                Register::Capabilities | Register::Configuration | Register::MainCounter => {
                    Register::ALL.contains(&register)
                }
            };
            assert!(listed, "{register:?} is missing from Register::ALL");
        }
        assert_eq!(Register::ALL.len(), 3);
    }

    #[test]
    fn the_block_sits_inside_one_page_of_the_address_it_is_granted_at() {
        // What makes a single one-page `<memory_region>` the complete grant.
        // That the block fits inside that page is asserted at compile time
        // beside `Register::offset`; what is checked here is the two numbers
        // that assertion is taken over.
        assert_eq!(MMIO_BASE, 0xFED0_0000);
        assert_eq!(MMIO_LENGTH, 1024);
        assert!(MMIO_BASE.is_multiple_of(PAGE_SIZE));
        assert_eq!(MMIO_BASE % PAGE_SIZE + MMIO_LENGTH, MMIO_LENGTH);
    }

    #[test]
    fn a_conforming_block_is_probed_and_its_counter_started() {
        let capabilities = capabilities_word(1, true, CRYSTAL_PERIOD_FEMTOSECONDS);
        let (log, outcome) = probe(FakeHpet::conforming());
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            log.ops(),
            conforming_probe_sequence(capabilities),
            "capabilities, then the configuration read-modify-write and its readback"
        );
    }

    #[test]
    fn a_probe_reports_the_period_and_frequency_the_block_claimed() {
        let hpet = Hpet::probe(FakeHpet::conforming()).expect("the fake conforms");
        assert_eq!(hpet.period_femtoseconds(), CRYSTAL_PERIOD_FEMTOSECONDS);
        assert_eq!(
            hpet.frequency_hz().get(),
            FEMTOSECONDS_PER_SECOND / u64::from(CRYSTAL_PERIOD_FEMTOSECONDS)
        );
        // 14.31818 MHz, to the truncation the division leaves.
        assert_eq!(hpet.frequency_hz().get(), 14_318_179);
    }

    #[test]
    fn a_block_with_no_revision_is_refused_before_anything_is_written() {
        // The first check, and so where an unclaimed window — every read
        // answering all-ones or nothing at all — surfaces.
        for capabilities in [0, 0xFFFF_FFFF_FFFF_FF00, capabilities_word(0, true, 1)] {
            let (log, outcome) = probe(FakeHpet::conforming().with_capabilities(capabilities));
            assert_eq!(outcome, Err(HpetError::NotPresent { capabilities }));
            assert_eq!(
                log.ops(),
                vec![Op::Read {
                    register: Register::Capabilities,
                    value: capabilities,
                }],
                "nothing may be written to a window that does not answer as a block"
            );
        }
        // An all-ones window does report a revision, so it is refused later —
        // which is why the whole word travels in the error.
        let (_, outcome) = probe(FakeHpet::conforming().with_capabilities(u64::MAX));
        assert_ne!(outcome, Ok(()));
    }

    #[test]
    fn a_block_answering_nothing_at_all_is_refused_as_absent() {
        // Every register answering zero — a window backed by memory that was
        // never a register file. It is refused on the first read, like the
        // all-ones window, and for the same reason.
        let (log, outcome) = probe(FakeHpet::conforming().answering(vec![]));
        assert_eq!(outcome, Err(HpetError::NotPresent { capabilities: 0 }));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn a_period_outside_the_specifications_band_is_refused_with_what_was_claimed() {
        for femtoseconds in [0, MAX_CLOCK_PERIOD_FEMTOSECONDS + 1, u32::MAX, 0x8000_0000] {
            let (log, outcome) = probe(FakeHpet::conforming().with_period(femtoseconds));
            assert_eq!(
                outcome,
                Err(HpetError::ImplausibleClockPeriod { femtoseconds })
            );
            assert_eq!(log.len(), 1, "the configuration register is untouched");
        }
    }

    #[test]
    fn the_period_band_is_inclusive_at_both_ends() {
        for (femtoseconds, frequency) in [
            (1, MAX_FREQUENCY_HZ),
            (MAX_CLOCK_PERIOD_FEMTOSECONDS, MIN_FREQUENCY_HZ),
        ] {
            let hpet = Hpet::probe(FakeHpet::conforming().with_period(femtoseconds))
                .expect("a period inside the band is accepted");
            assert_eq!(hpet.period_femtoseconds(), femtoseconds);
            assert_eq!(hpet.frequency_hz().get(), frequency);
        }
        assert_eq!(MIN_FREQUENCY_HZ, 10_000_000);
        assert_eq!(MAX_FREQUENCY_HZ, 1_000_000_000_000_000);
    }

    #[test]
    fn a_thirty_two_bit_counter_is_refused() {
        // The wrapping difference `wait_ticks` measures is defined over the
        // whole of `u64`, so a counter that rolls at 2^32 would read as an
        // advance of nearly 2^64 every few minutes.
        let capabilities = capabilities_word(1, false, CRYSTAL_PERIOD_FEMTOSECONDS);
        let (log, outcome) = probe(FakeHpet::conforming().without_64_bit_counter());
        assert_eq!(outcome, Err(HpetError::CounterTooNarrow { capabilities }));
        assert_eq!(log.len(), 1, "the configuration register is untouched");
    }

    #[test]
    fn a_configuration_register_that_will_not_start_the_counter_is_refused_last() {
        // Every earlier step agrees; only the enable does not. Unrefused, every
        // reading of the counter would be the same number and a calibration
        // would divide by a delta of zero.
        let (log, outcome) = probe(FakeHpet::conforming().refusing_enable());
        assert_eq!(outcome, Err(HpetError::NotEnabled { read_back: 0 }));
        assert_eq!(log.len(), 4, "the whole sequence ran and then stopped");
        assert!(
            !log.ops().iter().any(|op| match op {
                Op::Read { register, .. } | Op::Write { register, .. } =>
                    *register == Register::MainCounter,
            }),
            "a counter that was never started is never read"
        );
    }

    #[test]
    fn the_configuration_bits_the_firmware_set_are_preserved_rather_than_reinterpreted() {
        // Read-modify-write: the comparator-routing bits this crate never
        // programs stay as they were found.
        let firmware = 0xDEAD_BEEF_0000_0002;
        let (log, outcome) = probe(FakeHpet::conforming().with_configuration(firmware));
        assert_eq!(outcome, Ok(()));
        assert!(
            log.ops().contains(&Op::Write {
                register: Register::Configuration,
                value: firmware | ENABLE_CNF,
            }),
            "the enable is set without clearing anything else"
        );
    }

    #[test]
    fn each_way_a_block_can_be_unusable_reaches_an_operator_as_its_own_error() {
        // Six ways for a block or its counter to be unusable must not
        // collapse into one console line. Each is driven to its own variant,
        // and no two are equal.
        let refusals = [
            probe(FakeHpet::conforming().with_capabilities(0)).1.err(),
            probe(FakeHpet::conforming().with_period(0)).1.err(),
            probe(FakeHpet::conforming().without_64_bit_counter())
                .1
                .err(),
            probe(FakeHpet::conforming().refusing_enable()).1.err(),
            Hpet::probe(FakeHpet::conforming().with_stuck_counter())
                .expect("the fake conforms")
                .wait_ticks(1)
                .err(),
            // Against the fastest period the band admits, where a span of
            // `u64::MAX` nanoseconds names more ticks than `u64` counts.
            Hpet::probe(FakeHpet::conforming().with_period(1))
                .expect("the fake conforms")
                .ticks_for(Duration::from_nanos(u64::MAX))
                .err(),
        ];
        for (index, outcome) in refusals.iter().enumerate() {
            assert!(outcome.is_some(), "refusal {index} must be an error");
            for other in refusals.iter().skip(index + 1) {
                assert_ne!(outcome, other);
            }
        }
    }

    #[test]
    fn the_counter_is_read_from_the_main_counter_register_and_answered_unchanged() {
        let log = running(FakeHpet::conforming().counting_from(0x1234_5678), |hpet| {
            assert_eq!(hpet.counter(), 0x1234_5678);
        });
        assert_eq!(
            log.ops(),
            vec![Op::Read {
                register: Register::MainCounter,
                value: 0x1234_5678,
            }]
        );
    }

    #[test]
    fn a_wait_for_no_ticks_takes_one_reading_and_returns_it_twice() {
        let log = running(FakeHpet::conforming().counting_from(7), |hpet| {
            assert_eq!(hpet.wait_ticks(0), Ok((7, 7)));
        });
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn a_wait_returns_the_pair_it_observed_and_stops_at_the_first_reading_that_suffices() {
        // One tick per read, so the target is met on the read that reaches it
        // and not a read later.
        let log = running(FakeHpet::conforming().counting_from(100), |hpet| {
            assert_eq!(hpet.wait_ticks(5), Ok((100, 105)));
        });
        // The start reading, then five more.
        assert_eq!(log.len(), 6);
        assert!(log.len() as u32 <= WAIT_READS_MAX);
    }

    #[test]
    fn a_wait_is_satisfied_by_an_advance_larger_than_it_asked_for() {
        let log = running(
            FakeHpet::conforming()
                .counting_from(0)
                .ticking_per_read(1_000),
            |hpet| assert_eq!(hpet.wait_ticks(5), Ok((0, 1_000))),
        );
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn a_counter_crossing_the_top_of_u64_is_measured_by_the_wrapping_difference() {
        // The rollover a 64-bit counter reaches after forty thousand years at
        // the crystal's rate, and after minutes on a fake. The delta is true
        // across it; a subtraction that saturated would report none.
        let start = u64::MAX - 2;
        let log = running(FakeHpet::conforming().counting_from(start), |hpet| {
            let (observed_start, end) = hpet.wait_ticks(5).expect("the counter advances");
            assert_eq!(observed_start, start);
            assert_eq!(end, 2, "the counter wrapped through zero");
            assert_eq!(end.wrapping_sub(observed_start), 5);
        });
        assert_eq!(log.len(), 6);
    }

    #[test]
    fn a_stalled_counter_costs_a_bounded_number_of_reads_and_the_calibration() {
        // The device this crate exists to survive: it answers every read,
        // forever, with the same number. The wait must return, name the fault,
        // and never spin.
        let log = running(
            FakeHpet::conforming()
                .counting_from(42)
                .with_stuck_counter(),
            |hpet| {
                assert_eq!(
                    hpet.wait_ticks(1),
                    Err(HpetError::CounterStalled {
                        polls: COUNTER_POLL_LIMIT,
                        counter: 42,
                    })
                );
            },
        );
        assert_eq!(log.len() as u32, WAIT_READS_MAX);
    }

    #[test]
    fn a_counter_too_slow_for_the_window_is_refused_apart_from_a_stalled_one() {
        // Alive, and moving; the window is what is wrong. Two causes, two
        // errors, and `observed` against `wanted` says by how much.
        let wanted = u64::from(COUNTER_POLL_LIMIT) + 10;
        let log = running(FakeHpet::conforming().counting_from(0), |hpet| {
            assert_eq!(
                hpet.wait_ticks(wanted),
                Err(HpetError::CounterTooSlow {
                    polls: COUNTER_POLL_LIMIT,
                    observed: u64::from(COUNTER_POLL_LIMIT),
                    wanted,
                })
            );
        });
        assert_eq!(log.len() as u32, WAIT_READS_MAX);
    }

    #[test]
    fn the_largest_wait_a_caller_can_name_still_terminates_within_the_bound() {
        let log = running(FakeHpet::conforming(), |hpet| {
            assert_eq!(
                hpet.wait_ticks(u64::MAX),
                Err(HpetError::CounterTooSlow {
                    polls: COUNTER_POLL_LIMIT,
                    observed: u64::from(COUNTER_POLL_LIMIT),
                    wanted: u64::MAX,
                })
            );
        });
        assert_eq!(log.len() as u32, WAIT_READS_MAX);
    }

    #[test]
    fn a_counter_that_oscillates_never_forges_progress() {
        // A hostile block whose readings alternate: every second read differs
        // from the last, so a driver comparing consecutive readings would see
        // progress forever. The high-water mark cannot be walked back, so the
        // advance stays at one and the wait is refused.
        let log = running(
            FakeHpet::conforming().answering_counter(vec![0, 1]),
            |hpet| {
                assert_eq!(
                    hpet.wait_ticks(100),
                    Err(HpetError::CounterTooSlow {
                        polls: COUNTER_POLL_LIMIT,
                        observed: 1,
                        wanted: 100,
                    })
                );
            },
        );
        assert_eq!(log.len() as u32, WAIT_READS_MAX);
    }

    #[test]
    fn a_counter_that_moved_backwards_is_refused_by_the_calibration_it_feeds() {
        // The delegation `wait_ticks` names. A backwards reading is a
        // wrapping difference near `u64::MAX`, which satisfies any wait at
        // once — and no timer on the part could contradict it. The refusal is
        // `lfw_clock::calibrate`'s: a reference interval that large derives a
        // frequency below the plausible floor.
        let hpet = Hpet::probe(FakeHpet::conforming().answering_counter(vec![10, 5]))
            .expect("the fake conforms");
        let (start, end) = hpet
            .wait_ticks(1)
            .expect("a wrapping difference satisfies it");
        assert_eq!((start, end), (10, 5));
        let reference_elapsed = end.wrapping_sub(start);
        assert_eq!(reference_elapsed, u64::MAX - 4);

        let derived = calibrate(3_000_000_000, reference_elapsed, hpet.frequency_hz());
        assert!(
            matches!(derived, Err(CalibrationError::ImplausiblySlow { hz }) if hz < MIN_PLAUSIBLE_TSC_HZ),
            "a backwards reference interval must not yield a frequency: {derived:?}"
        );
    }

    #[test]
    fn a_window_becomes_the_tick_count_the_period_divides_it_into() {
        let hpet = Hpet::probe(FakeHpet::conforming()).expect("the fake conforms");
        // One millisecond of the 14.31818 MHz crystal.
        assert_eq!(
            hpet.ticks_for(Duration::from_millis(1)),
            Ok(1_000_000 * FEMTOSECONDS_PER_NANOSECOND / u64::from(CRYSTAL_PERIOD_FEMTOSECONDS))
        );
        assert_eq!(hpet.ticks_for(Duration::from_millis(1)), Ok(14_318));
        assert_eq!(hpet.ticks_for(Duration::from_nanos(0)), Ok(0));
    }

    #[test]
    fn a_window_shorter_than_one_tick_is_no_ticks_rather_than_an_error() {
        // The caller's window is too short to measure anything, and the zero
        // says so; `wait_ticks(0)` is well defined.
        let hpet = Hpet::probe(FakeHpet::conforming()).expect("the fake conforms");
        assert_eq!(hpet.ticks_for(Duration::from_nanos(69)), Ok(0));
        assert_eq!(hpet.ticks_for(Duration::from_nanos(70)), Ok(1));
    }

    #[test]
    fn a_window_naming_more_ticks_than_u64_counts_is_refused_rather_than_truncated() {
        // Reachable only against the fastest period the band admits: at one
        // femtosecond per tick, five hours overflow the count.
        let hpet = Hpet::probe(FakeHpet::conforming().with_period(1)).expect("the fake conforms");
        let nanoseconds = u64::MAX;
        assert_eq!(
            hpet.ticks_for(Duration::from_nanos(nanoseconds)),
            Err(HpetError::DurationTooLong { nanoseconds })
        );
        // The boundary: the largest span that still counts, and the first that
        // does not.
        let last = u64::MAX / FEMTOSECONDS_PER_NANOSECOND;
        assert_eq!(
            hpet.ticks_for(Duration::from_nanos(last)),
            Ok(last * FEMTOSECONDS_PER_NANOSECOND)
        );
        assert_eq!(
            hpet.ticks_for(Duration::from_nanos(last + 1)),
            Err(HpetError::DurationTooLong {
                nanoseconds: last + 1
            })
        );
    }

    #[test]
    fn the_serviceable_wait_is_the_poll_bound_expressed_as_a_span() {
        // The constant a caller sizes a window against, and the identity it
        // encodes: the bound is a count of reads, and this is what that count
        // buys on the least favourable block the band admits.
        assert_eq!(WAIT_READS_MAX, COUNTER_POLL_LIMIT + 1);
        assert_eq!(
            WORST_CASE_SERVICEABLE_WAIT.as_nanos(),
            u64::from(COUNTER_POLL_LIMIT) * NANOS_PER_SECOND / MIN_FREQUENCY_HZ
        );
        assert_eq!(
            WORST_CASE_SERVICEABLE_WAIT.as_nanos(),
            Duration::from_millis(100).as_nanos()
        );
        // And it is a window this crate can actually turn into ticks and wait
        // for on such a block.
        let hpet = Hpet::probe(FakeHpet::conforming().with_period(MAX_CLOCK_PERIOD_FEMTOSECONDS))
            .expect("the fake conforms");
        assert_eq!(
            hpet.ticks_for(WORST_CASE_SERVICEABLE_WAIT),
            Ok(u64::from(COUNTER_POLL_LIMIT))
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The refusal property: whatever the capabilities register answers —
        /// over the whole of `u64` — a probe returns, and a probe that succeeds
        /// has established every fact the rest of the crate rests on.
        #[test]
        fn a_probe_decides_every_capabilities_word_without_panicking(
            capabilities in any::<u64>(),
        ) {
            let device = FakeHpet::conforming().with_capabilities(capabilities);
            match Hpet::probe(device) {
                Ok(hpet) => {
                    prop_assert_ne!(capabilities & REV_ID_MASK, 0);
                    prop_assert_ne!(capabilities & COUNT_SIZE_CAP, 0);
                    let femtoseconds = hpet.period_femtoseconds();
                    prop_assert_eq!(
                        u64::from(femtoseconds),
                        (capabilities >> COUNTER_CLK_PERIOD_SHIFT) & u64::from(u32::MAX)
                    );
                    prop_assert!(femtoseconds >= 1);
                    prop_assert!(femtoseconds <= MAX_CLOCK_PERIOD_FEMTOSECONDS);
                    // The frequency is the exact quotient of what was claimed,
                    // and lands in the band the band of periods implies.
                    let hz = hpet.frequency_hz().get();
                    prop_assert_eq!(hz, FEMTOSECONDS_PER_SECOND / u64::from(femtoseconds));
                    prop_assert!(hz >= MIN_FREQUENCY_HZ);
                    prop_assert!(hz <= MAX_FREQUENCY_HZ);
                }
                Err(error) => {
                    // The three identity refusals, and only those: the fake
                    // accepts the enable, so no other cause is available.
                    let identity = matches!(
                        error,
                        HpetError::NotPresent { .. }
                            | HpetError::ImplausibleClockPeriod { .. }
                            | HpetError::CounterTooNarrow { .. }
                    );
                    prop_assert!(identity, "unexpected refusal: {:?}", error);
                }
            }
        }

        /// The same over a block that answers an arbitrary cycled sequence to
        /// *every* register, including the configuration readback: the probe
        /// terminates within the four operations it can ever make.
        #[test]
        fn a_probe_terminates_within_its_operation_count_for_any_device_answers(
            answers in prop::collection::vec(any::<u64>(), 1..16),
        ) {
            let device = FakeHpet::conforming().answering(answers);
            let log = device.log();
            let _ = Hpet::probe(device);
            prop_assert!(log.len() <= 4);
        }

        /// The termination property, and the one that matters most: whatever a
        /// block answers to a counter read — differently on every read — a wait
        /// returns, and returns having made no more reads than the named bound
        /// admits. A device that could make it spin would hang this test rather
        /// than fail it, which is precisely the failure being excluded.
        #[test]
        fn a_wait_terminates_within_its_bound_for_any_counter_answers(
            answers in prop::collection::vec(any::<u64>(), 1..24),
            ticks in 0..64u64,
        ) {
            let device = FakeHpet::conforming().answering_counter(answers);
            let log = device.log();
            let hpet = Hpet::probe(device).expect("the fake accepts the sequence");
            log.take();
            let outcome = hpet.wait_ticks(ticks);
            prop_assert!(log.len() as u32 <= WAIT_READS_MAX);
            match outcome {
                // The whole of what a success claims, and it is claimed in
                // wrapping arithmetic because that is how it was measured.
                Ok((start, end)) => prop_assert!(end.wrapping_sub(start) >= ticks),
                // A wait can fail exactly two ways, and both spent the whole
                // budget. Matched into an `Option` so that a third way would
                // read as `None` rather than as a passing arm.
                Err(error) => {
                    let polls = match error {
                        HpetError::CounterStalled { polls, .. }
                        | HpetError::CounterTooSlow { polls, .. } => Some(polls),
                        _ => None,
                    };
                    prop_assert_eq!(polls, Some(COUNTER_POLL_LIMIT));
                }
            }
        }

        /// The counter's readings advance by exactly the stride a conforming
        /// block ticks at, in wrapping arithmetic, from any starting value —
        /// including one that carries the sequence across the top of `u64`.
        /// This is the monotonicity `wait_ticks`'s high-water mark rests on.
        #[test]
        fn counter_readings_are_monotonic_modulo_wraparound(
            base in any::<u64>(),
            stride in 1..1_000_000u64,
            reads in 1..16usize,
        ) {
            let hpet = Hpet::probe(FakeHpet::conforming().counting_from(base).ticking_per_read(stride))
                .expect("the fake accepts the sequence");
            let first = hpet.counter();
            prop_assert_eq!(first, base);
            let mut previous = first;
            for nth in 1..reads {
                let reading = hpet.counter();
                prop_assert_eq!(reading.wrapping_sub(previous), stride);
                // And the difference from the first reading only grows, which
                // is what a high-water mark is allowed to assume.
                prop_assert_eq!(reading.wrapping_sub(first), stride * nth as u64);
                previous = reading;
            }
        }

        /// A window is the exact number of whole ticks the claimed period
        /// divides it into, or a refusal — never a truncation into `u64`.
        #[test]
        fn a_window_is_the_exact_tick_count_or_a_refusal(
            femtoseconds in 1..=MAX_CLOCK_PERIOD_FEMTOSECONDS,
            nanoseconds in any::<u64>(),
        ) {
            let hpet = Hpet::probe(FakeHpet::conforming().with_period(femtoseconds))
                .expect("a period inside the band is accepted");
            let exact = u128::from(nanoseconds) * u128::from(FEMTOSECONDS_PER_NANOSECOND)
                / u128::from(femtoseconds);
            match hpet.ticks_for(Duration::from_nanos(nanoseconds)) {
                Ok(ticks) => prop_assert_eq!(u128::from(ticks), exact),
                // The one way it can fail, named as an equality so that any
                // other refusal fails the comparison instead of matching a
                // catch-all arm.
                Err(error) => {
                    prop_assert_eq!(error, HpetError::DurationTooLong { nanoseconds });
                    prop_assert!(exact > u128::from(u64::MAX));
                }
            }
        }

        /// The one register this crate ever writes is the configuration
        /// register — on any path, for any device answers.
        ///
        /// [`HpetMmio`] takes a [`Register`], so *which* offsets can be reached
        /// is a question the type answers and no test can restate. What it does
        /// not answer is which of the three may be written: a write to the main
        /// counter would reset the very quantity being measured, and one to the
        /// read-only capabilities register would be meaningless. Both are
        /// expressible, so both are excluded here rather than by construction.
        #[test]
        fn no_path_writes_any_register_but_the_configuration(
            capabilities in any::<u64>(),
            answers in prop::collection::vec(any::<u64>(), 1..16),
            ticks in 0..8u64,
        ) {
            let device = FakeHpet::conforming()
                .with_capabilities(capabilities)
                .answering_counter(answers);
            let log = device.log();
            if let Ok(hpet) = Hpet::probe(device) {
                let _ = hpet.wait_ticks(ticks);
                let _ = hpet.counter();
            }
            for op in log.ops() {
                if let Op::Write { register, .. } = op {
                    prop_assert_eq!(register, Register::Configuration);
                }
            }
        }
    }
}
