#![no_main]
#![no_std]

//! Hardware-probe protection domain: it proves, on the booted image, that a
//! hardfloat SSE protection domain runs at all, that AES-NI and PCLMULQDQ
//! execute and answer correctly, and that XMM state survives the kernel's
//! context switches. Then it parks.
//!
//! This binary is the one protection domain compiled with the SIMD target
//! specification — hardfloat, SSE through SSE4.2, AES-NI, PCLMULQDQ, ADX and
//! BMI2 enabled at compile time — where every other domain is built softfloat
//! with the vector units disabled. The pinned kernel saves x87 and SSE state
//! per thread (XSAVE feature set 3), so the XMM tier should be usable; whether
//! it actually is, on this toolchain and this kernel, is what a boot of this
//! domain answers. The cryptography domain is designed on that answer.
//!
//! # What one run proves
//!
//! Three claims, each judged by the QEMU gate on the console record:
//!
//! 1. **The domain boots.** A hardfloat SSE binary that Microkit cannot load,
//!    or that faults on its first XMM instruction, never emits a record.
//! 2. **The instructions answer correctly.** One `AESENC` against the values
//!    of FIPS-197's Appendix B cipher example (the round-1 state and round key,
//!    compared against the round-2 state), and one `PCLMULQDQ` whose expected
//!    product follows from the carry-less schoolbook multiplication written at
//!    the constants. A wrong answer is a `refused` record naming which.
//! 3. **XMM state survives preemption.** A distinctive 128-bit value is held
//!    live across a bounded loop at the busy-loop domains' own priority, so
//!    round-robin timeslicing preempts the loop mid-flight; every pass
//!    re-checks the value and re-runs both known answers, and a preemption is
//!    observed as a timestamp-counter gap no in-loop pass produces. The ready
//!    record carries how many preemptions the value was checked across.
//!
//! What the loop deliberately does not pin: which register the live value sits
//! in from pass to pass is the compiler's choice, not a promise this code can
//! make — `core::hint::black_box` keeps the value and every comparison out of
//! constant folding, and the multi-domain torture test planned for the
//! cryptography milestone is where register residency gets forced explicitly.
//!
//! # Adversary
//!
//! The **byzantine neighbour protection domain**, in one place: the clock
//! calibration region this domain maps read-only to stamp its records, whose
//! triple is peer-written and ranged by `pd_runtime::PdClock` before a stamp is
//! derived from it. No device, no network byte and no frame reaches this
//! domain — its other mappings are its own log ring and statistics shard.
//! Every hyphen-bearing literal below is a refusal cause token; none carries a
//! peer-chosen byte, and none is an untrusted parser, so there is no fuzz
//! target for this binary.
//!
//! # Why the gates cannot be complete, and why they still stand
//!
//! `CPUID` reports each feature before the first instruction from that set
//! runs, so a part that lacks one refuses with the feature word instead of
//! taking an invalid-opcode fault — the same shape as the management domain's
//! `RDRAND` gate. The check is best effort by nature: the compiler is entitled
//! to emit any compile-time-enabled instruction anywhere in this binary,
//! including before the gate. On such a part the domain faults and the Microkit
//! monitor reports it, which is the honest outcome for hardware below the
//! product's compile-time baseline; the gate turns the *orderly* cases into a
//! diagnosis.
//!
//! # Priority 1, and bounded work there
//!
//! The system description puts this domain beside the busy-loop domains on
//! purpose: equal priority is what makes seL4's round-robin preempt the loop
//! mid-pass, which is the very event under test. The loop is bounded three
//! ways — enough observed preemptions, a timestamp-counter budget, and a pass
//! budget that binds even on a part whose counter never advances — so the
//! probe spends a fraction of a second of shared timeslice and then parks,
//! and cannot starve the domains it shares the priority with.

use core::arch::x86_64::{
    __cpuid, __cpuid_count, __m128i, _mm_aesenc_si128, _mm_clmulepi64_si128, _mm_cmpeq_epi8,
    _mm_cvtsi128_si64, _mm_extract_epi64, _mm_movemask_epi8, _mm_set_epi64x,
};
use core::hint::black_box;

use lfw_log::{Domain, DomainDetail, DomainState, Event, Refusal, RefusalDetail, RingSink, Sink};
use lfw_metrics::{HardwareProbeSample, StatsShard};
use pd_runtime::{PdClock, attach_region, log_sample, read_timestamp_counter};
use sel4_microkit::{ChannelSet, Handler, Infallible, protection_domain};
use wire::{ClockCalibration, LogConsume, LogRecords};

/// Preemptions the loop runs until it has observed, at which point the claim
/// is made: the live value was checked after this many context switches.
const TARGET_PREEMPTIONS: u64 = 4;

/// A timestamp-counter gap between two adjacent passes that no pass produces
/// on its own: a pass is tens of cycles, and this is tens of microseconds on
/// any plausible frequency, while a round-robin timeslice away is milliseconds.
const PREEMPTION_GAP_TICKS: u64 = 200_000;

/// Counter ticks the whole loop may spend before reporting what it saw —
/// under a second on any plausible frequency, so the record is on the console
/// well inside the shortest scenario that judges it.
const TICK_BUDGET: u64 = 1 << 30;

/// Passes the loop may run even if the counter never advances — the one
/// failure the tick budget cannot bound — so the loop terminates on a part
/// whose `RDTSC` is broken rather than spinning on a shared priority forever.
const PASS_BUDGET: u64 = 1 << 28;

/// `CPUID.0H:EAX` must reach this leaf for the structured-feature word the
/// BMI2 and ADX bits live in to exist.
const FEATURE_LEAF: u32 = 1;
const EXTENDED_FEATURE_LEAF: u32 = 7;

/// `CPUID.01H:EDX` bit for SSE2, and `CPUID.01H:ECX` bits for the rest of the
/// XMM tier this binary is compiled against.
const SSE2_EDX_BIT: u32 = 1 << 26;
const PCLMULQDQ_ECX_BIT: u32 = 1 << 1;
const SSSE3_ECX_BIT: u32 = 1 << 9;
const SSE41_ECX_BIT: u32 = 1 << 19;
const SSE42_ECX_BIT: u32 = 1 << 20;
const AES_ECX_BIT: u32 = 1 << 25;

/// `CPUID.07H.0H:EBX` bits for the two general-purpose-register extensions the
/// target also enables at compile time.
const BMI2_EBX_BIT: u32 = 1 << 8;
const ADX_EBX_BIT: u32 = 1 << 19;

/// FIPS-197 Appendix B cipher example, block byte order as two little-endian
/// lanes: the state entering round 1 (the plaintext after the initial round-key
/// addition), round key 1, and the state entering round 2 — so the expected
/// value is the standard's own worked figure, not this file's arithmetic.
const AES_STATE: (u64, u64) = (0x2be2_f4a0_bee3_3d19, 0x0848_f8e9_2a8d_c69a);
const AES_ROUND_KEY: (u64, u64) = (0xb12c_5488_17fe_faa0, 0x0576_6c2a_3939_a323);
const AES_EXPECTED: (u64, u64) = (0x2b35_9f68_f27f_9ca4, 0x4950_6a02_43ea_5b6b);

/// Carry-less multiplication of the two low lanes, with the expected product
/// derivable by hand: (2^63 + 0xb)(2^63 + 0xd) carry-lessly is
/// 2^126 xor 2^63·(0xb xor 0xd) xor (0xb clmul 0xd). The last factor is
/// 1011 · 1101 = 1011000 xor 101100 xor 1011 = 1111111 = 0x7f; 2^126 is bit 62
/// of the high lane and 2^63·0x6 is bits 0 and 1 of it — so the high lane is
/// 0x4000000000000003 and the low lane 0x7f.
const CLMUL_A: u64 = 0x8000_0000_0000_000b;
const CLMUL_B: u64 = 0x8000_0000_0000_000d;
const CLMUL_EXPECTED: (u64, u64) = (0x7f, 0x4000_0000_0000_0003);

/// The value held live in XMM across the loop: no lane is zero, no byte
/// repeats its neighbour, and neither half is the other — so a register lane
/// zeroed, swapped or duplicated by a broken save/restore cannot compare equal.
const PATTERN: (u64, u64) = (0xa5c3_5a3c_9669_e11e, 0x1ee1_6996_3c5a_c3a5);

/// This domain's lifecycle record.
fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::HardwareProbe,
        state,
        detail,
    });
}

/// A refusal this domain raises. `signalled` is `false` on every one: there is
/// no device here to be told anything.
const fn refusal(cause: &'static str, detail: RefusalDetail) -> Refusal {
    Refusal {
        cause,
        detail,
        signalled: false,
    }
}

/// Why this node could not prove the hardware profile. Each carries the console
/// record it becomes, because the mapping is one site per cause and a second
/// table here would be a copy to keep in step.
struct ProbeError(Refusal);

/// What one run of the probe observed, whatever the verdict: the counts go to
/// the shard on both paths, so a refused run still reports how far it got.
struct Observation {
    verdict: Result<(), ProbeError>,
    passes: u64,
    preemptions: u64,
}

#[protection_domain]
fn init() -> HardwareProbe {
    // Before anything that could have something to say. The region is zeroed by
    // the kernel, so it is a valid empty ring the moment it is mapped, and the
    // console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let calibration: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(calibration));
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);

    announce(&sink, DomainState::Starting, DomainDetail::None);
    let observed = match feature_gate() {
        // SAFETY: `probe` requires the sse2, sse4.1, aes and pclmulqdq target
        // features to be available on the part it executes on, and the
        // guarantor of that is `feature_gate` on this match's scrutinee — the
        // only path to this arm, which returns the matching `*-not-supported`
        // refusal before reaching it when any of those CPUID bits is clear.
        // The kernel is the guarantor of the same unprivileged-execution fact
        // `read_timestamp_counter` records for `RDTSC`; being wrong about
        // either is a fault the Microkit monitor reports in this domain, not
        // a silently wrong number.
        Ok(()) => unsafe { probe() },
        // A missing feature refuses before the loop runs a pass, so both
        // counts are honestly zero.
        Err(error) => Observation {
            verdict: Err(error),
            passes: 0,
            preemptions: 0,
        },
    };
    match &observed.verdict {
        Ok(()) => announce(
            &sink,
            DomainState::Ready,
            DomainDetail::Proven {
                preemptions: observed.preemptions,
                iterations: observed.passes,
            },
        ),
        Err(ProbeError(refusal)) => {
            // The whole reason, not a summary: with no shell and no CLI on the
            // appliance, this record is all an operator gets.
            announce(&sink, DomainState::Refused, DomainDetail::Refusal(*refusal));
        }
    }
    // Last, and once: this domain runs to completion and parks with no channel
    // to wake it, so its shard is written here and never moves again.
    stats.publish(
        &HardwareProbeSample {
            proven: observed.verdict.is_ok(),
            iterations: observed.passes,
            preemptions: observed.preemptions,
            log: log_sample(sink.dropped(), sink.refused()),
        }
        .values(),
    );
    HardwareProbe
}

/// Refuse, with the feature word an operator compares against the part's
/// documentation, on any part below the compile-time baseline. Best effort on
/// the terms in the crate header: it runs before the first probe instruction,
/// not before the first instruction the compiler chose.
fn feature_gate() -> Result<(), ProbeError> {
    // `__cpuid` is a safe call on this toolchain, which is the compiler's
    // statement that the instruction has no precondition a caller could
    // violate: it is architectural on x86_64 and unprivileged, and both
    // specifications under `support/targets` target x86_64 and nothing else.
    // The one fact left is third-party runtime behaviour and is recorded
    // rather than asserted: the seL4 kernel does not trap `CPUID` in a
    // protection domain, the same premise `read_timestamp_counter` records for
    // `RDTSC`. Leaf 1 exists on every part that implements `CPUID` at all;
    // leaf 7 does not, which is what the max-leaf check below is for.
    let leaf1 = __cpuid(FEATURE_LEAF);
    for (bit, cause) in [
        (SSSE3_ECX_BIT, "ssse3-not-supported"),
        (SSE41_ECX_BIT, "sse41-not-supported"),
        (SSE42_ECX_BIT, "sse42-not-supported"),
        (AES_ECX_BIT, "aes-not-supported"),
        (PCLMULQDQ_ECX_BIT, "pclmulqdq-not-supported"),
    ] {
        if leaf1.ecx & bit == 0 {
            return Err(ProbeError(refusal(
                cause,
                RefusalDetail::One(u64::from(leaf1.ecx)),
            )));
        }
    }
    if leaf1.edx & SSE2_EDX_BIT == 0 {
        return Err(ProbeError(refusal(
            "sse2-not-supported",
            RefusalDetail::One(u64::from(leaf1.edx)),
        )));
    }
    let max_leaf = __cpuid(0).eax;
    if max_leaf < EXTENDED_FEATURE_LEAF {
        return Err(ProbeError(refusal(
            "cpuid-leaf-seven-unavailable",
            RefusalDetail::One(u64::from(max_leaf)),
        )));
    }
    let leaf7 = __cpuid_count(EXTENDED_FEATURE_LEAF, 0);
    for (bit, cause) in [
        (BMI2_EBX_BIT, "bmi2-not-supported"),
        (ADX_EBX_BIT, "adx-not-supported"),
    ] {
        if leaf7.ebx & bit == 0 {
            return Err(ProbeError(refusal(
                cause,
                RefusalDetail::One(u64::from(leaf7.ebx)),
            )));
        }
    }
    Ok(())
}

/// The probe loop: both known answers and the live pattern, re-checked every
/// pass, across at least [`TARGET_PREEMPTIONS`] observed preemptions or until
/// a budget expires.
///
/// # Safety
/// The caller must have established that the part executing this supports the
/// four target features named in the attribute; `feature_gate` is the enforcer,
/// and `init` calls this only on its accepting path. On a part without them,
/// an instruction below is an invalid-opcode fault.
#[target_feature(enable = "sse2,sse4.1,aes,pclmulqdq")]
fn probe() -> Observation {
    // Held live across the whole loop — this is the value whose survival is
    // under test. `black_box` keeps it a runtime value the optimizer cannot
    // fold, and the fresh `black_box` load inside every pass keeps each
    // comparison a pass actually executes rather than one hoisted out.
    let live = black_box(lanes_to_m128(PATTERN));

    let start = read_timestamp_counter().0;
    let mut last = start;
    let mut passes: u64 = 0;
    let mut preemptions: u64 = 0;
    loop {
        passes = passes.saturating_add(1);

        let aes = _mm_aesenc_si128(
            black_box(lanes_to_m128(AES_STATE)),
            black_box(lanes_to_m128(AES_ROUND_KEY)),
        );
        if let Err(error) = expect(aes, AES_EXPECTED, "aes-known-answer-mismatch") {
            return refused(error, passes, preemptions);
        }
        let product = _mm_clmulepi64_si128::<0>(
            black_box(_mm_set_epi64x(0, CLMUL_A.cast_signed())),
            black_box(_mm_set_epi64x(0, CLMUL_B.cast_signed())),
        );
        if let Err(error) = expect(product, CLMUL_EXPECTED, "pclmul-known-answer-mismatch") {
            return refused(error, passes, preemptions);
        }
        // The expected side is re-drawn through `black_box` on every pass:
        // both operands of a loop-invariant comparison would let the
        // optimizer hoist the check out of the loop, and a pattern checked
        // once before the first preemption proves nothing about survival.
        if let Err(error) = expect(live, black_box(PATTERN), "xmm-pattern-corrupted") {
            return refused(error, passes, preemptions);
        }

        // Wrapping, on the terms every counter delta in this system is read:
        // the difference of two readings of a free-running counter is the
        // elapsed count whether or not it crossed the top of `u64`.
        let now = read_timestamp_counter().0;
        if now.wrapping_sub(last) >= PREEMPTION_GAP_TICKS {
            preemptions = preemptions.saturating_add(1);
        }
        last = now;
        if preemptions >= TARGET_PREEMPTIONS
            || now.wrapping_sub(start) >= TICK_BUDGET
            || passes >= PASS_BUDGET
        {
            return Observation {
                verdict: Ok(()),
                passes,
                preemptions,
            };
        }
    }
}

/// An [`Observation`] that refused mid-loop, carrying how far it got.
const fn refused(error: ProbeError, passes: u64, preemptions: u64) -> Observation {
    Observation {
        verdict: Err(error),
        passes,
        preemptions,
    }
}

/// The two lanes as the 128-bit value they spell, low lane first.
#[target_feature(enable = "sse2")]
fn lanes_to_m128(lanes: (u64, u64)) -> __m128i {
    _mm_set_epi64x(lanes.1.cast_signed(), lanes.0.cast_signed())
}

/// `value` equals the expected lanes, or the refusal carrying what was read
/// instead — the observed lanes, low then high, which is what turns a
/// mismatch on a booted node into a diagnosis.
#[target_feature(enable = "sse2,sse4.1")]
fn expect(value: __m128i, lanes: (u64, u64), cause: &'static str) -> Result<(), ProbeError> {
    let mask = _mm_movemask_epi8(_mm_cmpeq_epi8(value, lanes_to_m128(lanes)));
    if mask == 0xFFFF {
        return Ok(());
    }
    Err(ProbeError(refusal(
        cause,
        RefusalDetail::Two(
            _mm_cvtsi128_si64(value).cast_unsigned(),
            _mm_extract_epi64::<1>(value).cast_unsigned(),
        ),
    )))
}

/// Returned by `init` in every case: this domain runs once and then parks in
/// the Microkit event loop, whether it proved the profile or refused to.
struct HardwareProbe;

impl Handler for HardwareProbe {
    type Error = Infallible;

    /// Unreachable by capability: nothing in this system holds a notification
    /// capability on this domain, so the event loop it parks in has no sender.
    /// It exists because [`Handler`] requires it.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
