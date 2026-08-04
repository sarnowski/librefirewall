#![no_main]
#![no_std]

//! Cryptography protection domain: it proves, on the booted image, that every
//! primitive the appliance owns answers its published test vectors, measures
//! what each costs on this part, seeds the node's random bit generator from
//! hardware, and then parks.
//!
//! This is the second binary compiled with the SIMD target specification, and
//! the reason that specification exists: with AES-NI and carry-less multiply
//! enabled at compile time, the adopted cryptography crates' runtime backend
//! detection folds to a constant and only the accelerated code is emitted. The
//! portable fallback is not the slow path on this image — it is absent from
//! it.
//!
//! # What one boot proves, and why three claims and not one
//!
//! 1. **The part meets the baseline.** `CPUID` is read before the first
//!    instruction from any gated set runs, and a missing mandatory feature
//!    refuses the domain with the feature word an operator can compare against
//!    the part's documentation. A `ready` record is therefore itself the
//!    assertion that every mandatory feature was present.
//! 2. **Every primitive is correct here.** The same published vectors the host
//!    suite runs — NIST CAVP, RFC 8439 and Wycheproof — are re-run against the
//!    code as compiled for this target, on this hardware. A host test proves
//!    the source; only this proves the instructions the source became.
//! 3. **The accelerated backend is the one running.** Correctness cannot show
//!    that: a portable AES answers the same vectors. What shows it is cost, so
//!    every measured primitive reports thousandths of a cycle per byte, and
//!    the gate holds AES-256-GCM's below a figure no portable implementation
//!    reaches. This is the claim that would otherwise go quietly untrue.
//!
//! # Why the measurement takes the minimum of several rounds
//!
//! A round interrupted by the scheduler measures the interruption, not the
//! cipher. The minimum across rounds is the round that was not interrupted —
//! or the least interrupted one, which errs toward reporting the primitive as
//! *slower* than it is and so can only make the gate's floor harder to meet,
//! never easier.
//!
//! # Adversary
//!
//! The **byzantine neighbour protection domain**, in one place: the clock
//! calibration region this domain maps read-only to stamp its records, whose
//! triple is peer-written and ranged by `pd_runtime::PdClock` before a stamp
//! is derived from it. No device, no network byte and no frame reaches this
//! domain, and nothing it computes here comes from outside it — every input to
//! every primitive is a compile-time constant or a hardware draw.
//!
//! **No surface here carries key material.** The seed is drawn, folded and
//! consumed inside this file; the generator holds it, no record names it, and
//! the raw draws are cleared before the buffer holding them goes out of scope.
//! The only numbers that leave are counts and costs.

mod entropy;

use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::hint::black_box;

use lfw_crypto::{
    Aes256Gcm, ChaCha20Poly1305, Drbg, KEY_LEN, NONCE_LEN, Sha256, VectorFailure,
    prove_aes_256_gcm, prove_chacha20, prove_chacha20_poly1305, prove_drbg, prove_hkdf_sha256,
    prove_hmac_sha256, prove_sha256,
};
use lfw_log::{
    Domain, DomainDetail, DomainState, Event, Primitive, Refusal, RefusalDetail, RingSink, Sink,
};
use lfw_metrics::{CRYPTO_PRIMITIVES, CryptoSample, StatsShard};
use pd_runtime::{PdClock, attach_region, log_sample, read_timestamp_counter};
use sel4_microkit::{ChannelSet, Handler, Infallible, protection_domain};
use wire::{ClockCalibration, LogConsume, LogRecords};

use entropy::{ENTROPY_LEN, EntropyError, draw_seed_material};

/// Bytes one timing pass runs a primitive over. Four pages: past every cache
/// line and block boundary that could make a shorter buffer flatter than the
/// steady state, and small enough that a round is thousands of cycles rather
/// than millions on a part emulating every instruction.
const MEASURE_BYTES: usize = 4096;

/// Passes per timed round, and rounds per primitive. The product is what each
/// primitive processes; the minimum across rounds is what it reports.
const PASSES_PER_ROUND: u32 = 4;
const ROUNDS: u32 = 8;

/// `CPUID.0H:EAX` must reach this leaf for the structured-feature word BMI2
/// and ADX live in to exist.
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

/// One primitive's proof: the run that proves it and the token a disagreement
/// is refused with.
struct Proof {
    primitive: Primitive,
    prove: fn() -> Result<u32, VectorFailure>,
    cause: &'static str,
}

/// Every primitive this domain proves, the run that proves it, and the token a
/// disagreement is refused with.
///
/// One row per member of the console vocabulary, and the QEMU judge holds this
/// table to that vocabulary from the other side: a primitive added there with
/// no row here produces no record, and the gate fails for the record it did
/// not see rather than passing on the six it did.
const PROOFS: [Proof; 7] = [
    Proof {
        primitive: Primitive::Sha256,
        prove: prove_sha256,
        cause: "sha-256-vector-mismatch",
    },
    Proof {
        primitive: Primitive::HmacSha256,
        prove: prove_hmac_sha256,
        cause: "hmac-sha-256-vector-mismatch",
    },
    Proof {
        primitive: Primitive::HkdfSha256,
        prove: prove_hkdf_sha256,
        cause: "hkdf-sha-256-vector-mismatch",
    },
    Proof {
        primitive: Primitive::ChaCha20,
        prove: prove_chacha20,
        cause: "chacha20-vector-mismatch",
    },
    Proof {
        primitive: Primitive::ChaCha20Poly1305,
        prove: prove_chacha20_poly1305,
        cause: "chacha20-poly1305-vector-mismatch",
    },
    Proof {
        primitive: Primitive::Aes256Gcm,
        prove: prove_aes_256_gcm,
        cause: "aes-256-gcm-vector-mismatch",
    },
    Proof {
        primitive: Primitive::Drbg,
        prove: prove_drbg,
        cause: "chacha20-drbg-vector-mismatch",
    },
];

/// The primitives whose cost is measured, and nothing else: a hash, the
/// channel's AEAD, and the AEAD the hardware baseline exists for. The other
/// four are compositions of these or are drawn from in key-sized pieces, so a
/// throughput figure for them would measure this domain's loop rather than the
/// primitive.
const MEASURED: [Primitive; 3] = [
    Primitive::Sha256,
    Primitive::ChaCha20Poly1305,
    Primitive::Aes256Gcm,
];

/// The console's primitive vocabulary and the metrics shard's are two arrays
/// in two crates that neither may read from the other, and this domain indexes
/// the second one with a member of the first. Held equal here, where both are
/// visible, so that index is in bounds by construction rather than by a test
/// somewhere else.
const _: () = assert!(Primitive::ALL.len() == CRYPTO_PRIMITIVES.len());

/// This domain's lifecycle record.
fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::Crypto,
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

/// Why this node could not establish its cryptography.
struct CryptoError(Refusal);

/// What one bring-up established, whatever the verdict: the counts go to the
/// shard on both paths, so a refused run still reports how far it got.
struct Outcome {
    verdict: Result<(), CryptoError>,
    vectors: [u64; CRYPTO_PRIMITIVES.len()],
    milli_cycles_per_byte: [u64; CRYPTO_PRIMITIVES.len()],
}

#[protection_domain]
fn init() -> Crypto {
    // Before anything that could have something to say. The region is zeroed
    // by the kernel, so it is a valid empty ring the moment it is mapped, and
    // the console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let calibration: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(calibration));
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);

    announce(&sink, DomainState::Starting, DomainDetail::None);
    let outcome = bring_up(&sink);
    match &outcome.verdict {
        Ok(()) => announce(&sink, DomainState::Ready, DomainDetail::None),
        Err(CryptoError(cause)) => {
            // The whole reason, not a summary: with no shell and no CLI on the
            // appliance, this record is all an operator gets.
            announce(&sink, DomainState::Refused, DomainDetail::Refusal(*cause));
        }
    }
    // Last, and once: this domain runs to completion and parks with no channel
    // to wake it, so its shard is written here and never moves again.
    stats.publish(
        &CryptoSample {
            proven: outcome.verdict.is_ok(),
            vectors: outcome.vectors,
            milli_cycles_per_byte: outcome.milli_cycles_per_byte,
            log: log_sample(sink.dropped(), sink.refused()),
        }
        .values(),
    );
    Crypto
}

/// Gate on the part, prove every primitive, measure the three that are
/// measured, and seed the generator — reporting each step as it happens, so a
/// refusal halfway through leaves the steps that did hold on the console.
fn bring_up(sink: &dyn Sink) -> Outcome {
    let mut outcome = Outcome {
        verdict: Ok(()),
        vectors: [0; CRYPTO_PRIMITIVES.len()],
        milli_cycles_per_byte: [0; CRYPTO_PRIMITIVES.len()],
    };
    match feature_gate() {
        Ok(features) => announce(
            sink,
            DomainState::Negotiated,
            DomainDetail::Features(features),
        ),
        Err(error) => {
            outcome.verdict = Err(error);
            return outcome;
        }
    }

    for Proof {
        primitive,
        prove,
        cause,
    } in PROOFS
    {
        match prove() {
            Ok(vectors) => {
                outcome.vectors[primitive as usize] = u64::from(vectors);
                announce(
                    sink,
                    DomainState::Negotiated,
                    DomainDetail::Proved {
                        primitive,
                        vectors: u64::from(vectors),
                    },
                );
            }
            Err(VectorFailure { index, .. }) => {
                // The row's index and nothing from the row: a vector's bytes
                // are a published constant, but a refusal that echoed input
                // would be a habit to have on a path where the input is not.
                outcome.verdict = Err(CryptoError(refusal(
                    cause,
                    RefusalDetail::One(u64::from(index)),
                )));
                return outcome;
            }
        }
    }

    for primitive in MEASURED {
        let cost = measure(primitive);
        outcome.milli_cycles_per_byte[primitive as usize] = cost;
        announce(
            sink,
            DomainState::Negotiated,
            DomainDetail::Measured {
                primitive,
                milli_cycles_per_byte: cost,
            },
        );
    }

    if let Err(error) = seed_generator() {
        outcome.verdict = Err(error);
    }
    outcome
}

/// Draw hardware entropy, fold it into the node's generator, and prove the
/// generator answers.
///
/// The generator is built and dropped here because nothing yet consumes it:
/// the store domain generates keys from one in the phase that gives this
/// domain a channel, and a generator held open with no reader would be a
/// seeded secret sitting in memory for no purpose. What this proves now is
/// that the hardware can seed one and that the seeded one produces bytes.
fn seed_generator() -> Result<(), CryptoError> {
    let mut raw = [0_u8; ENTROPY_LEN];
    let drawn = draw_seed_material(&mut raw);
    let outcome = drawn.map_err(|error| {
        CryptoError(match error {
            EntropyError::NotSupported { feature_word } => refusal(
                "rdrand-not-supported",
                RefusalDetail::One(u64::from(feature_word)),
            ),
            EntropyError::Exhausted { word } => {
                refusal("rdrand-exhausted", RefusalDetail::One(word as u64))
            }
            EntropyError::Stuck { word } => {
                refusal("rdrand-output-stuck", RefusalDetail::One(word as u64))
            }
        })
    });
    let result = outcome.and_then(|()| {
        let mut generator = Drbg::from_entropy(&raw);
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        generator.fill(&mut first);
        generator.fill(&mut second);
        // Two draws that came out identical would mean the generator never
        // advanced, which no vector can catch because a vector fixes the seed
        // and reads one draw. Neither value leaves this frame.
        if first == second {
            return Err(CryptoError(refusal(
                "generator-repeated-a-draw",
                RefusalDetail::None,
            )));
        }
        Ok(())
    });
    // Whatever happened above, the draws do not outlive this frame in
    // readable form. Written through a volatile write so the compiler cannot
    // remove a store to a value nothing reads again.
    for byte in &mut raw {
        // SAFETY: `write_volatile` requires a valid, aligned, writable pointer
        // to a live value, and the guarantor is this function's own stack
        // frame: `raw` is a local array still in scope, and the pointer comes
        // from a mutable reference into it that the borrow checker proved
        // unique. `u8` has alignment one, so no alignment obligation remains.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    result
}

/// Refuse, with the feature words an operator compares against the part's
/// documentation, on any part below the compile-time baseline; on an accepting
/// part, the two words packed as one — leaf 1's `ECX` low, leaf 7's `EBX`
/// high — so the record says what was found and not merely that something was.
///
/// Best effort by nature, on the same terms as the hardware probe's gate: it
/// runs before the first *gated* instruction, not before the first instruction
/// the compiler chose. On a part below the baseline the domain faults and the
/// Microkit monitor reports it, which is the honest outcome for hardware below
/// the product's compile-time requirement; this turns the orderly cases into a
/// diagnosis.
fn feature_gate() -> Result<u64, CryptoError> {
    // `__cpuid` is a safe call on this toolchain, on the terms `entropy.rs`
    // records for the same instruction.
    let leaf1 = __cpuid(FEATURE_LEAF);
    for (bit, cause) in [
        (SSSE3_ECX_BIT, "ssse3-not-supported"),
        (SSE41_ECX_BIT, "sse41-not-supported"),
        (SSE42_ECX_BIT, "sse42-not-supported"),
        (AES_ECX_BIT, "aes-not-supported"),
        (PCLMULQDQ_ECX_BIT, "pclmulqdq-not-supported"),
    ] {
        if leaf1.ecx & bit == 0 {
            return Err(CryptoError(refusal(
                cause,
                RefusalDetail::One(u64::from(leaf1.ecx)),
            )));
        }
    }
    if leaf1.edx & SSE2_EDX_BIT == 0 {
        return Err(CryptoError(refusal(
            "sse2-not-supported",
            RefusalDetail::One(u64::from(leaf1.edx)),
        )));
    }
    let max_leaf = __cpuid(0).eax;
    if max_leaf < EXTENDED_FEATURE_LEAF {
        return Err(CryptoError(refusal(
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
            return Err(CryptoError(refusal(
                cause,
                RefusalDetail::One(u64::from(leaf7.ebx)),
            )));
        }
    }
    Ok(u64::from(leaf1.ecx) | (u64::from(leaf7.ebx) << 32))
}

/// Thousandths of a timestamp-counter cycle per byte, as the least any round
/// spent.
///
/// Saturating throughout: the release profile checks overflow, so an
/// implausible counter reading on a part whose `RDTSC` misbehaves must produce
/// a number the gate refuses rather than a fault the operator has to decode.
fn measure(primitive: Primitive) -> u64 {
    let mut buffer = [0_u8; MEASURE_BYTES];
    let mut least = u64::MAX;
    for round in 0..ROUNDS {
        let start = read_timestamp_counter().0;
        for _ in 0..PASSES_PER_ROUND {
            run_once(primitive, &mut buffer);
        }
        let spent = read_timestamp_counter().0.wrapping_sub(start);
        // The first round is the cold one — first touch of the buffer, first
        // pass through the key schedule — so it is run and discarded.
        if round > 0 && spent < least {
            least = spent;
        }
    }
    let bytes = (MEASURE_BYTES as u64).saturating_mul(u64::from(PASSES_PER_ROUND));
    if least == u64::MAX || bytes == 0 {
        return 0;
    }
    least.saturating_mul(1000) / bytes
}

/// One pass of a primitive over `buffer`.
///
/// `black_box` on both sides of every call: the buffer's contents are never
/// read again, and without it the optimizer is entitled to delete the whole
/// measurement and report a part that computes nothing as infinitely fast.
fn run_once(primitive: Primitive, buffer: &mut [u8; MEASURE_BYTES]) {
    // Fixed keys and a fixed nonce: this measures a cipher's throughput, and
    // nothing here is confidential — no output of these calls is used, and the
    // buffer is a local this function's caller drops.
    const KEY: [u8; KEY_LEN] = [0x5A; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0xA5; NONCE_LEN];
    match primitive {
        Primitive::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&buffer[..]));
            black_box(hasher.finish());
        }
        Primitive::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(&KEY);
            let tag = cipher.seal(&NONCE, &[], black_box(&mut buffer[..]));
            black_box(tag.is_ok());
        }
        Primitive::Aes256Gcm => {
            let cipher = Aes256Gcm::new(&KEY);
            let tag = cipher.seal(&NONCE, &[], black_box(&mut buffer[..]));
            black_box(tag.is_ok());
        }
        // Unreachable by construction: `MEASURED` names exactly the three
        // arms above, and this function has one caller, which iterates it.
        Primitive::HmacSha256 | Primitive::HkdfSha256 | Primitive::ChaCha20 | Primitive::Drbg => {}
    }
}

/// Returned by `init` in every case: this domain runs once and then parks in
/// the Microkit event loop, whether it established the profile or refused to.
struct Crypto;

impl Handler for Crypto {
    type Error = Infallible;

    /// Unreachable by capability: nothing in this system holds a notification
    /// capability on this domain, so the event loop it parks in has no sender.
    /// It exists because [`Handler`] requires it.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
