#![no_main]
#![no_std]

//! Cryptography protection domain: it proves, on the booted image, that every
//! primitive the appliance owns answers its published test vectors, measures
//! what each costs on this part, seeds the node's random bit generator from
//! hardware, proves it can authenticate under a key it does not hold, and then
//! parks.
//!
//! This is one of three binaries compiled with the SIMD target specification, and
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
//! 4. **The appliance can authenticate under a key it does not hold, and can
//!    present the certificate over it.** The device key belongs to the domain
//!    that owns the medium it is written on, and this domain is not that one. So
//!    it asks three things: which key do you hold, sign these bytes, and hand me
//!    the certificate over that key — then verifies the signature against the key
//!    it was given, which is a claim about the delegation and not about ECDSA, and
//!    holds the certificate to that same key, which is a claim this domain can
//!    settle on its own. The session below then runs its **server half under that
//!    same delegated key**, because that is the only thing that proves the seam
//!    where it will actually be used: `sign` is called synchronously, deep inside
//!    a rustls handshake, at the point a server produces its `CertificateVerify`.
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
//! The **byzantine neighbour protection domain**, in two places now. The clock
//! calibration region this domain maps read-only to stamp its records, whose
//! triple is peer-written and ranged by `pd_runtime::PdClock` before a stamp is
//! derived from it. And the **delegation's reply region**, every word of which is
//! the key holder's: `wire::signing` ranges it before a byte is copied, and what
//! survives that is a byte string this domain hands to a verifier or to the TLS
//! library, both of which judge it against a public key rather than believing it.
//! A holder that never answers is bounded rather than trusted — see `delegate`.
//!
//! No device, no network byte and no frame reaches this domain, and no input to
//! any primitive comes from outside it: every one is a compile-time constant, a
//! hardware draw, or a value this domain produced itself.
//!
//! **No surface here carries key material, and this domain now holds none at
//! all for the identity it authenticates under.** The seed is drawn, folded and
//! consumed inside this file; the generator holds it, no record names it, and the
//! raw draws are cleared before the buffer holding them goes out of scope. The
//! device key is never here in any form: what crosses the delegation is a public
//! point, a public name, a certificate and signatures, because those are the only
//! shapes the ABI has fields for and every one of them is something a peer of this
//! appliance is shown. The certificate is not printed either — its length is what
//! reaches a record. The only numbers that leave are counts and costs.
//!
//! # Two keys, and only one of them is this domain's
//!
//! The session it proves has two ends, and they are keyed differently on purpose.
//! The **client** end and the certification authority above both are generated
//! here from this domain's own generator, because what they stand in for — a
//! management server and the anchor it was issued under — is not this appliance.
//! The **server** end is the appliance, so it authenticates under the appliance's
//! own key: the certificate binds the public point the holder answered with, and
//! the `CertificateVerify` is computed in the holder's domain. The one thing this
//! arrangement cannot prove is a session across a wire, there being none yet.
//!
//! # This domain seeds itself, and so does every other that holds a key
//!
//! The draw, its health check and the generator behind it are `lfw_crypto`'s, so
//! two domains that each own key material do not each carry a copy of the rule
//! for what a broken generator looks like. What they do not share is the
//! generator: each seeds its own from the hardware, because a seed that crossed a
//! channel would let the domain at the other end reproduce the key. `RDRAND` and
//! `CPUID` are unprivileged and carried by no capability, so a domain seeding
//! itself is granted nothing by this system description.

extern crate alloc;

use alloc::sync::Arc;

mod arena;
mod delegate;

use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::hint::black_box;

use lfw_crypto::{
    Aes256Gcm, ChaCha20Poly1305, Drbg, Entropy, EntropyError, KEY_LEN, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey, NONCE_LEN, NodeEntropy, P256_MAX_SIGNATURE_LEN, P256SecretKey,
    SEED_MATERIAL_LEN, Sha256, VectorFailure, X25519Secret, hardware_seed, prove_aes_256_gcm,
    prove_chacha20, prove_chacha20_poly1305, prove_drbg, prove_ecdsa_p256, prove_hkdf_sha256,
    prove_hmac_sha256, prove_ml_kem_768, prove_sha256, prove_x25519, zeroize,
};
use lfw_log::{
    Domain, DomainDetail, DomainState, Event, Primitive, Refusal, RefusalDetail, RingSink, Sink,
};
use lfw_metrics::{CRYPTO_PRIMITIVES, CryptoSample, StatsShard};
use lfw_tls::{Negotiated, ServerKey, SessionError, prove_session};
use pd_runtime::{
    PdClock, RELAY_DEMANDS_PER_WAKEUP, TerminatedSession, Terminating, TerminatingPass,
    attach_region, log_sample, read_timestamp_counter,
};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{
    ClockCalibration, LogConsume, LogRecords, RelayRefusal, RelayReply, RelayRequest, SignReply,
    SignRequest,
};

use arena::{ARENA_BYTES, Arena, ArenaRegion};
use delegate::{Delegated, DelegationError, HeldCertificate, HeldKey};

/// The appliance's only allocator, and the one exception to the rule that a
/// protection domain has none. It is here because a proven TLS implementation
/// requires one; every property that makes that acceptable — the bound, the
/// refusal, the confinement to this domain — is `arena`'s.
#[global_allocator]
static ARENA: Arena = Arena::new();

/// Bytes one timing pass runs a primitive over. Four pages: past every cache
/// line and block boundary that could make a shorter buffer flatter than the
/// steady state, and small enough that a round is thousands of cycles rather
/// than millions on a part emulating every instruction.
const MEASURE_BYTES: usize = 4096;

/// Passes per timed round, and rounds per primitive. The product is what each
/// primitive processes; the minimum across rounds is what it reports.
const PASSES_PER_ROUND: u32 = 4;
const ROUNDS: u32 = 8;

/// `CPUID.0H:EAX` must reach this leaf for the structured-feature word ADX
/// lives in to exist.
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

/// `CPUID.07H.0H:EBX` bit for the one general-purpose-register extension the
/// target also enables at compile time. BMI2 is not among them: it is
/// VEX-encoded, and the emulator this image is proved on refuses that encoding
/// while the kernel's saved state excludes the vector state, so the target
/// disables it and gating on a bit nothing uses would refuse a part that runs
/// this image perfectly.
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
const PROOFS: [Proof; 10] = [
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
    Proof {
        primitive: Primitive::EcdsaP256,
        prove: prove_ecdsa_p256,
        cause: "ecdsa-p256-vector-mismatch",
    },
    Proof {
        primitive: Primitive::X25519,
        prove: prove_x25519,
        cause: "x25519-vector-mismatch",
    },
    Proof {
        primitive: Primitive::MlKem768,
        prove: prove_ml_kem_768,
        cause: "ml-kem-768-vector-mismatch",
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

/// The primitives whose cost is one number per operation rather than per byte.
///
/// A signature, a key agreement and an encapsulation each do exactly one
/// amount of work; dividing that by a message length would be dividing by a
/// denominator nobody chose. So they are reported in whole cycles, under their
/// own record and their own metric.
const PER_OPERATION: [Primitive; 3] =
    [Primitive::EcdsaP256, Primitive::X25519, Primitive::MlKem768];

/// Operations one timed round performs, and rounds per primitive. Fewer
/// passes than the per-byte measurement takes because one asymmetric
/// operation is already tens of thousands of cycles.
const OPERATIONS_PER_ROUND: u32 = 2;

/// Bytes of application data the proven session carries each way. Short on
/// purpose: what it establishes is that the traffic keys work in both
/// directions, and a longer payload would measure the pump.
const SESSION_PAYLOAD: &[u8] = b"librefirewall management channel";

/// The domain that holds the device key, as this domain's channel to it.
///
/// One direction only: this domain wakes the holder, and the holder answers by
/// publishing rather than by signalling back. There is nothing for a reverse
/// capability to do — `sign` is called from inside a handshake and has no
/// continuation a notification could resume — and it would be a wakeup capability
/// held by the domain that owns the appliance's identity on the domain that runs
/// adopted protocol code.
const KEY_HOLDER: Channel = Channel::new(0);

/// The domain that owns the network, as this domain's channel to it.
///
/// **Both directions**, unlike the holder's above, and the reason is scheduling
/// rather than taste: that domain sits at this one's priority and is
/// event-driven, so neither is running while the other is and neither has a
/// loop the other's write could be observed in. A reply published into the
/// relay is therefore invisible until it is signalled. What the capability is
/// worth to whoever reaches this domain is a wakeup on a domain that owns the
/// management port, and a bounded run of bytes on a connection it already
/// holds; it is worth no key, the relay's ABI having no field for one.
const MANAGEMENT: Channel = Channel::new(1);

/// The bytes the direct proof signs.
///
/// A fixed string and not a digest of anything: what is being proved is that a
/// signature made in another domain verifies under the key that domain named, and
/// any message settles that. It is deliberately not the session payload — a
/// message that appeared in two proofs would let one of them pass on the other's
/// work.
const DELEGATION_CHALLENGE: &[u8] = b"librefirewall device key delegation";

/// How much of the arena a starved session is left with.
///
/// A little more than a phase is required to have, deliberately: the session
/// passes its first check, sets its two ends up, and is then refused by a
/// later one — which is the interesting half of the claim, because it is the
/// case where the arena drains *under a running session* rather than being
/// short before it starts. The same guard, the same arena and the same
/// allocator as the session above; the only difference is how much room is
/// left.
const STARVED_HEADROOM: usize = lfw_tls::STEP_RESERVE + 8192;

/// The console's primitive vocabulary and the metrics shard's are two arrays
/// in two crates that neither may read from the other, and this domain indexes
/// the second one with a member of the first. Held equal here, where both are
/// visible, so that index is in bounds by construction rather than by a test
/// somewhere else.
const _: () = assert!(Primitive::ALL.len() == CRYPTO_PRIMITIVES.len());

/// Seconds since the Unix epoch, as this node believes them.
///
/// From the clock domain's published calibration where there is one, and from
/// a compile-time floor where there is not: a certificate needs a validity
/// window, and a node whose clock never published would otherwise write one
/// nothing accepts. The floor is not a security control and is not treated as
/// one — the appliance's time is an unauthenticated real-time-clock reading
/// either way, which is enough to bound a certificate and not enough to judge
/// an adversary by.
fn wall_seconds(clock: &PdClock<'_>) -> u64 {
    /// Seconds at the start of 2026, which is before any image carrying this
    /// code was built and after every year a `UTCTime` cannot name.
    const FLOOR: u64 = 1_767_225_600;
    clock
        .calibration()
        .map_or(FLOOR, |calibration| {
            calibration.utc(read_timestamp_counter()).as_nanos() / 1_000_000_000
        })
        .max(FLOOR)
}

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
    cycles_per_operation: [u64; CRYPTO_PRIMITIVES.len()],
}

#[protection_domain]
fn init() -> Crypto {
    // Before anything that could have something to say. The region is zeroed
    // by the kernel, so it is a valid empty ring the moment it is mapped, and
    // the console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let calibration: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let clock = PdClock::new(calibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(calibration));
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);
    // Before the first allocation, which is what the null base until now
    // would otherwise refuse. The region is mapped read-write into this
    // domain and no other, and nothing else in this system names it.
    let region: &'static ArenaRegion = attach_region!(arena_vaddr: ArenaRegion);
    ARENA.attach(region.bytes.as_ptr().cast_mut().cast());
    // The delegation's two regions, whose directions are the system
    // description's: the request is this domain's to write and the holder's to
    // read, and the reply is the reverse. Nothing here restates that — the handle
    // `wire::signing` hands back reaches the reply only through a view with no
    // store on it, so this domain cannot forge the signature it then verifies.
    let sign_request: &'static SignRequest = attach_region!(sign_request_vaddr: SignRequest);
    let sign_reply: &'static SignReply = attach_region!(sign_reply_vaddr: SignReply);
    // The relay's two regions, and the directions are the mirror of the
    // delegation's above: this domain reads what the network end wrote and
    // writes what goes back. It cannot write the question, so it cannot make
    // the network end believe a peer said something it did not.
    let relay_request: &'static RelayRequest = attach_region!(relay_request_vaddr: RelayRequest);
    let relay_reply: &'static RelayReply = attach_region!(relay_reply_vaddr: RelayReply);

    announce(&sink, DomainState::Starting, DomainDetail::None);
    // One requester for the whole boot, and behind an `Arc` because the library's
    // certificate resolver takes a share of it: a second would restart at sequence
    // zero and reuse numbers the first has outstanding
    // (`wire::SignRequest::requester`). Allocated here, before the arena's mark is
    // taken, so it sits outside every session's reset.
    let delegated: Arc<Delegated> =
        Arc::new(Delegated::attach(sign_request, sign_reply, KEY_HOLDER));
    let outcome = bring_up(&sink, wall_seconds(&clock), &delegated);
    match &outcome.verdict {
        Ok(()) => announce(&sink, DomainState::Ready, DomainDetail::None),
        Err(CryptoError(cause)) => {
            // The whole reason, not a summary: with no shell and no CLI on the
            // appliance, this record is all an operator gets.
            announce(&sink, DomainState::Refused, DomainDetail::Refusal(*cause));
        }
    }
    // The bring-up's own numbers, which do not move again: what this domain
    // does from here is answer the relay, and no session changes a vector count
    // or a measured cost. The log counts beside them do move, which is why the
    // sample is kept and republished rather than written once.
    let sample = CryptoSample {
        proven: outcome.verdict.is_ok(),
        vectors: outcome.vectors,
        milli_cycles_per_byte: outcome.milli_cycles_per_byte,
        cycles_per_operation: outcome.cycles_per_operation,
        log: log_sample(sink.dropped(), sink.refused()),
    };
    stats.publish(&sample.values());
    Crypto {
        relay: Terminating::attach(relay_request, relay_reply),
        sink,
        shard: stats,
        sample,
    }
}

/// Gate on the part, prove every primitive, measure the three that are
/// measured, and seed the generator — reporting each step as it happens, so a
/// refusal halfway through leaves the steps that did hold on the console.
fn bring_up(sink: &dyn Sink, now: u64, delegated: &Arc<Delegated>) -> Outcome {
    let mut outcome = Outcome {
        verdict: Ok(()),
        vectors: [0; CRYPTO_PRIMITIVES.len()],
        milli_cycles_per_byte: [0; CRYPTO_PRIMITIVES.len()],
        cycles_per_operation: [0; CRYPTO_PRIMITIVES.len()],
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

    let generator = match seed_generator() {
        Ok(generator) => generator,
        Err(error) => {
            outcome.verdict = Err(error);
            return outcome;
        }
    };
    // Leaked deliberately and once: every key exchange the TLS provider holds
    // reaches the node's randomness through a `'static` borrow, and this
    // domain runs to completion and parks, so there is nothing to give back
    // to. The allocation happens before the arena's mark is taken.
    let entropy: &'static dyn Entropy =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(NodeEntropy::new(generator)));

    for primitive in PER_OPERATION {
        let cost = measure_operation(primitive, entropy);
        outcome.cycles_per_operation[primitive as usize] = cost;
        announce(
            sink,
            DomainState::Negotiated,
            DomainDetail::Operation {
                primitive,
                cycles: cost,
            },
        );
    }

    // Before the session, because the session's server half runs under the key
    // this establishes: a handshake that failed on an unanswered delegation would
    // report a TLS refusal and say nothing about which half was at fault.
    let delegation = match prove_delegation(sink, delegated) {
        Ok(delegation) => delegation,
        Err(error) => {
            outcome.verdict = Err(error);
            return outcome;
        }
    };

    if let Err(error) = prove_tls(sink, entropy, now, delegated, &delegation) {
        outcome.verdict = Err(error);
    }
    outcome
}

/// The appliance's identity as the key holder gave it up: which key it holds, and
/// the certificate over that key.
///
/// One value because they are one answer and are only worth anything held to each
/// other. A certificate that does not carry the point the same channel named is not
/// this appliance's identity however well either half reads alone, and a point with
/// no certificate is nothing a peer can be shown.
struct Delegation {
    held: HeldKey,
    certificate: HeldCertificate,
}

/// Ask the key holder which key it holds, have it sign a fixed challenge, verify
/// that signature against that key, and take the certificate over it.
///
/// **This proves the delegation and not ECDSA**, which the vector run above has
/// already settled. What it establishes is that the two regions carry a request
/// and an answer, that the answer is this request's, that the bytes coming back
/// are a signature under the point the holder named, and that the certificate the
/// holder keeps is over that same point — so a channel wired to the wrong region,
/// a holder answering the wrong question, a public key paired with somebody else's
/// scalar, and a certificate belonging to some other appliance are each a refusal
/// here rather than a handshake failure three steps later.
///
/// The record it leaves names the appliance, the holder's own tally and the size of
/// the certificate. Reported before the session, so a boot whose session then fails
/// still shows the delegation having worked.
fn prove_delegation(sink: &dyn Sink, delegated: &Delegated) -> Result<Delegation, CryptoError> {
    let held = delegated.held_key().map_err(delegation_refusal)?;
    // An all-zero point is what a zeroed region reads as, so it is the one shape
    // that would let a channel nobody wired pass this proof.
    if held.public_key.iter().all(|byte| *byte == 0) || held.device == 0 {
        return Err(CryptoError(refusal(
            "delegated-key-absent",
            RefusalDetail::None,
        )));
    }
    let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
    let len = lfw_tls::SignOperation::sign(delegated, DELEGATION_CHALLENGE, &mut signature)
        .map_err(|_| CryptoError(refusal("delegated-signature-refused", RefusalDetail::None)))?;
    // The whole point of the exercise: the bytes are held to the key the *other*
    // domain named, so a holder signing under anything else fails here rather
    // than in a peer's validator.
    lfw_crypto::p256_verify(
        &held.public_key,
        DELEGATION_CHALLENGE,
        signature.get(..len).unwrap_or_default(),
    )
    .map_err(|_| {
        CryptoError(refusal(
            "delegated-signature-invalid",
            RefusalDetail::One(len as u64),
        ))
    })?;
    let certificate = held_certificate(delegated, &held)?;
    let delegation = Delegation { held, certificate };
    report_delegation(sink, delegated, &delegation);
    Ok(delegation)
}

/// Take the appliance's certificate from the holder and hold it to the key the
/// same channel named.
///
/// **The check is one this domain can settle by itself**, which is why it is worth
/// making: the uncompressed point the holder published appears in a certificate
/// exactly once, inside the `SubjectPublicKeyInfo`, so finding those bytes in the
/// encoding establishes that the certificate's subject public key is the key that
/// will sign. A certificate for some other appliance, a stale one from before a
/// factory reset, and a region nobody wired all fail it.
///
/// Nothing is parsed. A second X.509 reader in the domain that faces the network
/// is what this appliance declines to have, and none is needed: containment is the
/// whole claim, and the algorithm the point is wrapped in is fixed by the profile
/// the holder wrote it under.
fn held_certificate(delegated: &Delegated, held: &HeldKey) -> Result<HeldCertificate, CryptoError> {
    let certificate = delegated.held_certificate().map_err(certificate_refusal)?;
    if !contains(certificate.as_bytes(), &held.public_key) {
        // The length and not the bytes: a certificate is public, and a console
        // that printed 768 bytes of DER would push every record an operator needs
        // out of a bounded ring to say something they cannot read anyway.
        return Err(CryptoError(refusal(
            "delegated-certificate-not-the-key",
            RefusalDetail::One(certificate.as_bytes().len() as u64),
        )));
    }
    Ok(certificate)
}

/// Whether `needle` appears in `haystack`.
///
/// Written out rather than reached for, because `core` has no such method, and
/// total: an empty needle is answered `false` rather than handed to `windows`,
/// which has no zero width, and an over-long one yields no window at all.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// What the delegation has come to: the appliance this domain signs for, the
/// holder's own signature tally, and the size of the certificate it handed over.
///
/// The tally is the holder's number rather than a count of calls made here, which
/// is what makes a second record after the handshake meaningful: the number
/// moving is the holder having signed again. The certificate's length is on both
/// records and does not move, which is the point of it being there twice — one
/// appliance has one certificate, and a length that changed across a boot would be
/// two answers to one question.
fn report_delegation(sink: &dyn Sink, delegated: &Delegated, delegation: &Delegation) {
    announce(
        sink,
        DomainState::Negotiated,
        DomainDetail::Delegated {
            device: delegation.held.device,
            signatures: delegated.signatures(),
            certificate: delegation.certificate.as_bytes().len() as u64,
        },
    );
}

/// Why the delegation refused, as a cause token an operator can act on.
fn delegation_refusal(error: DelegationError) -> CryptoError {
    CryptoError(refusal(error.cause(), RefusalDetail::None))
}

/// Why the certificate could not be had, as a cause token of its own.
///
/// Its own three rather than [`delegation_refusal`]'s, because by the time this is
/// reached the public-key exchange has already worked and the challenge has already
/// been signed: a holder that stops answering *here* is a different fault from one
/// that never answered, and an operator reading
/// `delegated-certificate-unanswered` knows the channel is wired and the key is
/// usable. A shared token would throw that away.
fn certificate_refusal(error: DelegationError) -> CryptoError {
    let cause = match error {
        DelegationError::Unanswered => "delegated-certificate-unanswered",
        DelegationError::Refused => "delegated-certificate-refused",
        DelegationError::Faulted => "delegated-certificate-faulted",
    };
    CryptoError(refusal(cause, RefusalDetail::None))
}

/// Establish one session **under the delegated key**, report what it negotiated,
/// and then prove that a session which runs out of arena refuses rather than
/// faults.
///
/// Both halves are here because they are one claim: the allocator this domain
/// carries is bounded, and what makes that acceptable is that reaching the
/// bound is an answer. A boot that showed only the first half would have shown
/// a working TLS stack and nothing about what happens when it runs out.
///
/// **The server half's key is the appliance's own and lives in another domain.**
/// That is what takes the seam the whole way: the delegation is exercised where
/// it will be used, synchronously inside a handshake, rather than as a call this
/// file makes on its own terms. A second record afterwards carries the holder's
/// tally, which has moved by the handshake's own `CertificateVerify` — that
/// movement is the proof, because a session that had quietly signed with a local
/// key would leave the number where it was.
///
/// The starved session that follows keeps a **local** key deliberately: what it
/// proves is the arena's bound, and a session that also depended on another
/// domain answering would fail for two reasons at once with one record to say so.
fn prove_tls(
    sink: &dyn Sink,
    entropy: &'static dyn Entropy,
    now: u64,
    delegated: &Arc<Delegated>,
    delegation: &Delegation,
) -> Result<(), CryptoError> {
    let arena = ARENA.bump();
    let mark = arena.mark();
    // A share of the one requester rather than a second one: the resolver holds it
    // for as long as the configuration lives, and two requesters on one channel
    // would each claim the other's replies.
    let negotiated = prove_session(
        entropy,
        arena,
        now,
        SESSION_PAYLOAD,
        &ServerKey::Delegated {
            operation: Arc::clone(delegated) as Arc<dyn lfw_tls::SignOperation>,
            public_key: delegation.held.public_key,
        },
    )
    .map_err(session_refusal)?;
    report_session(sink, &negotiated);
    announce(
        sink,
        DomainState::Negotiated,
        DomainDetail::Arena {
            bytes: arena.high_water() as u64,
            bound: ARENA_BYTES as u64,
        },
    );
    arena.reset_to(mark);
    // The holder's tally again, after the handshake. It must have moved: the
    // server's `CertificateVerify` was computed in the holder's domain, and a
    // number that stayed put would mean the handshake signed some other way.
    report_delegation(sink, delegated, delegation);

    // The same session with the arena all but full. It must refuse, and the
    // refusal must be the arena's rather than any other — a session that
    // failed for another reason here would prove nothing about the bound.
    let starve = arena.remaining().saturating_sub(STARVED_HEADROOM);
    let filler = arena
        .allocate(starve, 16)
        .map_err(|_| CryptoError(refusal("arena-starvation-unreachable", RefusalDetail::None)))?;
    let starved = prove_session(entropy, arena, now, SESSION_PAYLOAD, &ServerKey::Local);
    arena.release(filler, starve);
    arena.reset_to(mark);
    match starved {
        Err(SessionError::ArenaExhausted(exhausted)) => {
            announce(
                sink,
                DomainState::Negotiated,
                DomainDetail::Arena {
                    bytes: exhausted.remaining as u64,
                    bound: exhausted.requested as u64,
                },
            );
            // The guard is what refused, so the allocator never had to: a
            // non-zero count here would mean an allocation was answered null,
            // which is the path this design exists to keep unreachable.
            if arena.refusals() != 0 {
                return Err(CryptoError(refusal(
                    "arena-allocation-refused",
                    RefusalDetail::One(u64::from(arena.refusals())),
                )));
            }
            Ok(())
        }
        Err(other) => Err(session_refusal(other)),
        Ok(_) => Err(CryptoError(refusal(
            "starved-session-established",
            RefusalDetail::One(STARVED_HEADROOM as u64),
        ))),
    }
}

/// One session's parameters, as three records: what it settled on, what it
/// carried, and who it admitted.
fn report_session(sink: &dyn Sink, negotiated: &Negotiated) {
    announce(
        sink,
        DomainState::Negotiated,
        DomainDetail::Session {
            version: negotiated.version,
            suite: negotiated.suite,
        },
    );
    announce(
        sink,
        DomainState::Negotiated,
        DomainDetail::Exchange {
            group: negotiated.group,
            echoed: u64::from(negotiated.echoed),
        },
    );
    // The peer's identity as the profile defines one: the leading 128 bits of
    // the digest over the certificate it authenticated with. No certificate
    // and no key reaches a surface — this is a name for one.
    let mut device = 0_u128;
    for byte in negotiated.peer_certificate.iter().take(16) {
        device = (device << 8) | u128::from(*byte);
    }
    announce(sink, DomainState::Negotiated, DomainDetail::Peer { device });
}

/// Why a session did not establish, as a cause token an operator can act on.
fn session_refusal(error: SessionError) -> CryptoError {
    let cause = match error {
        SessionError::ArenaExhausted(_) => "tls-arena-exhausted",
        SessionError::Identity(_) => "tls-identity-unbuildable",
        SessionError::Tls(_) => "tls-handshake-refused",
        SessionError::Stalled => "tls-session-stalled",
        SessionError::NoPeerCertificate => "tls-peer-unauthenticated",
        SessionError::WrongPeerCertificate => "tls-peer-certificate-wrong",
        SessionError::NotEchoed => "tls-application-data-lost",
        SessionError::NotClosed => "tls-session-not-closed",
    };
    CryptoError(refusal(cause, RefusalDetail::None))
}

/// Draw hardware entropy, fold it into the node's generator, prove the
/// generator answers, and hand it back.
///
/// It is handed back rather than dropped now that something consumes it: the
/// session below keys itself from this generator, so what proves the seeding
/// and what keys the appliance are the same object.
fn seed_generator() -> Result<Drbg, CryptoError> {
    let mut raw = [0_u8; SEED_MATERIAL_LEN];
    let drawn = hardware_seed(&mut raw);
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
        Ok(generator)
    });
    // Whatever happened above, the draws do not outlive this frame in readable
    // form. Through `lfw_crypto`, which is the one place in the appliance that
    // clears key material, so the *how* is decided once rather than per caller.
    zeroize(&mut raw);
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
    if leaf7.ebx & ADX_EBX_BIT == 0 {
        return Err(CryptoError(refusal(
            "adx-not-supported",
            RefusalDetail::One(u64::from(leaf7.ebx)),
        )));
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
        Primitive::HmacSha256
        | Primitive::HkdfSha256
        | Primitive::ChaCha20
        | Primitive::Drbg
        | Primitive::EcdsaP256
        | Primitive::X25519
        | Primitive::MlKem768 => {}
    }
}

/// Whole timestamp-counter cycles one operation of `primitive` cost, as the
/// least any round spent.
///
/// The same minimum-of-rounds argument the per-byte measurement is taken
/// under, and the same saturating arithmetic for the same reason.
fn measure_operation(primitive: Primitive, entropy: &dyn Entropy) -> u64 {
    let mut least = u64::MAX;
    for round in 0..ROUNDS {
        let start = read_timestamp_counter().0;
        for _ in 0..OPERATIONS_PER_ROUND {
            run_operation(primitive, entropy);
        }
        let spent = read_timestamp_counter().0.wrapping_sub(start);
        if round > 0 && spent < least {
            least = spent;
        }
    }
    if least == u64::MAX {
        return 0;
    }
    least / u64::from(OPERATIONS_PER_ROUND)
}

/// One operation of an asymmetric primitive, end to end.
///
/// End to end and not one half: what an operator wants from these numbers is
/// what a handshake costs, and a handshake signs *and* verifies, agrees from
/// both sides, and encapsulates *and* decapsulates. Measuring a half would
/// report a number no path takes.
fn run_operation(primitive: Primitive, entropy: &dyn Entropy) {
    match primitive {
        Primitive::EcdsaP256 => {
            let Ok(key) = P256SecretKey::generate(entropy) else {
                return;
            };
            let public = key.public_key();
            let mut signature = [0_u8; P256_MAX_SIGNATURE_LEN];
            let Ok(len) = key.sign(black_box(SESSION_PAYLOAD), &mut signature) else {
                return;
            };
            black_box(lfw_crypto::p256_verify(&public, SESSION_PAYLOAD, &signature[..len]).is_ok());
        }
        Primitive::X25519 => {
            let ours = X25519Secret::generate(entropy);
            let theirs = X25519Secret::generate(entropy);
            black_box(ours.agree(&black_box(theirs.public_key())).is_ok());
        }
        Primitive::MlKem768 => {
            let ours = MlKem768DecapsulationKey::generate(entropy);
            let Ok(peer) = MlKem768EncapsulationKey::from_bytes(&ours.encapsulation_key()) else {
                return;
            };
            let Ok((ciphertext, _)) = peer.encapsulate(entropy) else {
                return;
            };
            black_box(ours.decapsulate(black_box(&ciphertext)).is_ok());
        }
        // Unreachable by construction, on `run_once`'s terms: `PER_OPERATION`
        // names exactly the three arms above.
        Primitive::Sha256
        | Primitive::HmacSha256
        | Primitive::HkdfSha256
        | Primitive::ChaCha20
        | Primitive::ChaCha20Poly1305
        | Primitive::Aes256Gcm
        | Primitive::Drbg => {}
    }
}

/// The relay's own refusals, in the vocabulary a console line speaks.
///
/// One arm per cause, on the management domain's terms: each of these is a
/// different thing to go and look at, and three of the four accuse the network
/// end of a protocol mistake rather than the peer of anything.
const fn relay_refusal(reason: RelayRefusal, detail: RefusalDetail) -> Refusal {
    let cause = match reason {
        RelayRefusal::NoConnection => "relay-no-connection",
        RelayRefusal::PayloadTooLong => "relay-payload-too-long",
        RelayRefusal::NoSuchOperation => "relay-no-such-operation",
        // Unreachable: this end never gives up on a session, having no protocol
        // to give up on yet. A value rather than an assertion, because the
        // match must be exhaustive and a panic on this path is not admissible.
        RelayRefusal::SessionFailed => "relay-session-failed",
    };
    refusal(cause, detail)
}

/// Returned by `init` in every case. The bring-up runs once; what the domain
/// does afterwards is answer the relay, which is why this now carries state.
struct Crypto {
    /// The terminating end of the relay. Every decision it makes about a session
    /// — what to answer, when one ends, and how — is `pd_runtime::relay`'s and
    /// host-tested there; what is here is the console record each answer owes
    /// and the shard republished beside it.
    relay: Terminating<'static>,
    sink: RingSink<'static, PdClock<'static>>,
    /// The shard this domain publishes, kept so a session's end can republish
    /// it: the sample's own numbers are the bring-up's and do not move, but the
    /// log counts beside them do, and a shard written once at boot would
    /// under-report every record written after it.
    shard: &'static StatsShard,
    sample: CryptoSample,
}

impl Crypto {
    /// Put on the console what one answer left owed: the refusal's token, where
    /// there was one, and the account of a session that finished.
    ///
    /// The order is the refusal first: it is the cause and the account is what it
    /// cost, and a reader meets them in that order on the transcript.
    fn announce_pass(&mut self, pass: TerminatingPass) {
        if let Some((reason, detail)) = pass.refused {
            announce(
                &self.sink,
                DomainState::Ready,
                DomainDetail::Refusal(relay_refusal(reason, detail)),
            );
        }
        if let Some(session) = pass.report {
            self.report(session);
        }
    }

    /// The session's account, and the shard republished with the log counts
    /// these records have moved.
    fn report(&mut self, session: TerminatedSession) {
        announce(
            &self.sink,
            DomainState::Ready,
            DomainDetail::Onboarded {
                relayed: session.relayed,
                received: session.received,
                sent: session.sent,
                ended: session.ended,
            },
        );
        let mut sample = self.sample;
        sample.log = log_sample(self.sink.dropped(), self.sink.refused());
        self.shard.publish(&sample.values());
    }
}

impl Handler for Crypto {
    type Error = Infallible;

    /// Take what the network end has handed over and answer it.
    ///
    /// Bounded by [`RELAY_DEMANDS_PER_WAKEUP`] and by the channel's own window,
    /// which is one item: a wakeup storm from the other end costs a constant
    /// number of reads of a word this domain already maps and never an
    /// unbounded loop. Nothing here blocks, nothing here allocates, and nothing
    /// here reads a byte it was not handed.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let mut answered = false;
        for _ in 0..RELAY_DEMANDS_PER_WAKEUP {
            let Some(demand) = self.relay.take() else {
                break;
            };
            let pass = self.relay.answer(demand);
            self.announce_pass(pass);
            answered = true;
        }
        // Woken once per pass rather than once per answer, and **only where
        // there was one**: the window is one item, so a pass publishes at most
        // one reply, and a signal on a pass that answered nothing is a wakeup
        // the other end would answer with another wakeup.
        if answered {
            MANAGEMENT.notify();
        }
        Ok(())
    }
}
