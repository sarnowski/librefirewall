//! The hardware a protection domain seeds its generator from, and the one
//! instruction that yields it.
//!
//! Every domain that owns key material seeds its **own** generator from this,
//! and that is the point rather than an accident of where the code sits: a seed
//! that crossed a channel would let the domain at the other end reproduce the
//! key, which for a device identity is the whole of what custody means. `RDRAND`
//! and `CPUID` are unprivileged instructions carried by no capability, so a
//! domain seeding itself is a domain granted nothing.
//!
//! What lives here is what two such domains would otherwise each hold a copy of:
//! how much to draw, which shapes are a broken generator, and how a draw becomes
//! a generator. What stays with each domain is the *reporting* — the cause tokens
//! a refusal reaches an operator as are minted where the domain names them, so
//! two domains' console vocabularies never become one.
//!
//! # Why many draws and not the two a per-boot secret takes
//!
//! A sequence-number secret lives one boot and 128 bits of it is the whole
//! requirement. A generator every key an appliance will ever own descends from
//! has a different failure to survive: not a busy queue but a source that
//! answered *badly* — degraded, stuck, or reseeded from too little. Nothing in
//! the output of such a source distinguishes it from a healthy one, so the answer
//! is not detection but margin and a health check.
//!
//! [`SEED_DRAWS`] words is 2048 bits for a 352-bit seed. Intel's guidance is that
//! 512 bits of `RDRAND` output spans at least one reseed of the underlying
//! hardware entropy source, so this spans several, and the whole of it is folded
//! into the seed rather than sliced — a fold means a single degraded draw among
//! many is diluted rather than placed directly into a key.
//!
//! # The health check, and what it can and cannot catch
//!
//! Two conditions refuse the draw: a word equal to the one before it, and a word
//! of all zeroes or all ones. These are the shapes a stuck or disconnected
//! generator produces, and they are the repetition test the entropy-source
//! standards prescribe in its simplest form. Each costs a false refusal with
//! probability about 2^-64, which is not a rate worth weighing against a silently
//! constant seed.
//!
//! What it cannot catch is a source that is merely *weak* — biased, or reseeding
//! from a starved pool — because such output is statistically indistinguishable
//! from good output at this sample size. That limit is stated rather than papered
//! over: the check is a tripwire for a broken generator, not an assurance of a
//! healthy one.
//!
//! # Adversary
//!
//! None reaches this file. No byte here comes from a device, a peer protection
//! domain or the network. What it defends against is the hardware failing, which
//! is not an adversary but is the failure a node holding an identity cannot
//! afford to survive quietly.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use core::arch::x86_64::{__cpuid, _rdrand64_step};

use crate::{Drbg, Entropy};

/// How many times one 64-bit draw is retried before the generator is called
/// broken, from Intel's *Digital Random Number Generator Software Implementation
/// Guide*: the instruction clears the carry flag when its queue is momentarily
/// empty, and beyond this many attempts it is not busy but faulty.
const DRAW_ATTEMPTS: usize = 10;

/// Words drawn for one seeding — 2048 bits, on the terms in the header.
pub const SEED_DRAWS: usize = 32;

/// Bytes those words occupy, and the width of the buffer [`hardware_seed`] fills.
pub const SEED_MATERIAL_LEN: usize = SEED_DRAWS * 8;

/// The CPUID leaf and the bit in its `ECX` that reports `RDRAND`.
const FEATURE_LEAF: u32 = 1;
const RDRAND_BIT: u32 = 1 << 30;

/// Why a node cannot seed a generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyError {
    /// `CPUID.01H:ECX[30]` is clear, so the instruction is not architecturally
    /// available. The word read is carried whole, because an operator comparing
    /// it against the part's documentation is what turns this into a diagnosis.
    NotSupported { feature_word: u32 },
    /// The instruction is available and did not produce a number in
    /// [`DRAW_ATTEMPTS`] attempts, which is a hardware fault rather than a busy
    /// queue. `word` says which draw failed.
    Exhausted { word: usize },
    /// A draw repeated the one before it, or was all zeroes or all ones. The
    /// index says which, so a repeating source and a stuck-at-zero one are
    /// different things to go and look at.
    Stuck { word: usize },
}

/// Fill `raw` with hardware randomness, or say why there is none.
///
/// # Errors
/// [`EntropyError`], on the terms in the header: a part with no `RDRAND`, one
/// whose generator will not answer, or one whose answers are the shapes a broken
/// generator gives.
pub fn hardware_seed(raw: &mut [u8; SEED_MATERIAL_LEN]) -> Result<(), EntropyError> {
    let feature_word = feature_word();
    if feature_word & RDRAND_BIT == 0 {
        return Err(EntropyError::NotSupported { feature_word });
    }
    fold_draws(raw, draw)
}

/// The health check and the fold, over whatever `draw` answers.
///
/// Separated from the instruction so the whole of what this module *decides* is
/// reachable by a host test: which shapes refuse, which index a refusal names,
/// and where each accepted word lands in the buffer. What is left in
/// [`hardware_seed`] is the CPUID gate and the intrinsic, neither of which a test
/// can hold.
///
/// # Errors
/// [`EntropyError::Exhausted`] where `draw` answers `None`, and
/// [`EntropyError::Stuck`] for a word this check refuses — each naming the index
/// it happened at.
pub fn fold_draws(
    raw: &mut [u8; SEED_MATERIAL_LEN],
    mut draw: impl FnMut() -> Option<u64>,
) -> Result<(), EntropyError> {
    let mut previous: Option<u64> = None;
    for word in 0..SEED_DRAWS {
        let drawn = draw().ok_or(EntropyError::Exhausted { word })?;
        if drawn == 0 || drawn == u64::MAX || previous == Some(drawn) {
            return Err(EntropyError::Stuck { word });
        }
        previous = Some(drawn);
        // Bounded by construction: the eight-byte chunk at this loop's own
        // index, in an array sized `SEED_DRAWS * 8` by the same constant the
        // loop counts to.
        let at = word * 8;
        for (slot, byte) in raw.iter_mut().skip(at).take(8).zip(drawn.to_le_bytes()) {
            *slot = byte;
        }
    }
    Ok(())
}

/// `CPUID.01H:ECX`, the word carrying the `RDRAND` feature bit.
fn feature_word() -> u32 {
    // `__cpuid` is a safe call on this toolchain, which is the compiler's
    // statement that the instruction has no precondition a caller could
    // violate: it is architectural on x86_64 and unprivileged, and every
    // specification under `support/targets` targets x86_64 and nothing else.
    // The one fact left is third-party runtime behaviour and is recorded rather
    // than asserted: the seL4 kernel does not trap `CPUID` in a protection
    // domain, the same premise a timestamp-counter read rests on. Leaf 1 exists
    // on every part that implements `CPUID` at all.
    __cpuid(FEATURE_LEAF).ecx
}

/// One 64-bit draw, retried as Intel's guidance prescribes.
fn draw() -> Option<u64> {
    for _ in 0..DRAW_ATTEMPTS {
        let mut value = 0_u64;
        // SAFETY: `_rdrand64_step` requires the `rdrand` target feature to be
        // available on the part it executes on, and the guarantor of that is the
        // `CPUID` check in `hardware_seed` above — the only caller of this
        // function, which returns `EntropyError::NotSupported` before reaching
        // it when `CPUID.01H:ECX[30]` is clear. The kernel is the guarantor of
        // the same unprivileged-execution fact `feature_word` records. The
        // intrinsic writes through the pointer it is given and reports whether
        // it did, and `value` is a live local of the right width, so there is no
        // other precondition to meet; the carry flag is read below rather than
        // assumed, which is why a cleared one is a retry and not a zero word
        // folded into a seed.
        let carry = unsafe { _rdrand64_step(&mut value) };
        if carry == 1 {
            return Some(value);
        }
    }
    None
}

/// Overwrite a buffer that held key material and is about to go out of scope.
///
/// The one place in the appliance that clears key material, so the *how* is
/// decided once: the adopted `zeroize` crate, whose whole purpose is a write the
/// optimiser may not remove. A caller doing it by hand would need `unsafe` — a
/// volatile write — and that is `unsafe` in whichever crate reached for it,
/// including crates with no hardware or ABI reason to hold any.
///
/// It does not make the bytes unreachable, and does not pretend to: a value that
/// was copied before this ran is still wherever it was copied to. What it
/// guarantees is that *this* buffer does not outlive its use in readable form.
pub fn zeroize(bytes: &mut [u8]) {
    use zeroize::Zeroize as _;
    bytes.zeroize();
}

/// One node's generator, shared the way everything that needs randomness asks
/// for it.
///
/// One generator per domain, behind the interface [`Entropy`] defines: whatever
/// that domain keys — a session, a device identity, a certificate serial — draws
/// from the one whose seeding it proved. A second source would be a second thing
/// to prove.
pub struct NodeEntropy {
    /// Held rather than borrowed, because the interface hands out a shared
    /// reference and the generator advances on every draw.
    generator: UnsafeCell<Drbg>,
    /// What makes the sharing sound rather than merely single-threaded.
    taken: AtomicBool,
}

impl NodeEntropy {
    #[must_use]
    pub const fn new(generator: Drbg) -> Self {
        Self {
            generator: UnsafeCell::new(generator),
            taken: AtomicBool::new(false),
        }
    }
}

// SAFETY: `Sync` requires that concurrent shared access be sound. The guarantor
// is the flag below rather than the execution model: `fill` acquires `taken`
// before it touches the generator and releases it after, so at most one caller
// holds the `&mut` at a time whatever the caller count. A Microkit protection
// domain runs one thread and so never contends, but the claim does not rest on
// that — an appliance whose soundness argument was "there is only one thread"
// would be one edit away from being wrong.
unsafe impl Sync for NodeEntropy {}

impl Entropy for NodeEntropy {
    fn fill(&self, out: &mut [u8]) {
        while self
            .taken
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the flag above is held, so this is the only live reference to
        // the generator for the duration of the call. It is released immediately
        // afterwards and the reference does not escape.
        unsafe { (*self.generator.get()).fill(out) };
        self.taken.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

    /// A generator answering a fixed sequence, so what the fold does with each
    /// word is visible.
    fn sequence(words: Vec<Option<u64>>) -> impl FnMut() -> Option<u64> {
        let mut at = 0_usize;
        move || {
            let answer = words.get(at).copied().flatten();
            at += 1;
            answer
        }
    }

    /// Every accepted word lands at its own eight bytes, little-endian, and the
    /// buffer is filled exactly.
    #[test]
    fn each_accepted_draw_lands_at_its_own_eight_bytes() {
        let words: Vec<Option<u64>> = (1..=SEED_DRAWS as u64).map(Some).collect();
        let mut raw = [0_u8; SEED_MATERIAL_LEN];
        fold_draws(&mut raw, sequence(words)).expect("distinct non-degenerate words");
        for word in 0..SEED_DRAWS {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&raw[word * 8..word * 8 + 8]);
            assert_eq!(u64::from_le_bytes(bytes), word as u64 + 1);
        }
    }

    /// The three shapes a broken generator gives, each refused at the index it
    /// happened at — which is what makes a repeating source and a stuck-at-zero
    /// one two different things to go and look at.
    #[test]
    fn each_shape_of_a_broken_generator_is_refused_at_its_own_index() {
        let good: Vec<Option<u64>> = (1..=SEED_DRAWS as u64).map(Some).collect();
        for (at, degenerate) in [(0_usize, 0_u64), (3, u64::MAX)] {
            let mut words = good.clone();
            words[at] = Some(degenerate);
            let mut raw = [0_u8; SEED_MATERIAL_LEN];
            assert_eq!(
                fold_draws(&mut raw, sequence(words)),
                Err(EntropyError::Stuck { word: at })
            );
        }
        // A repeat of the word before it, which no single-word rule catches.
        let mut words = good.clone();
        words[5] = words[4];
        let mut raw = [0_u8; SEED_MATERIAL_LEN];
        assert_eq!(
            fold_draws(&mut raw, sequence(words)),
            Err(EntropyError::Stuck { word: 5 })
        );
    }

    #[test]
    fn a_generator_that_stops_answering_is_refused_at_the_draw_it_stopped_on() {
        let mut words: Vec<Option<u64>> = (1..=SEED_DRAWS as u64).map(Some).collect();
        words[7] = None;
        let mut raw = [0_u8; SEED_MATERIAL_LEN];
        assert_eq!(
            fold_draws(&mut raw, sequence(words)),
            Err(EntropyError::Exhausted { word: 7 })
        );
        // And one that answers nothing at all is refused at the first draw
        // rather than filling the buffer with zeroes.
        assert_eq!(
            fold_draws(&mut raw, sequence(vec![])),
            Err(EntropyError::Exhausted { word: 0 })
        );
    }

    /// The same value at two *non-adjacent* positions is accepted: the check is
    /// a repetition test over consecutive draws and not a uniqueness test, and
    /// claiming the stronger property would be claiming something this cannot
    /// see.
    #[test]
    fn a_value_repeated_out_of_sequence_is_not_a_stuck_generator() {
        let mut words: Vec<Option<u64>> = (1..=SEED_DRAWS as u64).map(Some).collect();
        words[9] = words[2];
        let mut raw = [0_u8; SEED_MATERIAL_LEN];
        fold_draws(&mut raw, sequence(words)).expect("no two adjacent draws agree");
    }

    /// The generator behind the shared interface advances: two draws of the same
    /// width do not answer the same bytes. Neither value leaves this frame.
    #[test]
    fn the_shared_generator_advances_between_draws() {
        let entropy = NodeEntropy::new(Drbg::from_entropy(&[0x5a; SEED_MATERIAL_LEN]));
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        entropy.fill(&mut first);
        entropy.fill(&mut second);
        assert_ne!(first, second);
    }

    /// The buffer is cleared, and cleared whatever it held: a run of zeroes is
    /// what a caller relies on, and a partial clear would leave the tail of a
    /// scalar readable.
    #[test]
    fn zeroizing_a_buffer_leaves_every_byte_zero() {
        let mut buffer = [0xA5_u8; SEED_MATERIAL_LEN];
        zeroize(&mut buffer);
        assert!(buffer.iter().all(|byte| *byte == 0));
        // And over an empty slice, which is the one length a loop could get
        // wrong.
        zeroize(&mut []);
    }

    #[test]
    fn each_entropy_refusal_reads_differently() {
        let mut rendered: Vec<std::string::String> = [
            EntropyError::NotSupported { feature_word: 0 },
            EntropyError::Exhausted { word: 1 },
            EntropyError::Stuck { word: 1 },
        ]
        .iter()
        .map(|error| std::format!("{error:?}"))
        .collect();
        rendered.sort();
        let count = rendered.len();
        rendered.dedup();
        assert_eq!(rendered.len(), count);
    }
}
