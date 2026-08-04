//! The hardware draws this node's generator is seeded from, and the one
//! instruction that yields them.
//!
//! # Why many draws and not the two the management domain takes
//!
//! That domain draws 128 bits once, for a sequence-number secret that lives
//! one boot. This one seeds the generator every key the appliance will ever
//! own descends from, so the failure it must survive is different: not a busy
//! queue but a source that answered *badly* — degraded, stuck, or reseeded
//! from too little. Nothing in the output of such a source distinguishes it
//! from a healthy one, so the answer is not detection but margin and a health
//! check.
//!
//! [`DRAWS`] words is 2048 bits for a 352-bit seed. Intel's guidance is that
//! 512 bits of `RDRAND` output spans at least one reseed of the underlying
//! hardware entropy source, so this spans several, and the whole of it is
//! folded into the seed rather than sliced — a fold means a single degraded
//! draw among many is diluted rather than placed directly into a key.
//!
//! # The health check, and what it can and cannot catch
//!
//! Two conditions refuse the draw: a word equal to the one before it, and a
//! word of all zeroes or all ones. These are the shapes a stuck or
//! disconnected generator produces, and they are the repetition test the
//! entropy-source standards prescribe in its simplest form. Each costs a
//! false refusal with probability about 2^-64, which is not a rate worth
//! weighing against a silently constant seed.
//!
//! What it cannot catch is a source that is merely *weak* — biased, or
//! reseeding from a starved pool — because such output is statistically
//! indistinguishable from good output at this sample size. That limit is
//! stated rather than papered over: the check is a tripwire for a broken
//! generator, not an assurance of a healthy one.
//!
//! # Adversary
//!
//! None reaches this file. `RDRAND` is a hardware instruction and no byte here
//! comes from a device, a peer protection domain or the network. What it
//! defends against is the hardware failing, which is not an adversary but is
//! the failure this node cannot afford to survive quietly.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use lfw_crypto::{Drbg, Entropy};

use core::arch::x86_64::{__cpuid, _rdrand64_step};

/// How many times one 64-bit draw is retried before the generator is called
/// broken, from Intel's *Digital Random Number Generator Software
/// Implementation Guide*: the instruction clears the carry flag when its queue
/// is momentarily empty, and beyond this many attempts it is not busy but
/// faulty.
const DRAW_ATTEMPTS: usize = 10;

/// Words drawn for one seeding — 2048 bits, on the terms in the header.
pub const DRAWS: usize = 32;

/// Bytes those words occupy.
pub const ENTROPY_LEN: usize = DRAWS * 8;

/// The CPUID leaf and the bit in its `ECX` that reports `RDRAND`.
const FEATURE_LEAF: u32 = 1;
const RDRAND_BIT: u32 = 1 << 30;

/// Why this node cannot seed its generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyError {
    /// `CPUID.01H:ECX[30]` is clear, so the instruction is not architecturally
    /// available. The word read is carried whole, because an operator
    /// comparing it against the part's documentation is what turns this into a
    /// diagnosis.
    NotSupported { feature_word: u32 },
    /// The instruction is available and did not produce a number in
    /// [`DRAW_ATTEMPTS`] attempts, which is a hardware fault rather than a
    /// busy queue. `word` says which draw failed.
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
/// whose generator will not answer, or one whose answers are the shapes a
/// broken generator gives.
pub fn draw_seed_material(raw: &mut [u8; ENTROPY_LEN]) -> Result<(), EntropyError> {
    let feature_word = feature_word();
    if feature_word & RDRAND_BIT == 0 {
        return Err(EntropyError::NotSupported { feature_word });
    }
    let mut previous: Option<u64> = None;
    for word in 0..DRAWS {
        let drawn = draw().ok_or(EntropyError::Exhausted { word })?;
        if drawn == 0 || drawn == u64::MAX || previous == Some(drawn) {
            return Err(EntropyError::Stuck { word });
        }
        previous = Some(drawn);
        // Bounded by construction: the eight-byte chunk at this loop's own
        // index, in an array sized `DRAWS * 8` by the same constant the loop
        // counts to.
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
    // The one fact left is third-party runtime behaviour and is recorded
    // rather than asserted: the seL4 kernel does not trap `CPUID` in a
    // protection domain, the same premise `read_timestamp_counter` records for
    // `RDTSC`. Leaf 1 exists on every part that implements `CPUID` at all.
    __cpuid(FEATURE_LEAF).ecx
}

/// One 64-bit draw, retried as Intel's guidance prescribes.
fn draw() -> Option<u64> {
    for _ in 0..DRAW_ATTEMPTS {
        let mut value = 0_u64;
        // SAFETY: `_rdrand64_step` requires the `rdrand` target feature to be
        // available on the part it executes on, and the guarantor of that is
        // the `CPUID` check in `draw_seed_material` above — the only caller,
        // which returns `EntropyError::NotSupported` before reaching this
        // function when `CPUID.01H:ECX[30]` is clear. The kernel is the
        // guarantor of the same unprivileged-execution fact `feature_word`
        // records. The intrinsic writes through the pointer it is given and
        // reports whether it did, and `value` is a live local of the right
        // width, so there is no other precondition to meet; the carry flag is
        // read below rather than assumed, which is why a cleared one is a
        // retry and not a zero word folded into a seed.
        let carry = unsafe { _rdrand64_step(&mut value) };
        if carry == 1 {
            return Some(value);
        }
    }
    None
}

/// The node's generator, shared the way everything that needs randomness asks
/// for it.
///
/// One generator per node, behind the interface [`lfw_crypto::Entropy`]
/// defines: the TLS stack, the key generation and the certificate serials all
/// draw from the one whose seeding this domain proved and whose output its
/// published vectors cover. A second source would be a second thing to prove.
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

// SAFETY: `Sync` requires that concurrent shared access be sound. The
// guarantor is the flag below rather than the execution model: `fill` acquires
// `taken` before it touches the generator and releases it after, so at most
// one caller holds the `&mut` at a time whatever the caller count. A Microkit
// protection domain runs one thread and so never contends, but the claim does
// not rest on that — an appliance whose soundness argument was "there is only
// one thread" would be one edit away from being wrong.
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
        // SAFETY: the flag above is held, so this is the only live reference
        // to the generator for the duration of the call. It is released
        // immediately afterwards and the reference does not escape.
        unsafe { (*self.generator.get()).fill(out) };
        self.taken.store(false, Ordering::Release);
    }
}
