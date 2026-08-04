//! The one random number this domain needs, and the instruction that yields it.
//!
//! # What it is for, and why nothing weaker will do
//!
//! The transport derives every initial sequence number from a keyed hash of the
//! connection's 4-tuple (RFC 6528, `lfw_tcp::isn`), and the key is a secret this
//! node must hold for one boot and never reveal. An attacker who knows it can
//! predict the sequence number a listener will choose for any 4-tuple, and with
//! that can inject into a connection it cannot see and complete a handshake as an
//! address it does not hold — off the path, exactly the threat model's
//! **management-plane attacker**. So the secret must be unpredictable, and it
//! must be *per boot*: a constant compiled in, or one derived from the
//! configuration, is one an attacker reads out of the image.
//!
//! There is no other source. This system has no entropy pool, no seed file and no
//! persistent storage a domain may write; the counter this domain also reads is
//! not a secret, being observable from anywhere on the node and roughly
//! predictable from outside it. `RDRAND` is what the hardware offers, and it is
//! the whole of what is available.
//!
//! # Why a failure refuses the domain rather than proceeding
//!
//! A weak secret is worse than no port, because a port with a weak secret *looks*
//! like a working one. So every failure below — no `RDRAND` at all, or one that
//! will not produce a number — is a refusal that leaves the management port
//! unaddressed and says why on the console. An operator with no shell —
//! the appliance has none — gets one line, and it names the cause.
//!
//! # Why the retry count is what Intel's own guidance says
//!
//! `RDRAND` sets the carry flag when the value it wrote is usable and clears it
//! when the hardware's queue is momentarily empty; the documented remedy is a
//! bounded retry, and the documented bound is ten. Beyond that the generator is
//! not busy but broken, and looping further would spin a protection domain
//! forever on a hardware fault, unbounded by anything this node controls.

use core::arch::x86_64::{__cpuid, _rdrand64_step};

/// How many times one 64-bit draw is retried before the generator is called
/// broken. Intel's *Digital Random Number Generator Software Implementation
/// Guide* is the source of the number; see the module header.
const DRAW_ATTEMPTS: usize = 10;

/// Words drawn: a 128-bit key, which is `lfw_tcp::IsnSecret`'s width.
const WORDS: usize = 2;

/// The CPUID leaf and the bit in its `ECX` that reports `RDRAND`.
const FEATURE_LEAF: u32 = 1;
const RDRAND_BIT: u32 = 1 << 30;

/// Why this node cannot produce a per-boot secret.
///
/// Two causes rather than one, because they are different things to go and look
/// at: a part that never had the instruction, and one that has it and will not
/// answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyError {
    /// `CPUID.01H:ECX[30]` is clear, so the instruction is not architecturally
    /// available. The word read is carried whole: an operator comparing it against
    /// the part's documentation is what turns this into a diagnosis.
    NotSupported { feature_word: u32 },
    /// The instruction is available and did not produce a number in
    /// [`DRAW_ATTEMPTS`] attempts, which is a hardware fault rather than a busy
    /// queue. `word` says which of the two draws failed.
    Exhausted { word: usize },
}

/// Sixteen bytes of hardware randomness, or the reason there are none.
///
/// # Errors
/// [`EntropyError`], on the terms in the module header: a part with no `RDRAND`,
/// or one whose generator will not answer.
pub fn secret_bytes() -> Result<[u8; 16], EntropyError> {
    let feature_word = feature_word();
    if feature_word & RDRAND_BIT == 0 {
        return Err(EntropyError::NotSupported { feature_word });
    }
    let mut bytes = [0u8; 16];
    for word in 0..WORDS {
        let drawn = draw().ok_or(EntropyError::Exhausted { word })?;
        // Bounded by construction: two eight-byte chunks of a sixteen-byte array,
        // and the index is this loop's own rather than anything external.
        let at = word * 8;
        for (slot, byte) in bytes.iter_mut().skip(at).zip(drawn.to_le_bytes()) {
            *slot = byte;
        }
    }
    Ok(bytes)
}

/// `CPUID.01H:ECX`, the word carrying the `RDRAND` feature bit.
fn feature_word() -> u32 {
    // `__cpuid` is a safe call on this toolchain, which is the compiler's
    // statement that the instruction has no precondition a caller could violate:
    // it is architectural on x86_64 and unprivileged, and
    // `support/targets/x86_64-sel4-minimal.json` targets x86_64 and nothing else.
    // The one fact left is third-party runtime behaviour and is recorded rather
    // than asserted: the seL4 kernel does not trap `CPUID` in a protection
    // domain, the same premise `read_timestamp_counter` records for `RDTSC`.
    // Being wrong about it is a fault the Microkit monitor reports in this
    // domain, not a silently wrong number. Leaf 1 exists on every part that
    // implements `CPUID` at all, so no leaf bound is being assumed either.
    __cpuid(FEATURE_LEAF).ecx
}

/// One 64-bit draw, retried as Intel's guidance prescribes.
///
/// `None` where the generator did not answer in [`DRAW_ATTEMPTS`] attempts, which
/// is reported as a refusal rather than answered with the zero the instruction
/// leaves behind.
fn draw() -> Option<u64> {
    for _ in 0..DRAW_ATTEMPTS {
        let mut value = 0u64;
        // SAFETY: `_rdrand64_step` requires the `rdrand` target feature to be
        // available on the part it executes on, and the guarantor of that is the
        // `CPUID` check in `secret_bytes` above — the only caller, which returns
        // `EntropyError::NotSupported` before reaching this function when
        // `CPUID.01H:ECX[30]` is clear. The kernel is the guarantor of the same
        // unprivileged-execution fact `feature_word` records. The intrinsic
        // writes through the pointer it is given and reports whether it did, and
        // `value` is a live local of the right width, so there is no other
        // precondition to meet; the carry flag it returns is read below rather
        // than assumed, which is why a cleared one is a retry and not a zero
        // secret.
        let carry = unsafe { _rdrand64_step(&mut value) };
        if carry == 1 {
            return Some(value);
        }
    }
    None
}
