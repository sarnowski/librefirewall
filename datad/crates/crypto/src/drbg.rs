use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use zeroize::Zeroize as _;

use crate::{KEY_LEN, NONCE_LEN};

/// Bytes of seed material the generator is constructed from: a ChaCha20 key
/// and the nonce that separates one seeding from the next.
pub const SEED_LEN: usize = KEY_LEN + NONCE_LEN;

/// Draws after which [`Drbg::reseed_due`] asks for fresh hardware entropy.
///
/// The generator's forward secrecy does not depend on reseeding — each draw
/// already discards the key that produced it — so this bound is not about the
/// generator degrading. It is about a seed that was *never* good: a hardware
/// source that answered badly at boot is not detectable from the output, and
/// re-drawing bounds how much of a node's key material descends from one such
/// answer. A million draws is far past what a node makes between reboots, so
/// on a healthy appliance the bound is a backstop rather than a schedule.
pub const RESEED_INTERVAL: u32 = 1 << 20;

/// Domain separation for the entropy fold: a salt and an info string that
/// belong to this generator and to nothing else the appliance derives, so
/// material folded here can never coincide with material folded elsewhere from
/// the same input.
const SEED_SALT: &[u8] = b"librefirewall-drbg-seed-v1";
const SEED_INFO: &[u8] = b"librefirewall-chacha20-drbg";

/// Bytes one pass of the keystream produces beyond the next key. Sized so the
/// buffer below is a few hundred bytes of stack rather than a page, because
/// every consumer draws a key or a nonce and none draws in bulk.
const CHUNK: usize = 256;

/// The appliance's deterministic random bit generator: ChaCha20 in counter
/// mode, rekeyed from its own output on every draw.
///
/// # What it is, stated as a construction rather than a name
///
/// A draw runs the RFC 8439 ChaCha20 keystream under the current key, the
/// seeded nonce and a counter that starts at zero. The first 32 bytes become
/// the next key and are never emitted; what follows is the caller's. The old
/// key is overwritten in place and the keystream buffer is cleared before it
/// leaves the stack, so the state that produced an output cannot be recovered
/// from the state that follows it — a node whose memory is read after the fact
/// does not thereby yield the keys it generated earlier.
///
/// Because every draw is keyed afresh, the counter never has to advance past
/// one pass and the nonce never has to change within a seeding. That is what
/// makes the whole construction provable against a published vector: the first
/// draw after a seeding is exactly the RFC 8439 keystream from byte 32 onward,
/// and `vectors::CHACHA20_STREAM_VECTORS` proves that keystream itself.
///
/// # Why this and not SP 800-90A HMAC_DRBG
///
/// HMAC_DRBG was preferred and rejected on the state of its implementations,
/// not its design: the one crate that offers it is pinned to a previous
/// generation of the adopted hash and MAC crates, which would put two versions
/// of each — and two SHA-256 implementations — into the image. The dependency
/// policy denies duplicate versions, and the second implementation would be
/// one more thing to prove on the shipped image for no property this
/// construction lacks.
///
/// # Adversary
///
/// **Untrusted network traffic**, at one remove: what this generates ends up
/// as nonces and ephemeral keys facing the network, so an output that repeated
/// or that could be run backwards is the failure that matters. Nothing an
/// adversary sends reaches this type — it takes a seed and a length and
/// nothing else — so there is no input here to reject; the properties are
/// carried by the construction above and proved by
/// `vectors::DRBG_VECTORS`.
pub struct Drbg {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    draws: u32,
}

impl Drbg {
    /// Fold raw hardware entropy of any length into a seeded generator.
    ///
    /// The fold is HKDF-SHA-256 — extract with a fixed domain-separating salt,
    /// then expand — because that is the standard construction for exactly
    /// this step and it is already adopted here. Folding rather than slicing
    /// is the property that matters: a caller hands over far more raw material
    /// than a seed needs, and every bit of it reaches every bit of the seed,
    /// so one degraded draw among many is diluted rather than placed directly
    /// into a key.
    ///
    /// The derived seed is cleared before this returns; only the generator's
    /// own key survives, and that is rekeyed on the first draw.
    #[must_use]
    pub fn from_entropy(raw: &[u8]) -> Self {
        let mut seed = [0_u8; SEED_LEN];
        let prk = crate::hkdf_extract(SEED_SALT, raw);
        // `SEED_LEN` is far below the construction's limit, so the only
        // refusal this call has is unreachable here; the assertion below is
        // what holds that true as the seed's shape changes.
        const { assert!(SEED_LEN <= crate::MAX_DERIVED_LEN) };
        if crate::hkdf_expand(&prk, SEED_INFO, &mut seed).is_err() {
            // Unreachable on the assertion above, and answered rather than
            // panicked on: a generator seeded from the zero array would be a
            // silent catastrophe, so the refusal path is the one that cannot
            // happen *and* is not the dangerous one if it did — `from_seed`
            // below is fed a seed that never left its zeroed state, and the
            // caller's own draw check catches a generator that does not
            // advance.
            seed = [0_u8; SEED_LEN];
        }
        let generator = Self::from_seed(&seed);
        seed.zeroize();
        generator
    }

    /// Seed the generator from exactly [`SEED_LEN`] bytes. The caller owns
    /// where they came from; in a test that is a constant, and on the
    /// appliance it is [`Drbg::from_entropy`]'s fold of hardware draws.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut key = [0_u8; KEY_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        key.copy_from_slice(&seed[..KEY_LEN]);
        nonce.copy_from_slice(&seed[KEY_LEN..]);
        Self {
            key,
            nonce,
            draws: 0,
        }
    }

    /// Fill `out` with generated bytes.
    ///
    /// Infallible and unbounded in `out`: a request longer than one pass is
    /// served by several, each rekeyed like any other draw, so there is no
    /// length here to refuse and no counter that can run out.
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(CHUNK) {
            self.fill_chunk(chunk);
        }
        self.draws = self.draws.saturating_add(1);
    }

    /// Whether the seed this generator runs on has served long enough that the
    /// caller should draw a fresh one from hardware.
    #[must_use]
    pub fn reseed_due(&self) -> bool {
        self.draws >= RESEED_INTERVAL
    }

    /// One pass: at most [`CHUNK`] bytes out, and the next key taken from in
    /// front of them.
    fn fill_chunk(&mut self, chunk: &mut [u8]) {
        let mut keystream = [0_u8; KEY_LEN + CHUNK];
        let produced = KEY_LEN + chunk.len();
        let mut cipher = chacha20::ChaCha20::new(&self.key.into(), &self.nonce.into());
        cipher.apply_keystream(&mut keystream[..produced]);
        chunk.copy_from_slice(&keystream[KEY_LEN..produced]);
        self.key.copy_from_slice(&keystream[..KEY_LEN]);
        keystream.zeroize();
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
