//! Initial sequence numbers per RFC 6528: a monotonic time component plus a
//! keyed hash of the connection's own 4-tuple.
//!
//! # Why this is a security mechanism and not a refinement
//!
//! An off-path attacker who can predict the sequence number a listener will
//! choose can inject data into a connection it cannot see, and can complete a
//! handshake as an address it does not hold. Against the
//! **management-plane attacker** that is the difference between needing to be on
//! the path and not needing to be. RFC 6528 section 3's construction is what removes
//! it: the time component keeps sequence numbers from repeating across
//! connections on one 4-tuple, and the keyed hash makes the offset between two
//! *different* 4-tuples unguessable without the key — so observing one
//! connection's numbers reveals nothing about another's.
//!
//! # Why SipHash-2-4 rather than something shorter
//!
//! The hash has to be a pseudo-random function keyed by a secret, and inventing
//! one is the mistake this whole mechanism exists to avoid: a construction with
//! an unexamined key-recovery weakness leaves the ISN predictable to an attacker
//! who has watched enough connections, which is exactly the property being
//! bought. SipHash-2-4 is short enough to hold to this workspace's coverage
//! floor, needs no tables, and is a published PRF with published test vectors —
//! so [`tests`] can hold this implementation to the reference output rather than
//! only to itself, which is the one check a hand-rolled mixer could never have.
//!
//! Two alternatives were rejected. A truncated cryptographic digest (SHA-256)
//! would be a far larger implementation for a 32-bit output and no stronger
//! claim at this size. Reading a fresh random number per connection instead of
//! hashing would make the ISN unpredictable *and* would lose the RFC 6528
//! property the time component provides — two connections on one 4-tuple whose
//! numbers must not overlap — and would put an `RDRAND` on the path of every
//! inbound `SYN`, which is a flood amplifier.
//!
//! # The secret is the caller's to obtain
//!
//! Nothing here generates entropy: a crate that reached for a hardware
//! instruction could not be host-tested, and the protection domain is where the
//! `unsafe` for one belongs (`pds/management`). [`IsnSecret`] therefore has one
//! constructor, taking the bytes, and no `Default` — a zero key is a key an
//! attacker also has, and there must be no way to reach one by omission.

use lfw_clock::Monotonic;
use net_headers::Ipv4Address;

use crate::seq::SeqNumber;

/// Nanoseconds per tick of RFC 6528 section 3's timer, which that section fixes at
/// 4 microseconds.
const TIMER_TICK_NANOS: u64 = 4_000;

/// The per-boot key the 4-tuple hash is taken under.
///
/// No `Default` and no `const ZERO`: see the module header. It is `Clone` but
/// not `Copy`, so a caller that passes it somewhere states that it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsnSecret([u8; 16]);

impl IsnSecret {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// RFC 6528 section 3's `M + F(...)`, over one boot's secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsnGenerator {
    secret: IsnSecret,
}

impl IsnGenerator {
    #[must_use]
    pub const fn new(secret: IsnSecret) -> Self {
        Self { secret }
    }

    /// The initial sequence number for one connection.
    ///
    /// The whole 4-tuple is hashed, in a fixed order, so that a peer cannot
    /// learn the offset for one tuple by opening connections on another.
    #[must_use]
    pub fn initial_sequence(
        &self,
        now: Monotonic,
        local: Ipv4Address,
        local_port: u16,
        remote: Ipv4Address,
        remote_port: u16,
    ) -> SeqNumber {
        let mut tuple = [0u8; 12];
        let (head, tail) = tuple.split_at_mut(8);
        // Bounded by construction: the two chunks are 8 and 4 bytes of a 12-byte
        // array, and each `copy_from_slice` is given exactly that many.
        if let Some(chunk) = head.first_chunk_mut::<4>() {
            *chunk = local.octets();
        }
        if let Some(chunk) = head.last_chunk_mut::<4>() {
            *chunk = remote.octets();
        }
        if let Some(chunk) = tail.first_chunk_mut::<2>() {
            *chunk = local_port.to_be_bytes();
        }
        if let Some(chunk) = tail.last_chunk_mut::<2>() {
            *chunk = remote_port.to_be_bytes();
        }
        let offset = siphash24(&self.secret.0, &tuple);
        // The clock component, in RFC 6528's own units. Truncating to 32 bits is
        // the construction, not a loss: the sum is taken modulo 2^32 because a
        // sequence number is.
        let timer = now.as_nanos() / TIMER_TICK_NANOS;
        SeqNumber::new((timer as u32).wrapping_add(offset as u32))
    }
}

/// SipHash-2-4 (Aumasson and Bernstein, 2012) over `message`, keyed by `key`.
///
/// Two compression rounds per message word and four finalization rounds, which
/// is what the name states and what the published test vectors are taken
/// against. Every arithmetic operation is wrapping by definition of the
/// algorithm — it is a 64-bit ARX permutation — so none of them is a
/// possible-overflow this crate's rules would refuse.
fn siphash24(key: &[u8; 16], message: &[u8]) -> u64 {
    let [
        k0_0,
        k0_1,
        k0_2,
        k0_3,
        k0_4,
        k0_5,
        k0_6,
        k0_7,
        k1_0,
        k1_1,
        k1_2,
        k1_3,
        k1_4,
        k1_5,
        k1_6,
        k1_7,
    ] = *key;
    let k0 = u64::from_le_bytes([k0_0, k0_1, k0_2, k0_3, k0_4, k0_5, k0_6, k0_7]);
    let k1 = u64::from_le_bytes([k1_0, k1_1, k1_2, k1_3, k1_4, k1_5, k1_6, k1_7]);

    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    // Whole eight-byte words as arrays rather than slices, so no length
    // conversion needs a branch that could not be taken (and so could not be
    // covered).
    let (blocks, remainder) = message.as_chunks::<8>();
    for block in blocks {
        let word = u64::from_le_bytes(*block);
        v3 ^= word;
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }

    // The final word: whatever bytes are left, little-endian, with the message
    // length in its top byte.
    let mut last = [0u8; 8];
    for (slot, byte) in last.iter_mut().zip(remainder) {
        *slot = *byte;
    }
    // Lossless where it matters: SipHash defines the top byte as the length
    // modulo 256, so the truncation is the specification.
    last[7] = (message.len() % 256) as u8;
    let word = u64::from_le_bytes(last);
    v3 ^= word;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= word;

    v2 ^= 0xff;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^ v1 ^ v2 ^ v3
}

/// One SipRound.
fn round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod tests;
