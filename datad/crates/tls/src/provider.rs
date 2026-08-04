use alloc::{boxed::Box, sync::Arc, vec};

use lfw_crypto::Entropy;
use rustls::{
    Error,
    crypto::{CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SupportedKxGroup},
    pki_types::PrivateKeyDer,
    sign::SigningKey,
    time_provider::TimeProvider,
};

use crate::{kx::X25519MlKem768, suite::TLS13_CHACHA20_POLY1305_SHA256, verify};

/// Assemble the appliance's crypto provider.
///
/// Every part of it is first-party glue over the cryptography this appliance
/// already proves at boot: the hash, the MAC and the key schedule built from
/// it, the record-layer AEAD, the hybrid key exchange, and the one signature
/// algorithm. Nothing here computes anything — the whole file is the shape the
/// library wants those primitives in.
///
/// The two `Box::leak` calls are the only way to satisfy the library's
/// `&'static dyn` key-exchange list from a source of randomness chosen at run
/// time. They allocate once, before the arena's mark is taken, so the bytes
/// are outside every session's reset and are not a leak that grows.
#[must_use]
pub fn provider(entropy: &'static dyn Entropy) -> CryptoProvider {
    let hybrid: &'static dyn SupportedKxGroup = Box::leak(Box::new(X25519MlKem768::new(entropy)));
    let random: &'static dyn SecureRandom = Box::leak(Box::new(Random { entropy }));
    CryptoProvider {
        cipher_suites: vec![TLS13_CHACHA20_POLY1305_SHA256],
        kx_groups: vec![hybrid],
        signature_verification_algorithms: verify::SUPPORTED_ALGORITHMS,
        secure_random: random,
        key_provider: &Keys,
    }
}

/// The node's generator, in the shape the library asks for randomness in.
struct Random {
    entropy: &'static dyn Entropy,
}

impl core::fmt::Debug for Random {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the node generator")
    }
}

impl SecureRandom for Random {
    /// Infallible, because the appliance's generator is: it is seeded once at
    /// bring-up from hardware, and a node whose seeding failed refused to
    /// start rather than reaching this call.
    fn fill(&self, out: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.entropy.fill(out);
        Ok(())
    }
}

/// The library's door to a private key in DER, and one this appliance keeps
/// shut.
///
/// The appliance never loads a key from an encoding: the key is generated
/// where it lives and is reached through a signing capability instead, which
/// is what lets the store domain hold it later without this crate changing.
/// A refusal here is therefore the correct answer and not a gap — the only
/// callers are the library's convenience builders, which this crate does not
/// use.
#[derive(Debug)]
struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(&self, _: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "this appliance signs through a key it never loads".into(),
        ))
    }
}

/// The clock, in the shape the library asks the time in.
///
/// Wall time reaches the library only to judge a certificate's validity
/// window. The appliance's own clock is an unauthenticated real-time-clock
/// reading, which is enough for that and is not enough to judge anything an
/// adversary controls — so the window is ten years wide and the check is a
/// sanity bound rather than a security control.
pub struct Clock {
    unix_seconds: u64,
}

impl Clock {
    #[must_use]
    pub const fn at(unix_seconds: u64) -> Self {
        Self { unix_seconds }
    }
}

impl core::fmt::Debug for Clock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("rtc")
    }
}

impl TimeProvider for Clock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            core::time::Duration::from_secs(self.unix_seconds),
        ))
    }
}
