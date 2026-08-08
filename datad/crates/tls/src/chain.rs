//! Whether an onboarding package's device certificate chains to the anchor
//! delivered beside it, answered by the certificate validator this appliance
//! already adopted.
//!
//! # Adversary
//!
//! The **unauthenticated management-plane attacker**, directly. Both
//! certificates arrive as members of an archive that party uploaded, so an
//! anchor here is not a trust anchor in the usual sense at all — it is a
//! candidate, offered by the same peer that offered the certificate it is asked
//! to vouch for. That is the onboarding trust model, in which the party who
//! reaches an unprovisioned appliance becomes its owner, and it is why the
//! answer this module gives is worth stating precisely: **it says the delivered
//! anchor really did issue the delivered certificate, and nothing about who the
//! anchor is.**
//!
//! # Why the adopted validator and not a walk written here
//!
//! The appliance has exactly one general X.509 policy engine, it is the one the
//! TLS library brings, and this is the only place that can reach it. A second
//! reader written to answer the same question would be the parser an attacker
//! found first, and it would be the *newer* of the two — so it would be the one
//! with the bugs. Everything a chain check weighs beyond one signature comes
//! free with the adopted one: basic constraints, key usage, the validity
//! windows, the path length, and the encodings each of those lives in.
//!
//! # Why a client verifier over a server one
//!
//! The certificate being judged is an **end entity that identifies a device** —
//! the appliance itself, as the management authority issued it. That is the
//! shape a client certificate has, and the client verifier is the one that
//! judges it without also demanding a name to match: a server verifier asks
//! which host the certificate is for, and the answer for a device certificate
//! is no host at all. The revocation list is deliberately empty: there is no
//! revocation transport on an appliance that has never spoken to a management
//! server, and offering one would be a claim this appliance cannot keep.
//!
//! # The allocations are the session's, and the reserve is the caller's
//!
//! Building a verifier allocates, out of the same arena a session runs on. This
//! module refuses nothing on that account — the caller checks the room it needs
//! before it begins, on [`crate::STEP_RESERVE`]'s terms, because a refusal has
//! to happen before the allocations start rather than inside them.

use alloc::sync::Arc;

use lfw_package::{ChainRejected, ChainVerifier};
use rustls::{
    RootCertStore,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, UnixTime},
    server::WebPkiClientVerifier,
};

/// The adopted validator, asked one question: does this device certificate
/// chain to this anchor.
///
/// It holds the provider rather than taking one per call because a verifier is
/// built per package — the anchor is a *delivered* value, so there is nothing to
/// build once at bring-up — and the provider is the one thing that is the same
/// every time.
pub struct DeliveredAnchor {
    provider: Arc<CryptoProvider>,
    /// Seconds since the Unix epoch, as the caller's clock reads them.
    ///
    /// Carried rather than fetched, on the same terms every other time in this
    /// crate is: the appliance's notion of now comes from a domain that owns a
    /// clock, and a crate that reached for one of its own would be a second
    /// answer to what time it is.
    now: u64,
}

impl DeliveredAnchor {
    #[must_use]
    pub const fn new(provider: Arc<CryptoProvider>, now: u64) -> Self {
        Self { provider, now }
    }
}

impl ChainVerifier for DeliveredAnchor {
    /// Both arguments are DER a peer composed, and every way either of them can
    /// be wrong is one answer.
    ///
    /// That the answer carries nothing is the injected interface's own
    /// decision and it is right here for a second reason: *why* a chain failed
    /// is the adopted validator's vocabulary, several dozen strings deep and
    /// none of them this appliance's — so a caller that carried one onward
    /// would be putting a library's internal prose on an operator surface.
    fn verify(&self, end_entity: &[u8], anchor: &[u8]) -> Result<(), ChainRejected> {
        let mut anchors = RootCertStore::empty();
        // The anchor is parsed here, by the store that will use it, rather than
        // being checked somewhere and passed in — so an anchor that is not a
        // certification authority, or is not a certificate at all, is refused by
        // the same code that would otherwise have to trust it.
        anchors
            .add(CertificateDer::from(anchor.to_vec()))
            .map_err(|_| ChainRejected)?;
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(anchors),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|_| ChainRejected)?;
        // No intermediates: the package carries two certificates and this
        // appliance issues a path of length one, so a chain needing a third is
        // one it was not given.
        verifier
            .verify_client_cert(
                &CertificateDer::from(end_entity.to_vec()),
                &[],
                UnixTime::since_unix_epoch(core::time::Duration::from_secs(self.now)),
            )
            .map(|_| ())
            .map_err(|_| ChainRejected)
    }
}
