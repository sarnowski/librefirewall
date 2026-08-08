//! `lfw_tls`'s onboarding server: the TLS 1.3 terminator an unauthenticated
//! administrator-or-attacker reaches, driven the way the relay drives it — one
//! arbitrary byte stream cut into arbitrary deliveries, each answered into a
//! buffer of an arbitrary size.
//!
//! # Adversary
//!
//! The **management-plane attacker**, with the relay in between carrying its
//! bytes unread. Every byte here is that party's, and so is the pacing: how
//! much arrives at once, where the pieces fall, and how much room the wire has
//! for the answer. A harness that fed the whole stream in one call would model
//! away exactly the authority that makes the buffering interesting, because a
//! record that spans two deliveries is the reason there is a buffer at all.
//!
//! # What is asserted, beyond not crashing
//!
//! * **Containment.** The answer is written into a guarded buffer, so a write
//!   past what the server was given fails here rather than becoming a byte of
//!   some other structure — and the length it reports is held to what it
//!   actually touched, which the borrow checker does not do.
//! * **Boundedness.** Neither direction outgrows what the server declares it
//!   holds, at any point in the run. A bound deleted from the buffering fails
//!   here rather than becoming a region a peer paces the size of.
//! * **Nothing reaches the protocol above an unestablished handshake.** The
//!   plaintext a peer can put in front of the onboarding protocol is empty
//!   until the handshake completed, so a state machine that offered a record
//!   decrypted under an unfinished key schedule fails here.
//! * **An outcome settles once.** The first answer is the one that stays: a
//!   later consequence of a failure must not displace the cause, because the
//!   cause is what an operator goes and looks at.
//! * **Finished is final.** A session the server has finished with produces no
//!   further byte and does not become unfinished, whatever arrives afterwards.

use std::{
    sync::{Arc, Mutex, OnceLock},
    vec::Vec,
};

use arbitrary::Unstructured;
use lfw_crypto::{Drbg, Entropy, SEED_LEN};
use lfw_tls::{
    Bump, CertificateKind, CryptoProvider, HELD_MAX, Identity, LocalKey, OnboardingServer,
    ServerOutcome, SignOperation, provider,
};

use crate::{any_index, any_u16, guard::Guarded};

/// The arena the cryptography domain gives a session, in the size it gives it.
const ARENA: usize = 2 * 1024 * 1024;

/// Deliveries one input is cut into, at most.
///
/// A libFuzzer time budget and not a bound on the adversary's authority: the
/// cut *points* are arbitrary and every prefix reaches the server regardless,
/// so no arrival pattern is excluded by it.
const MAX_DELIVERIES: usize = 24;

/// The most room an answer is ever offered, which is what the onboarding stream
/// keeps for what goes on the wire.
const ANSWER_ROOM: usize = 4096;

/// A wall clock somewhere inside the certificate's validity.
const NOW: u64 = 1_784_000_000;

/// The name an appliance's onboarding certificate carries.
const APPLIANCE: &[u8] = b"00000000000000000000000000000001";

pub fn onboarding_tls_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let deliveries = any_index(&mut unstructured, MAX_DELIVERIES) + 1;
    let mut cuts: Vec<usize> = (0..deliveries)
        .map(|_| usize::from(any_u16(&mut unstructured)))
        .collect();
    let room = any_index(&mut unstructured, ANSWER_ROOM) + 1;
    // How much of the arena is already spoken for. What makes the refusal path
    // reachable rather than a branch no input takes: on a host the allocations
    // come from the system's allocator, so nothing else would ever draw this
    // arena down.
    let spoken_for = any_index(&mut unstructured, ARENA);
    let stream = unstructured.take_rest();
    cuts.sort_unstable();

    let arena = Bump::new(ARENA);
    if spoken_for > 0 {
        let _ = arena.allocate(spoken_for, 16);
    }
    let (certificate, operation) = appliance();
    let Ok(mut server) = OnboardingServer::open(
        Arc::clone(assembled()),
        &arena,
        NOW,
        certificate,
        Arc::clone(operation),
    ) else {
        // An arena short of a phase's reserve refuses before the session
        // begins, which is the answer and not a failure to find.
        return;
    };

    let mut settled: Option<ServerOutcome> = None;
    let mut finished = false;
    let mut at = 0_usize;
    for cut in cuts
        .into_iter()
        .chain(core::iter::once(stream.len()))
        .map(|cut| cut.min(stream.len()))
    {
        let end = cut.max(at);
        let delivery = stream.get(at..end).unwrap_or_default();
        at = end;

        let mut guarded = Guarded::new(room);
        let turn = server.advance(delivery, guarded.out());
        guarded.assert_margins_intact("the onboarding server's answer");
        assert!(
            turn.sent <= guarded.capacity(),
            "the server reported writing {} bytes into a buffer of {}",
            turn.sent,
            guarded.capacity()
        );
        assert!(
            guarded.touched_len() <= turn.sent,
            "the server wrote further into the buffer than the length it reported"
        );

        assert!(
            server.received().len() <= HELD_MAX,
            "the plaintext the protocol above has not taken outgrew what one direction holds"
        );
        if !server.received().is_empty() {
            assert!(
                matches!(server.outcome(), Some(ServerOutcome::Established(_))),
                "a record was offered to the protocol above an unestablished handshake"
            );
        }
        if let Some(previous) = &settled {
            assert_eq!(
                Some(previous),
                server.outcome(),
                "a later consequence displaced the cause"
            );
        }
        settled = server.outcome().cloned();
        if finished {
            assert_eq!(turn.sent, 0, "a finished session put more on the wire");
            assert!(turn.finished, "a finished session became unfinished");
        }
        finished = turn.finished;

        // The protocol above, standing in for the one that does not exist yet:
        // it takes what it was given and answers with it, which is what puts
        // the record layer's write path under an adversary's own lengths.
        let said = server.received().to_vec();
        if !said.is_empty() {
            server.consumed(said.len());
            assert!(
                server.push(&said) <= said.len(),
                "the server claimed to have taken more plaintext than it was offered"
            );
        }
    }

    // However the run ended, the session ends: a server asked how the handshake
    // went always has an answer once the transport is gone.
    server.close();
    server.ended();
    assert!(
        server.outcome().is_some(),
        "a session that ended settled on no outcome at all"
    );
}

/// The provider every session here is given, assembled once.
///
/// Assembling one leaks two allocations that never come back, so a harness that
/// assembled one per input would spend a fuzzing run growing rather than
/// covering.
fn assembled() -> &'static Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Arc::new(provider(entropy())))
}

/// The appliance's own identity, built once.
///
/// A keypair and a certificate over it per input would spend the whole run in
/// ECDSA key generation rather than in the state machine under test, and
/// nothing an adversary reaches depends on which identity this is.
fn appliance() -> &'static (Vec<u8>, Arc<dyn SignOperation>) {
    static APPLIANCE_IDENTITY: OnceLock<(Vec<u8>, Arc<dyn SignOperation>)> = OnceLock::new();
    APPLIANCE_IDENTITY.get_or_init(|| {
        let identity = Identity::self_signed(
            entropy(),
            i64::try_from(NOW).unwrap_or(i64::MAX),
            CertificateKind::Onboarding,
            APPLIANCE,
        )
        .expect("the generator produces a usable identity");
        let certificate = identity.certificate().to_vec();
        (certificate, Arc::new(LocalKey::new(identity.into_key())))
    })
}

/// The node's generator behind the shared-borrow interface the library's
/// key-exchange list requires, seeded once so a run is reproducible from its
/// input alone.
fn entropy() -> &'static dyn Entropy {
    static SOURCE: OnceLock<Seeded> = OnceLock::new();
    SOURCE.get_or_init(|| Seeded(Mutex::new(Drbg::from_seed(&[0x5c; SEED_LEN]))))
}

struct Seeded(Mutex<Drbg>);

impl Entropy for Seeded {
    fn fill(&self, out: &mut [u8]) {
        self.0
            .lock()
            .expect("no harness panics holding this")
            .fill(out);
    }
}
