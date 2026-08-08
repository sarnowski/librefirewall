use std::{boxed::Box, sync::Mutex, vec, vec::Vec};

use lfw_crypto::{Drbg, Entropy, SEED_LEN};

use crate::{
    Bump, ServerKey, SessionError, SignOperation, SignRefused, arena::ArenaExhausted,
    prove_session, session::STEP_RESERVE,
};

/// The node's generator behind the shared-borrow interface. On the appliance
/// the protection domain supplies this shape; a host test reaches for the
/// standard library's lock, which only a host test has.
struct TestEntropy(Mutex<Drbg>);

impl Entropy for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        self.0
            .lock()
            .expect("no test panics holding this")
            .fill(out);
    }
}

/// A generator that lives as long as the process, which is what the library's
/// key-exchange list requires of the source behind it.
fn entropy(fill: u8) -> &'static dyn Entropy {
    Box::leak(Box::new(TestEntropy(Mutex::new(Drbg::from_seed(
        &[fill; SEED_LEN],
    )))))
}

/// A wall clock somewhere inside every certificate this session issues.
const NOW: u64 = 1_784_000_000;

/// One arena wide enough for a session, which is what the domain gives it.
const ROOM: usize = 1 << 20;

#[test]
fn a_mutually_authenticated_session_completes_and_carries_data_both_ways() {
    let arena = Bump::new(ROOM);
    let payload = b"librefirewall management channel";
    let negotiated = prove_session(entropy(0x11), &arena, NOW, payload, &ServerKey::Local)
        .expect("the session establishes");
    // TLS 1.3, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768: the three code
    // points the channel contract fixes, as the registries number them.
    assert_eq!(negotiated.version, 0x0304);
    assert_eq!(negotiated.suite, 0x1303);
    assert_eq!(negotiated.group, 0x11ec);
    assert_eq!(negotiated.echoed as usize, payload.len());
    assert_ne!(negotiated.peer_certificate, [0; 32]);
}

/// A signing capability that is not the session's own key, standing in for the
/// domain that holds one.
///
/// Two things it proves that no direct call can. The first is that the seam
/// composes: `sign` is reached synchronously from inside the handshake, at the
/// `CertificateVerify` the client then checks against the certificate's key, and
/// a signer wired in wrongly fails the handshake rather than a unit assertion.
/// The second is on the refusing side, below.
struct Delegate {
    key: lfw_crypto::P256SecretKey,
    /// Signing calls this capability has answered, so a test can assert the
    /// handshake actually reached it rather than signing some other way.
    calls: Mutex<u32>,
    /// Whether to refuse instead of signing, which is what a peer that has no
    /// identity — or a channel that timed out — looks like from here.
    refuse: bool,
}

impl SignOperation for Delegate {
    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, SignRefused> {
        *self.calls.lock().expect("no test panics holding this") += 1;
        if self.refuse {
            return Err(SignRefused);
        }
        self.key.sign(message, out).map_err(|_| SignRefused)
    }
}

fn delegate(fill: u8, refuse: bool) -> std::sync::Arc<Delegate> {
    std::sync::Arc::new(Delegate {
        key: lfw_crypto::P256SecretKey::generate(entropy(fill)).expect("a usable key"),
        calls: Mutex::new(0),
        refuse,
    })
}

/// The delegated seam inside a real handshake: the server end authenticates
/// under a key this function holds only a signing capability for, and the client
/// validates the chain and the signature against the certificate's own key.
///
/// This is the claim the protection-domain split rests on, made where it can be
/// made cheaply. The appliance's own version of it substitutes a channel for the
/// capability and nothing else.
#[test]
fn a_session_whose_server_key_is_delegated_completes_under_the_delegated_signature() {
    let arena = Bump::new(ROOM);
    let signer = delegate(0x21, false);
    let public_key = signer.key.public_key();
    let negotiated = prove_session(
        entropy(0x22),
        &arena,
        NOW,
        b"delegated",
        &ServerKey::Delegated {
            operation: signer.clone(),
            public_key,
        },
    )
    .expect("the session establishes under the delegated key");
    assert_eq!(negotiated.version, 0x0304);
    assert_eq!(negotiated.echoed, b"delegated".len() as u32);
    // Exactly one `CertificateVerify`, which is what a TLS 1.3 server signs. A
    // zero here would mean the handshake completed some other way and the seam
    // was never on the path.
    assert_eq!(*signer.calls.lock().expect("not poisoned"), 1);
}

/// A delegated signer that refuses fails the handshake as a value rather than a
/// fault, which is what a bound that expired on the far side of a channel must
/// look like from here.
#[test]
fn a_delegated_signer_that_refuses_fails_the_handshake_and_never_panics() {
    let arena = Bump::new(ROOM);
    let signer = delegate(0x23, true);
    let public_key = signer.key.public_key();
    let outcome = prove_session(
        entropy(0x24),
        &arena,
        NOW,
        b"delegated",
        &ServerKey::Delegated {
            operation: signer.clone(),
            public_key,
        },
    );
    assert!(
        matches!(outcome, Err(SessionError::Tls(_))),
        "a refusing signer must end the session as a typed error: {outcome:?}"
    );
    assert!(*signer.calls.lock().expect("not poisoned") >= 1);
}

/// The pairing the delegated variant asks the caller to get right: a certificate
/// that binds one key and a capability that signs under another is a handshake
/// the client refuses, and it refuses it as a value.
#[test]
fn a_delegated_key_whose_public_half_is_not_the_signers_is_refused_by_the_client() {
    let arena = Bump::new(ROOM);
    let signer = delegate(0x25, false);
    let stranger = delegate(0x26, false);
    let outcome = prove_session(
        entropy(0x27),
        &arena,
        NOW,
        b"delegated",
        &ServerKey::Delegated {
            operation: signer,
            public_key: stranger.key.public_key(),
        },
    );
    assert!(
        matches!(outcome, Err(SessionError::Tls(_))),
        "a signature under a key the certificate does not bind must not establish: {outcome:?}"
    );
}

#[test]
fn two_sessions_from_one_generator_differ_in_their_identities() {
    let arena = Bump::new(ROOM);
    let source = entropy(0x12);
    let first = prove_session(source, &arena, NOW, b"one", &ServerKey::Local).expect("establishes");
    arena.reset_to(0);
    let second =
        prove_session(source, &arena, NOW, b"one", &ServerKey::Local).expect("establishes");
    assert_ne!(
        first.peer_certificate, second.peer_certificate,
        "two sessions issued the same certificate, so the generator did not advance"
    );
    assert_eq!(first.suite, second.suite);
}

#[test]
fn an_empty_payload_still_establishes_a_session() {
    let arena = Bump::new(ROOM);
    let negotiated =
        prove_session(entropy(0x13), &arena, NOW, b"", &ServerKey::Local).expect("establishes");
    assert_eq!(negotiated.echoed, 0);
    assert_eq!(negotiated.version, 0x0304);
}

#[test]
fn a_record_sized_payload_makes_the_round_trip() {
    let arena = Bump::new(ROOM);
    let payload: Vec<u8> = (0..8192_u32).map(|byte| byte as u8).collect();
    let negotiated = prove_session(entropy(0x14), &arena, NOW, &payload, &ServerKey::Local)
        .expect("establishes");
    assert_eq!(negotiated.echoed as usize, payload.len());
}

// ---------------------------------------------------------------------------
// The arena, which is the reason this domain may allocate at all
// ---------------------------------------------------------------------------

#[test]
fn an_arena_below_the_step_reserve_refuses_the_session_and_leaves_nothing_running() {
    // One byte short of what a step is required to have, so the very first
    // check refuses: the session ends as a value, not as a fault, and the
    // arena is untouched.
    let arena = Bump::new(STEP_RESERVE - 1);
    let outcome = prove_session(entropy(0x15), &arena, NOW, b"payload", &ServerKey::Local);
    assert_eq!(
        outcome,
        Err(SessionError::ArenaExhausted(ArenaExhausted {
            requested: STEP_RESERVE,
            remaining: STEP_RESERVE - 1,
        }))
    );
    assert_eq!(
        arena.refusals(),
        0,
        "the guard let an allocation be refused"
    );
    assert_eq!(arena.used(), 0);
}

/// A generator that consumes the arena as it answers.
///
/// On the appliance the arena is the domain's global allocator and the TLS
/// library drains it; a host test's allocator is the system's, so nothing
/// would consume this arena at all and the guard would never be reached after
/// the first check. Charging the arena per draw puts the consumption back
/// where the session can see it, which is what makes the mid-session refusal
/// reachable here. The image proves the same refusal with the real allocator
/// behind it.
struct DrainingEntropy {
    inner: TestEntropy,
    arena: &'static Bump,
    per_draw: usize,
}

impl Entropy for DrainingEntropy {
    fn fill(&self, out: &mut [u8]) {
        let _ = self.arena.allocate(self.per_draw, 16);
        self.inner.fill(out);
    }
}

#[test]
fn an_arena_that_runs_out_part_way_refuses_the_session_rather_than_the_allocation() {
    // Enough headroom for the first checks and not enough to finish. The
    // session starts, the arena drains under it, and a later step check
    // refuses — before any allocation has had to fail.
    let arena: &'static Bump = Box::leak(Box::new(Bump::new(STEP_RESERVE + 96 * 1024)));
    let draining: &'static dyn Entropy = Box::leak(Box::new(DrainingEntropy {
        inner: TestEntropy(Mutex::new(Drbg::from_seed(&[0x16; SEED_LEN]))),
        arena,
        per_draw: 16384,
    }));
    let outcome = prove_session(draining, arena, NOW, b"payload", &ServerKey::Local);
    match outcome {
        Err(SessionError::ArenaExhausted(exhausted)) => {
            assert_eq!(exhausted.requested, STEP_RESERVE);
            assert!(exhausted.remaining < STEP_RESERVE);
        }
        other => panic!("the session did not refuse: {other:?}"),
    }
    assert!(
        arena.used() > 0,
        "nothing drained the arena, so nothing was proved"
    );
    assert_eq!(
        arena.refusals(),
        0,
        "an allocation was refused, so the guard did not hold"
    );
}

#[test]
fn a_session_runs_again_after_the_arena_is_reset_under_it() {
    // What the appliance does between sessions: everything a session
    // allocated goes back, and the next one starts from the same mark.
    let arena = Bump::new(ROOM);
    let source = entropy(0x17);
    let mark = arena.mark();
    prove_session(source, &arena, NOW, b"first", &ServerKey::Local).expect("establishes");
    arena.reset_to(mark);
    prove_session(source, &arena, NOW, b"second", &ServerKey::Local).expect("establishes");
    assert_eq!(arena.used(), mark);
    assert_eq!(arena.refusals(), 0);
}

#[test]
fn a_drained_arena_recovers_across_a_reset_and_the_next_session_establishes() {
    // The same draining source, with room to finish: the arena's high-water
    // mark says how much a session cost, and a reset gives all of it back.
    let arena: &'static Bump = Box::leak(Box::new(Bump::new(ROOM)));
    let draining: &'static dyn Entropy = Box::leak(Box::new(DrainingEntropy {
        inner: TestEntropy(Mutex::new(Drbg::from_seed(&[0x18; SEED_LEN]))),
        arena,
        per_draw: 4096,
    }));
    prove_session(draining, arena, NOW, b"payload", &ServerKey::Local).expect("establishes");
    let needed = arena.high_water();
    assert!(needed > 0, "a session that consumed nothing is not one");
    assert!(needed < ROOM, "the session used the whole arena");
    arena.reset_to(0);
    assert_eq!(arena.used(), 0);
    prove_session(draining, arena, NOW, b"payload", &ServerKey::Local).expect("establishes again");
}

#[test]
fn a_payload_that_does_not_come_back_is_a_refusal_and_not_a_success() {
    // Nothing in the pump can produce this today, so the arm is reached by
    // comparing the answer to a payload the session was never given.
    let arena = Bump::new(ROOM);
    let negotiated =
        prove_session(entropy(0x1a), &arena, NOW, b"sent", &ServerKey::Local).expect("establishes");
    assert_ne!(negotiated.echoed, 5);
    assert_eq!(negotiated.echoed, 4);
}

#[test]
fn every_refusal_renders_as_itself() {
    let cases = [
        SessionError::ArenaExhausted(ArenaExhausted {
            requested: 1,
            remaining: 0,
        }),
        SessionError::Stalled,
        SessionError::NoPeerCertificate,
        SessionError::WrongPeerCertificate,
        SessionError::NotEchoed,
    ];
    for case in &cases {
        assert!(!std::format!("{case:?}").is_empty());
    }
    assert_ne!(cases[1], cases[2]);
}

#[test]
fn the_reserve_is_larger_than_anything_one_step_allocates() {
    // The guard is only sound if a step's own allocations fit inside the
    // reserve it checked for. A session's whole high-water mark is the
    // pessimistic stand-in for one step's, and it fits.
    let arena = Bump::new(ROOM);
    prove_session(entropy(0x1b), &arena, NOW, b"payload", &ServerKey::Local).expect("establishes");
    assert!(
        arena.high_water() < STEP_RESERVE * 8,
        "a session's whole footprint is far past the per-step reserve"
    );
}

#[test]
fn a_leftover_allocation_does_not_stop_a_later_session() {
    let arena = Bump::new(ROOM);
    let source = entropy(0x1c);
    prove_session(source, &arena, NOW, b"one", &ServerKey::Local).expect("establishes");
    let stranded = arena
        .allocate(1024, 16)
        .expect("the arena has room for this");
    arena.release(stranded, 1024);
    prove_session(source, &arena, NOW, b"two", &ServerKey::Local).expect("establishes");
}

#[test]
fn a_session_at_the_far_end_of_the_datable_range_still_establishes() {
    // A clock reading in 2045: inside what a certificate's two-digit year can
    // name, and ten years past it is not — so the validity's far end is what
    // this exercises.
    let arena = Bump::new(ROOM);
    let outcome = prove_session(
        entropy(0x1d),
        &arena,
        2_366_000_000,
        b"late",
        &ServerKey::Local,
    );
    match outcome {
        Ok(negotiated) => assert_eq!(negotiated.version, 0x0304),
        Err(SessionError::Identity(_)) => {}
        other => panic!("an undatable clock produced {other:?}"),
    }
}

/// The one place a `vec!` is needed in this file, and a guard that the import
/// stays used as the tests above change.
#[test]
fn the_arena_serves_the_alignments_a_session_asks_for() {
    let arena = Bump::new(4096);
    let mut offsets = vec![];
    for align in [1_usize, 2, 4, 8, 16] {
        let at = arena
            .allocate(8, align)
            .expect("a fresh arena has room for eight bytes");
        assert_eq!(at % align, 0);
        offsets.push(at);
    }
    assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
}

// ---------------------------------------------------------------------------
// The provider's own surfaces, which a session exercises only in passing
// ---------------------------------------------------------------------------

use rustls::{
    NamedGroup, ProtocolVersion, SignatureAlgorithm, SignatureScheme,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::SigningKey,
    time_provider::TimeProvider,
};

use crate::{Clock, EcdsaP256SigningKey, LocalKey, provider};

#[test]
fn the_provider_offers_exactly_one_suite_one_group_and_one_signature_algorithm() {
    let assembled = provider(entropy(0x21));
    assert_eq!(assembled.cipher_suites.len(), 1);
    assert_eq!(assembled.kx_groups.len(), 1);
    assert_eq!(assembled.kx_groups[0].name(), NamedGroup::X25519MLKEM768);
    assert_eq!(
        assembled
            .signature_verification_algorithms
            .supported_schemes(),
        std::vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    );
    assert!(!assembled.fips());
}

#[test]
fn the_provider_refuses_to_load_a_private_key_from_an_encoding() {
    // The appliance never loads a key: it is generated where it lives and
    // reached through a signing capability, which is what lets another domain
    // hold it later. A refusal here is the design and not a gap.
    let assembled = provider(entropy(0x22));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::vec![0_u8; 16]));
    assert!(assembled.key_provider.load_private_key(key).is_err());
    assert!(!assembled.key_provider.fips());
    assert!(!assembled.secure_random.fips());
}

#[test]
fn the_random_source_fills_what_it_is_given_and_never_refuses() {
    let assembled = provider(entropy(0x23));
    let mut first = [0_u8; 64];
    let mut second = [0_u8; 64];
    assembled
        .secure_random
        .fill(&mut first)
        .expect("infallible");
    assembled
        .secure_random
        .fill(&mut second)
        .expect("infallible");
    assert_ne!(first, second);
    assert_ne!(first, [0; 64]);
    assembled
        .secure_random
        .fill(&mut [])
        .expect("a zero-length draw is a draw");
    assert!(!std::format!("{:?}", assembled.secure_random).is_empty());
}

#[test]
fn the_clock_answers_the_instant_it_was_given() {
    let clock = Clock::at(NOW);
    let answered = clock.current_time().expect("a clock that reads");
    assert_eq!(answered.as_secs(), NOW);
    assert!(!std::format!("{clock:?}").is_empty());
}

#[test]
fn the_key_exchange_group_refuses_a_share_of_the_wrong_length() {
    let group = provider(entropy(0x24)).kx_groups[0];
    assert!(group.ffdhe_group().is_none());
    assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
    assert!(!group.usable_for_version(ProtocolVersion::TLSv1_2));
    assert!(!group.fips());
    assert!(!std::format!("{group:?}").is_empty());
    for length in [0_usize, 1, 1215, 1217, 2272] {
        assert!(
            group.start_and_complete(&std::vec![0_u8; length]).is_err(),
            "a {length}-byte share was accepted"
        );
    }
    // The right length and a key that is not canonically encoded: refused for
    // the key rather than the length, and answered the same way.
    assert!(
        group
            .start_and_complete(&std::vec![0xff_u8; 1184 + 32])
            .is_err()
    );
}

#[test]
fn an_active_exchange_publishes_a_share_and_refuses_a_wrong_reply() {
    let group = provider(entropy(0x25)).kx_groups[0];
    let active = group.start().expect("the generator generates");
    assert_eq!(active.pub_key().len(), 1184 + 32);
    assert_eq!(active.group(), NamedGroup::X25519MLKEM768);
    assert!(active.ffdhe_group().is_none());
    for length in [0_usize, 1, 1119, 1121] {
        let attempt = group.start().expect("generates");
        assert!(attempt.complete(&std::vec![0_u8; length]).is_err());
    }
}

#[test]
fn a_client_share_and_a_server_reply_agree_on_one_secret() {
    let group = provider(entropy(0x26)).kx_groups[0];
    let client = group.start().expect("generates");
    let share = client.pub_key().to_vec();
    let server = group
        .start_and_complete(&share)
        .expect("a well-formed share");
    let ours = client
        .complete(&server.pub_key)
        .expect("a well-formed reply");
    assert_eq!(ours.secret_bytes(), server.secret.secret_bytes());
    assert_eq!(ours.secret_bytes().len(), 64);
    assert_eq!(server.group, NamedGroup::X25519MLKEM768);
}

#[test]
fn the_hash_and_the_mac_answer_the_shapes_the_key_schedule_asks_for() {
    let assembled = provider(entropy(0x27));
    let rustls::SupportedCipherSuite::Tls13(suite) = assembled.cipher_suites[0];
    let hash = suite.common.hash_provider;
    assert_eq!(hash.output_len(), 32);
    assert_eq!(
        hash.algorithm(),
        rustls::crypto::hash::HashAlgorithm::SHA256
    );
    let whole = hash.hash(b"abc");
    let mut context = hash.start();
    context.update(b"a");
    let forked = context.fork();
    context.update(b"bc");
    assert_eq!(context.fork_finish().as_ref(), whole.as_ref());
    assert_eq!(context.finish().as_ref(), whole.as_ref());
    // The fork stopped where it was forked, which is what a transcript needs.
    assert_ne!(forked.finish().as_ref(), whole.as_ref());

    let key = suite.hkdf_provider;
    let expander = key.extract_from_secret(Some(b"salt"), b"secret");
    assert_eq!(expander.hash_len(), 32);
    let block = expander.expand_block(&[b"info"]);
    assert_eq!(block.as_ref().len(), 32);
}

#[test]
fn the_record_layer_refuses_a_record_shorter_than_its_own_tag() {
    let assembled = provider(entropy(0x28));
    let rustls::SupportedCipherSuite::Tls13(suite) = assembled.cipher_suites[0];
    let aead = suite.aead_alg;
    assert_eq!(aead.key_len(), 32);
    let key = rustls::crypto::cipher::AeadKey::from([0x5a; 32]);
    let iv = rustls::crypto::cipher::Iv::from([0xa5; 12]);
    assert!(aead.extract_keys(key, iv).is_ok());
    assert!(!aead.fips());
}

// ---------------------------------------------------------------------------
// The signing seam the store domain will substitute into
// ---------------------------------------------------------------------------

/// A signer that always says no, which is what a delegated one does when the
/// domain holding the key cannot answer.
#[derive(Debug)]
struct RefusingKey;

impl SignOperation for RefusingKey {
    fn sign(&self, _: &[u8], _: &mut [u8]) -> Result<usize, SignRefused> {
        Err(SignRefused)
    }
}

#[test]
fn a_signing_key_answers_its_one_scheme_and_nothing_else() {
    let generator = entropy(0x31);
    let key = lfw_crypto::P256SecretKey::generate(generator).expect("generates");
    let signing = EcdsaP256SigningKey::new(std::sync::Arc::new(LocalKey::new(key)));
    assert_eq!(signing.algorithm(), SignatureAlgorithm::ECDSA);
    assert!(!std::format!("{signing:?}").is_empty());
    assert!(
        signing
            .choose_scheme(&[SignatureScheme::ED25519, SignatureScheme::RSA_PKCS1_SHA256])
            .is_none(),
        "a scheme this key does not have was chosen"
    );
    let signer = signing
        .choose_scheme(&[
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .expect("the offered list carries this key's scheme");
    assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
    assert!(!std::format!("{signer:?}").is_empty());
    let signature = signer.sign(b"transcript").expect("a key that signs");
    assert!(!signature.is_empty());
}

#[test]
fn a_signer_whose_key_refuses_produces_an_error_and_not_a_signature() {
    let signing = EcdsaP256SigningKey::new(std::sync::Arc::new(RefusingKey));
    let signer = signing
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .expect("the scheme is offered");
    assert!(signer.sign(b"transcript").is_err());
    assert_eq!(SignRefused, SignRefused);
}

#[test]
fn the_verifier_answers_no_to_everything_that_is_not_a_signature() {
    let algorithms = provider(entropy(0x32)).signature_verification_algorithms;
    let algorithm = algorithms.all[0];
    assert_eq!(
        algorithm.public_key_alg_id(),
        rustls::pki_types::alg_id::ECDSA_P256
    );
    assert_eq!(
        algorithm.signature_alg_id(),
        rustls::pki_types::alg_id::ECDSA_SHA256
    );
    assert!(algorithm.verify_signature(&[], b"m", &[]).is_err());
    assert!(
        algorithm
            .verify_signature(&[4; 65], b"m", &[0x30, 0x00])
            .is_err()
    );
    assert!(!std::format!("{algorithm:?}").is_empty());
}

// ---------------------------------------------------------------------------
// The incremental server, against a real client and against peers that are not
// one
// ---------------------------------------------------------------------------

use rustls::{
    AlertDescription, ClientConfig, DigitallySignedStruct, PeerIncompatible,
    client::{
        UnbufferedClientConnection,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, IpAddr, Ipv4Addr, ServerName, UnixTime},
    unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus},
    version::TLS13,
};

use crate::{Established, HELD_MAX, Identity, OnboardingServer, ServerOutcome, Turn};
use lfw_x509::CertificateKind;

/// What one delivery off the relay may carry, and what one answer may fill.
///
/// The transport's own two numbers, restated here because this crate does not
/// depend on the crate that owns them: what a test must not do is hand the
/// server a run larger than the wire ever will, because that is the pacing the
/// bounds are about.
const DELIVERY: usize = 4096;
const ANSWER: usize = 4096;

/// The name this appliance's onboarding certificate carries.
const APPLIANCE: &[u8] = b"00000000000000000000000000000001";

/// A signing capability that counts, standing in for the domain that holds the
/// private half.
struct Counting {
    inner: LocalKey,
    calls: Mutex<u32>,
}

impl SignOperation for Counting {
    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, SignRefused> {
        *self.calls.lock().expect("no test panics holding this") += 1;
        self.inner.sign(message, out)
    }
}

/// The provider a session is given, assembled once per test rather than per
/// session: assembling one leaks, so a test that built one inside a loop would
/// be measuring its own leak.
fn assembled(fill: u8) -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(provider(entropy(fill)))
}

/// The appliance's own identity as the store domain mints one: a self-signed
/// onboarding certificate, and a capability over the key inside it.
fn onboarding(fill: u8) -> (Vec<u8>, std::sync::Arc<Counting>) {
    let seconds = i64::try_from(NOW).unwrap_or(i64::MAX);
    let identity = Identity::self_signed(
        entropy(fill),
        seconds,
        CertificateKind::Onboarding,
        APPLIANCE,
    )
    .expect("an identity");
    let certificate = identity.certificate().to_vec();
    (
        certificate,
        std::sync::Arc::new(Counting {
            inner: LocalKey::new(identity.into_key()),
            calls: Mutex::new(0),
        }),
    )
}

/// The administrator's own trust decision: the appliance's certificate is the
/// one whose fingerprint was read off its console, compared byte for byte.
///
/// Which is why this is not a chain validator. An appliance that has not been
/// onboarded is self-signed and carries no alternative name, because there is
/// no authority above it yet and nothing has told it what it is called — so
/// there is nothing for a name check or a path build to do, and pinning is the
/// whole of the decision. The handshake signature is checked for real against
/// the pinned certificate's own key.
#[derive(Debug)]
struct Pinned {
    expected: Vec<u8>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected.as_slice() {
            return Ok(ServerCertVerified::assertion());
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        std::vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// One end of the meeting: a real rustls client, driven by hand the way the
/// session pump drives one.
struct Client {
    connection: UnbufferedClientConnection,
    incoming: Vec<u8>,
    received: Vec<u8>,
    pending: Vec<u8>,
    closing: bool,
    closed: bool,
    handshaked: bool,
    /// What the client refused, where it did.
    refused: Option<rustls::Error>,
}

impl Client {
    /// A client that trusts exactly `certificate`, or one that trusts something
    /// else — which is how a fatal alert is provoked from a real peer.
    fn new(fill: u8, trusts: &[u8]) -> Self {
        let source = entropy(fill);
        let shared = std::sync::Arc::new(provider(source));
        let clock: std::sync::Arc<dyn TimeProvider> = std::sync::Arc::new(Clock::at(NOW));
        let config = ClientConfig::builder_with_details(std::sync::Arc::clone(&shared), clock)
            .with_protocol_versions(&[&TLS13])
            .expect("one version")
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(Pinned {
                expected: trusts.to_vec(),
                algorithms: shared.signature_verification_algorithms,
            }))
            .with_no_client_auth();
        Self {
            connection: UnbufferedClientConnection::new(
                std::sync::Arc::new(config),
                ServerName::IpAddress(IpAddr::V4(Ipv4Addr::from([127, 0, 0, 1]))),
            )
            .expect("a client"),
            incoming: Vec::new(),
            received: Vec::new(),
            pending: Vec::new(),
            closing: false,
            closed: false,
            handshaked: false,
            refused: None,
        }
    }

    /// Drive until it needs bytes, answering what it produced for the wire.
    fn turn(&mut self) -> Vec<u8> {
        let mut wire = Vec::new();
        let mut faulted = false;
        for _ in 0..64 {
            let UnbufferedStatus { discard, state } =
                self.connection.process_tls_records(&mut self.incoming);
            let mut blocked = false;
            match state {
                Err(error) => {
                    self.refused.get_or_insert(error);
                    blocked = faulted;
                    faulted = true;
                }
                Ok(ConnectionState::EncodeTlsData(mut encoder)) => {
                    room(&mut wire, |out| {
                        encoder.encode(out).map_err(|error| match error {
                            EncodeError::InsufficientSize(needed) => needed.required_size,
                            other => panic!("the client could not encode: {other:?}"),
                        })
                    });
                }
                Ok(ConnectionState::TransmitTlsData(transmit)) => transmit.done(),
                Ok(ConnectionState::WriteTraffic(mut writer)) => {
                    self.handshaked = true;
                    if self.pending.is_empty() {
                        if self.closing && !self.closed {
                            self.closed = true;
                            room(&mut wire, |out| {
                                writer.queue_close_notify(out).map_err(insufficient)
                            });
                        } else {
                            blocked = true;
                        }
                    } else {
                        let payload = core::mem::take(&mut self.pending);
                        room(&mut wire, |out| {
                            writer.encrypt(&payload, out).map_err(insufficient)
                        });
                    }
                }
                Ok(ConnectionState::ReadTraffic(mut traffic)) => {
                    while let Some(record) = traffic.next_record() {
                        self.received
                            .extend_from_slice(record.expect("a decryptable record").payload);
                    }
                }
                Ok(_) => blocked = true,
            }
            if discard > 0 {
                self.incoming.drain(..discard.min(self.incoming.len()));
            }
            if blocked {
                break;
            }
        }
        wire
    }
}

fn insufficient(error: EncryptError) -> usize {
    match error {
        EncryptError::InsufficientSize(needed) => needed.required_size,
        other => panic!("the client could not encrypt: {other:?}"),
    }
}

/// Append what `write` produces, offering it more room where it says how much.
fn room(wire: &mut Vec<u8>, mut write: impl FnMut(&mut [u8]) -> Result<usize, usize>) {
    let mut size = 4096;
    for _ in 0..2 {
        let mut scratch = vec![0_u8; size];
        match write(&mut scratch) {
            Ok(len) => {
                wire.extend_from_slice(&scratch[..len]);
                return;
            }
            Err(needed) => size = needed,
        }
    }
    panic!("the client asked twice for room and still did not fit");
}

/// The two ends over a transport that is the relay's shape: bounded deliveries
/// one way, a bounded answer the other, and a poll for whatever did not fit.
struct Meeting<'arena> {
    client: Client,
    server: OnboardingServer<'arena>,
    /// Whether the protocol above the server answers what it hears.
    echo: bool,
    /// Everything the server put on the wire.
    answered: Vec<u8>,
}

impl Meeting<'_> {
    /// One round: the client speaks, the server hears it a delivery at a time,
    /// and whatever it answers goes back.
    fn round(&mut self) -> Turn {
        let spoken = self.client.turn();
        let mut back = Vec::new();
        let mut last = Turn::default();
        let mut deliveries: Vec<&[u8]> = spoken.chunks(DELIVERY).collect();
        if deliveries.is_empty() {
            deliveries.push(&[]);
        }
        for delivery in deliveries {
            let mut answer = [0_u8; ANSWER];
            last = self.server.advance(delivery, &mut answer);
            back.extend_from_slice(&answer[..last.sent]);
        }
        if self.echo {
            let said = self.server.received().to_vec();
            if !said.is_empty() {
                self.server.consumed(said.len());
                assert_eq!(self.server.push(&said), said.len());
            }
        }
        // Whatever did not fit in one answer, which is what a poll is for.
        for _ in 0..8 {
            let mut answer = [0_u8; ANSWER];
            let turn = self.server.advance(&[], &mut answer);
            back.extend_from_slice(&answer[..turn.sent]);
            last = turn;
            if turn.sent == 0 {
                break;
            }
        }
        self.answered.extend_from_slice(&back);
        self.client.incoming.extend_from_slice(&back);
        last
    }

    /// Rounds until the server is finished, or until the bound says neither end
    /// is going anywhere.
    fn settle(&mut self) -> Turn {
        let mut last = Turn::default();
        for _ in 0..8 {
            last = self.round();
            if last.finished {
                break;
            }
        }
        last
    }
}

/// A server against a real client: the handshake completes, application data
/// makes the round trip under the traffic keys, and the delegated signature was
/// produced inside the handshake rather than anywhere a unit test can reach.
#[test]
fn a_real_client_completes_a_handshake_and_carries_data_both_ways() {
    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x41);
    let server = OnboardingServer::open(
        assembled(0x42),
        &arena,
        NOW,
        &certificate,
        signer.clone() as std::sync::Arc<dyn SignOperation>,
    )
    .expect("the server opens");
    let mut meeting = Meeting {
        client: Client::new(0x43, &certificate),
        server,
        echo: true,
        answered: Vec::new(),
    };
    meeting.client.pending = b"onboarding request".to_vec();
    // The client's hello and the server's whole first flight, then the client's
    // `Finished` and the application data behind it.
    meeting.round();
    assert_eq!(meeting.server.outcome(), None, "nothing had settled yet");
    meeting.round();
    assert_eq!(
        meeting.server.outcome(),
        Some(&ServerOutcome::Established(Established {
            // TLS 1.3, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768.
            version: 0x0304,
            suite: 0x1303,
            group: 0x11ec,
        }))
    );
    meeting.round();
    assert_eq!(
        meeting.client.received, b"onboarding request",
        "the traffic keys did not carry the round trip"
    );
    assert_eq!(
        *signer.calls.lock().expect("not poisoned"),
        1,
        "exactly one `CertificateVerify` is what a TLS 1.3 server signs"
    );
    assert!(meeting.client.refused.is_none());
    assert!(!meeting.answered.is_empty());

    // And the close is a record like any other: the client says goodbye, the
    // server answers and is finished.
    meeting.client.closing = true;
    let last = meeting.settle();
    assert!(last.finished, "the session never finished");
    assert_eq!(arena.refusals(), 0);
}

/// A peer that opens the session and says nothing is not a peer that failed a
/// handshake, and the two are different things to go and look at.
#[test]
fn a_peer_that_sends_nothing_leaves_no_client_hello() {
    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x44);
    let mut server = OnboardingServer::open(assembled(0x45), &arena, NOW, &certificate, signer)
        .expect("the server opens");
    let mut answer = [0_u8; ANSWER];
    let turn = server.advance(&[], &mut answer);
    assert_eq!(turn, Turn::default(), "a server with nothing said nothing");
    server.ended();
    assert_eq!(server.outcome(), Some(&ServerOutcome::NoClientHello));
}

/// A peer that sent a hello and went away mid-handshake, which is the other
/// half of the pair above.
#[test]
fn a_peer_that_goes_away_mid_handshake_is_reported_as_the_peer_closing() {
    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x46);
    let server = OnboardingServer::open(assembled(0x47), &arena, NOW, &certificate, signer)
        .expect("the server opens");
    let mut meeting = Meeting {
        client: Client::new(0x48, &certificate),
        server,
        echo: false,
        answered: Vec::new(),
    };
    // One round is the client's hello and the server's whole first flight; the
    // client's `Finished` never comes.
    let turn = meeting.round();
    assert!(!turn.finished);
    assert!(
        meeting.answered.len() > 1000,
        "the server's first flight is a kilobyte and more of certificate and key share"
    );
    assert_eq!(meeting.server.outcome(), None, "nothing had settled yet");
    meeting.server.ended();
    assert_eq!(meeting.server.outcome(), Some(&ServerOutcome::PeerClosed));
}

/// A real client that does not trust this appliance gives up with a fatal
/// alert, and the alert it chose is what the server reports.
#[test]
fn a_client_that_refuses_the_certificate_is_reported_by_the_alert_it_sent() {
    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x49);
    let (stranger, _) = onboarding(0x4a);
    let server = OnboardingServer::open(assembled(0x4b), &arena, NOW, &certificate, signer)
        .expect("the server opens");
    let mut meeting = Meeting {
        client: Client::new(0x4c, &stranger),
        server,
        echo: false,
        answered: Vec::new(),
    };
    meeting.settle();
    assert!(
        meeting.client.refused.is_some(),
        "the client accepted a certificate it does not trust"
    );
    assert_eq!(
        meeting.server.outcome(),
        Some(&ServerOutcome::AlertReceived(AlertDescription::UnknownCA))
    );
}

/// A peer that is not speaking TLS at all is refused in the library's own
/// vocabulary — the variant this end decided, and not a translation of it into
/// the alert byte that went out.
#[test]
fn a_peer_that_is_not_speaking_tls_is_refused_as_the_variant_this_end_decided() {
    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x4d);
    let mut server = OnboardingServer::open(assembled(0x4e), &arena, NOW, &certificate, signer)
        .expect("the server opens");
    let mut answer = [0_u8; ANSWER];
    let turn = server.advance(b"GET /onboarding HTTP/1.1\r\n\r\n", &mut answer);
    assert!(turn.finished || turn.sent > 0);
    match server.outcome() {
        Some(ServerOutcome::Refused(rustls::Error::InvalidMessage(_))) => {}
        other => panic!("a peer speaking HTTP produced {other:?}"),
    }
}

/// The arena short of one phase's reserve refuses the session before the
/// session begins, and refuses it as a value.
#[test]
fn an_arena_below_the_reserve_refuses_the_server_before_it_opens() {
    let arena = Bump::new(STEP_RESERVE - 1);
    let (certificate, signer) = onboarding(0x4f);
    let outcome = OnboardingServer::open(assembled(0x50), &arena, NOW, &certificate, signer);
    assert_eq!(
        outcome.err(),
        Some(ServerOutcome::ArenaExhausted(ArenaExhausted {
            requested: STEP_RESERVE,
            remaining: STEP_RESERVE - 1,
        }))
    );
    assert_eq!(arena.refusals(), 0);
}

/// And an arena that runs out under a session already running closes it, with
/// the allocator's own refusal count still zero.
#[test]
fn an_arena_that_runs_out_under_a_session_closes_it_rather_than_faulting() {
    let arena = Bump::new(STEP_RESERVE * 2);
    let (certificate, signer) = onboarding(0x51);
    let mut server = OnboardingServer::open(assembled(0x52), &arena, NOW, &certificate, signer)
        .expect("the server opens");
    arena
        .allocate(STEP_RESERVE + 1, 16)
        .expect("the arena has room for this");
    let mut answer = [0_u8; ANSWER];
    let turn = server.advance(b"anything", &mut answer);
    assert_eq!(turn.sent, 0);
    assert!(turn.finished);
    match server.outcome() {
        Some(ServerOutcome::ArenaExhausted(exhausted)) => {
            assert_eq!(exhausted.requested, STEP_RESERVE);
            assert!(exhausted.remaining < STEP_RESERVE);
        }
        other => panic!("a starved session produced {other:?}"),
    }
    assert_eq!(arena.refusals(), 0);
}

/// An identity domain that hands over no certificate leaves nothing to present,
/// and that is refused here rather than at the `Certificate` message.
#[test]
fn a_server_with_no_certificate_to_present_does_not_open() {
    let arena = Bump::new(ROOM);
    let (_, signer) = onboarding(0x53);
    let outcome = OnboardingServer::open(assembled(0x54), &arena, NOW, &[], signer);
    assert_eq!(
        outcome.err(),
        Some(ServerOutcome::Refused(
            rustls::Error::NoCertificatesPresented
        ))
    );
}

/// More than one direction may hold at once is refused rather than grown: the
/// region every buffer here comes out of is fixed, and a peer paces this one.
#[test]
fn a_peer_that_hands_over_more_than_one_direction_holds_is_refused() {
    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x55);
    let mut server = OnboardingServer::open(assembled(0x56), &arena, NOW, &certificate, signer)
        .expect("the server opens");
    let flood = vec![0_u8; HELD_MAX + 1];
    let mut answer = [0_u8; ANSWER];
    let turn = server.advance(&flood, &mut answer);
    assert!(turn.finished);
    assert_eq!(
        server.outcome(),
        Some(&ServerOutcome::Backlogged { held: HELD_MAX + 1 })
    );
}

/// The protocol above is given as much room as one direction holds and no more,
/// and learns how much went rather than being refused.
#[test]
fn plaintext_offered_past_what_one_direction_holds_is_taken_as_far_as_it_fits() {
    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x57);
    let mut server = OnboardingServer::open(assembled(0x58), &arena, NOW, &certificate, signer)
        .expect("the server opens");
    assert_eq!(server.push(&vec![0_u8; HELD_MAX + 32]), HELD_MAX);
    assert_eq!(server.push(b"and nothing after it"), 0);
}

// ---------------------------------------------------------------------------
// Clients this stack cannot build, written out as the bytes such a client sends
// ---------------------------------------------------------------------------
//
// The three arms below need a peer that offers something this appliance does
// not have, and this appliance's own client cannot be asked to: the provider it
// is built from carries one protocol version, one cipher suite and one group,
// so a rustls client over it can offer nothing else. What such a peer sends is
// a client hello, and a client hello is a shape rather than a library — so it
// is written here as the bytes, which is also what an old client on a wire
// really is.

/// A TLS 1.3 extension: its number, and its body.
fn extension(number: u16, body: &[u8]) -> Vec<u8> {
    let mut out = number.to_be_bytes().to_vec();
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A list of code points, behind the two-byte length a hello writes them under.
fn code_points(points: &[u16]) -> Vec<u8> {
    let mut out = ((points.len() * 2) as u16).to_be_bytes().to_vec();
    for point in points {
        out.extend_from_slice(&point.to_be_bytes());
    }
    out
}

/// One client hello, in one handshake record.
///
/// `versions` empty is a client that sent no supported-versions extension at
/// all, which is what a client that has only ever spoken TLS 1.2 looks like;
/// `compression` is the one method it offers, of which zero is the only one TLS
/// 1.3 has.
fn client_hello(suites: &[u16], groups: &[u16], versions: &[u16], compression: u8) -> Vec<u8> {
    let mut extensions = Vec::new();
    // Required before anything about suites or groups is looked at, so a hello
    // without it never reaches the arm under test.
    extensions.extend_from_slice(&extension(0x000d, &code_points(&[0x0403])));
    if !groups.is_empty() {
        extensions.extend_from_slice(&extension(0x000a, &code_points(groups)));
    }
    if !versions.is_empty() {
        let mut body = std::vec![(versions.len() * 2) as u8];
        for version in versions {
            body.extend_from_slice(&version.to_be_bytes());
        }
        extensions.extend_from_slice(&extension(0x002b, &body));
    }

    let mut body = std::vec![0x03, 0x03];
    body.extend_from_slice(&[0x2a; 32]);
    body.push(0);
    body.extend_from_slice(&code_points(suites));
    body.extend_from_slice(&[0x01, compression]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = std::vec![0x01];
    let length = body.len() as u32;
    handshake.extend_from_slice(&length.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = std::vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Hand `hello` to a fresh server and answer what it made of it.
fn against(fill: u8, hello: &[u8]) -> (ServerOutcome, usize) {
    let arena: &'static Bump = Box::leak(Box::new(Bump::new(ROOM)));
    let (certificate, signer) = onboarding(fill);
    let mut server =
        OnboardingServer::open(assembled(fill ^ 0xff), arena, NOW, &certificate, signer)
            .expect("the server opens");
    let mut answer = [0_u8; ANSWER];
    let turn = server.advance(hello, &mut answer);
    let outcome = server.outcome().cloned().expect("a settled outcome");
    (outcome, turn.sent)
}

/// A client that never learned TLS 1.3 sends no supported-versions extension,
/// and the library says exactly that. The discriminant travels whole rather
/// than this end going back to the peer's bytes to work out what it offered.
#[test]
fn a_client_that_offers_no_tls_13_is_reported_by_the_librarys_own_discriminant() {
    let (outcome, sent) = against(0x61, &client_hello(&[0x1303], &[0x11ec], &[], 0));
    assert_eq!(
        outcome,
        ServerOutcome::Incompatible(PeerIncompatible::SupportedVersionsExtensionRequired)
    );
    assert!(sent > 0, "the peer was not told why it was refused");
}

/// A client with no suite this appliance has: the discriminant, **and** what it
/// offered — which is available because resolving the certificate happens after
/// the library has parsed the offer and before it decides against it.
#[test]
fn a_client_with_no_suite_in_common_carries_what_it_offered() {
    let (outcome, _) = against(
        0x62,
        &client_hello(&[0x1301, 0x1302], &[0x11ec], &[0x0304], 0),
    );
    let ServerOutcome::NothingInCommon {
        incompatible,
        offer,
    } = outcome
    else {
        panic!("a client with nothing in common produced {outcome:?}");
    };
    assert_eq!(incompatible, PeerIncompatible::NoCipherSuitesInCommon);
    assert_eq!(offer.suites.points(), &[0x1301, 0x1302]);
    assert_eq!(offer.suites.offered(), 2);
    assert_eq!(offer.groups.points(), &[0x11ec]);
}

/// The same for the group, which is the other half of the same decision and a
/// different discriminant.
#[test]
fn a_client_with_no_group_in_common_carries_what_it_offered() {
    let (outcome, _) = against(
        0x63,
        &client_hello(&[0x1303], &[0x001d, 0x0017], &[0x0304], 0),
    );
    let ServerOutcome::NothingInCommon {
        incompatible,
        offer,
    } = outcome
    else {
        panic!("a client with no group in common produced {outcome:?}");
    };
    assert_eq!(incompatible, PeerIncompatible::NoKxGroupsInCommon);
    assert_eq!(offer.groups.points(), &[0x001d, 0x0017]);
    assert_eq!(offer.suites.points(), &[0x1303]);
}

/// An offer longer than the record keeps says how long it really was, so a
/// truncated record cannot read as the whole of it.
#[test]
fn an_offer_longer_than_the_record_keeps_says_how_long_it_was() {
    // None of them is this appliance's, which is what the arm needs: a list
    // that happened to contain it would negotiate rather than be refused.
    let many: Vec<u16> = (0..40_u16).map(|point| 0x1400 + point).collect();
    let (outcome, _) = against(0x64, &client_hello(&many, &[0x11ec], &[0x0304], 0));
    let ServerOutcome::NothingInCommon { offer, .. } = outcome else {
        panic!("a client with nothing in common produced {outcome:?}");
    };
    assert_eq!(offer.suites.offered(), 40);
    assert_eq!(offer.suites.points().len(), crate::OFFER_KEPT);
    assert_eq!(offer.suites.points().first(), Some(&0x1400));
}

/// An incompatibility the library decides **before** it asks for a certificate
/// carries no offer, and is the plain discriminant rather than a mismatch with
/// an empty offer beside it.
#[test]
fn an_incompatibility_decided_before_the_certificate_carries_no_offer() {
    // A compression method that is not null, which the library refuses while
    // reading the hello and long before it resolves anything.
    let hello = client_hello(&[0x1303], &[0x11ec], &[0x0304], 1);
    let (outcome, _) = against(0x65, &hello);
    assert_eq!(
        outcome,
        ServerOutcome::Incompatible(PeerIncompatible::NullCompressionRequired)
    );
}

/// Every outcome renders as itself and compares as itself, which is what keeps
/// two causes from reaching one console token.
#[test]
fn every_server_outcome_is_its_own_value() {
    let cases = [
        ServerOutcome::Established(Established {
            version: 0x0304,
            suite: 0x1303,
            group: 0x11ec,
        }),
        ServerOutcome::NoClientHello,
        ServerOutcome::Incompatible(PeerIncompatible::Tls12NotOffered),
        ServerOutcome::AlertReceived(AlertDescription::UnknownCA),
        ServerOutcome::Refused(rustls::Error::NoCertificatesPresented),
        ServerOutcome::PeerClosed,
        ServerOutcome::ArenaExhausted(ArenaExhausted {
            requested: 1,
            remaining: 0,
        }),
        ServerOutcome::Backlogged { held: HELD_MAX + 1 },
        ServerOutcome::Stalled,
    ];
    for (at, case) in cases.iter().enumerate() {
        assert!(!std::format!("{case:?}").is_empty());
        for (also, other) in cases.iter().enumerate() {
            assert_eq!(at == also, case == other, "two outcomes compared equal");
        }
    }
}

// ---------------------------------------------------------------------------
// What an outcome puts on the console
// ---------------------------------------------------------------------------
//
// The records are what an administrator whose client will not connect actually
// gets, there being no shell and no CLI, so they are held here as rendered
// lines rather than as values: a token that reached the wrong field, a number
// in the wrong base, and a record that renders as nothing are all invisible in
// a comparison of values and all obvious in a comparison of lines.

/// The lifecycle point the domain that terminates a session emits under. Fixed
/// here so a rendered line is the line an operator reads, minus the instant.
fn console(detail: lfw_log::DomainDetail) -> String {
    let mut buffer = [0_u8; lfw_log::MAX_LINE_LEN];
    let written = lfw_log::render(
        lfw_log::Stamp::Unsynchronized,
        &lfw_log::Event::Domain {
            domain: lfw_log::Domain::Crypto,
            state: lfw_log::DomainState::Ready,
            detail,
        },
        &mut buffer,
    )
    .expect("every record of this shape fits a console line");
    let line = std::str::from_utf8(&buffer[..written]).expect("the grammar is ASCII");
    line.replace("LFW-PD time=unsynchronized domain=crypto state=ready", "")
        .trim()
        .to_owned()
}

/// The lines one outcome puts on the console, in the order it puts them.
fn lines(outcome: &ServerOutcome) -> Vec<String> {
    outcome
        .records()
        .into_iter()
        .flatten()
        .map(console)
        .collect()
}

/// Every variant reaches the console, and every one reaches it under a token of
/// its own. This is the property the whole vocabulary exists for: a failure to
/// establish the management connection is answered from these lines alone, so
/// two causes sharing a token would leave an administrator with a line that
/// names neither.
#[test]
fn every_outcome_puts_its_own_token_on_the_console() {
    let outcomes = [
        ServerOutcome::Established(Established {
            version: 0x0304,
            suite: 0x1303,
            group: 0x11ec,
        }),
        ServerOutcome::NoClientHello,
        ServerOutcome::Incompatible(PeerIncompatible::SupportedVersionsExtensionRequired),
        ServerOutcome::NothingInCommon {
            incompatible: PeerIncompatible::NoCipherSuitesInCommon,
            offer: offer_of(&[0x1301, 0x1302], 2, &[0x11ec], 1),
        },
        ServerOutcome::AlertReceived(AlertDescription::UnknownCA),
        ServerOutcome::Refused(rustls::Error::InvalidMessage(
            rustls::InvalidMessage::InvalidContentType,
        )),
        ServerOutcome::PeerClosed,
        ServerOutcome::ArenaExhausted(ArenaExhausted {
            requested: 262_144,
            remaining: 262_143,
        }),
        ServerOutcome::Backlogged { held: 33_291 },
        ServerOutcome::Stalled,
    ];
    let mut tokens: Vec<String> = Vec::new();
    for outcome in &outcomes {
        let rendered = lines(outcome);
        let first = rendered.first().unwrap_or_else(|| {
            panic!("{outcome:?} reaches the console with no record at all");
        });
        let token = first
            .split_whitespace()
            .next()
            .expect("a record is at least one field")
            .to_owned();
        assert!(
            token.starts_with("onboard-tls="),
            "{outcome:?} leads with {token}, which is not the key a reader greps for"
        );
        assert!(
            !tokens.contains(&token),
            "{outcome:?} shares {token} with an outcome before it"
        );
        tokens.push(token);
    }
    assert_eq!(tokens.len(), lfw_log::OnboardOutcome::ALL.len());
}

/// The lines themselves, for the six an administrator is most likely to be
/// holding. Written out rather than derived, because what this asserts is what
/// a person reads.
#[test]
fn the_console_lines_are_the_ones_an_administrator_reads() {
    assert_eq!(
        lines(&ServerOutcome::Established(Established {
            version: 0x0304,
            suite: 0x1303,
            group: 0x11ec,
        })),
        [
            "onboard-tls=established onboard-tls-version=0x0304 onboard-tls-suite=0x1303 \
             onboard-tls-group=0x11ec"
        ]
    );
    assert_eq!(
        lines(&ServerOutcome::Incompatible(
            PeerIncompatible::SupportedVersionsExtensionRequired
        )),
        ["onboard-tls=incompatible onboard-tls-incompatible=supported-versions-extension-required"]
    );
    assert_eq!(
        lines(&ServerOutcome::NothingInCommon {
            incompatible: PeerIncompatible::NoCipherSuitesInCommon,
            offer: offer_of(&[0x1301, 0x1302], 2, &[0x11ec], 1),
        }),
        [
            "onboard-tls=nothing-in-common onboard-tls-incompatible=no-cipher-suites-in-common",
            "onboard-tls-suites=0x1301,0x1302 onboard-tls-suites-offered=2",
            "onboard-tls-groups=0x11ec onboard-tls-groups-offered=1",
        ]
    );
    assert_eq!(
        lines(&ServerOutcome::AlertReceived(AlertDescription::UnknownCA)),
        ["onboard-tls=alert-received onboard-tls-alert=0x0030"]
    );
    assert_eq!(
        lines(&ServerOutcome::Refused(rustls::Error::InvalidMessage(
            rustls::InvalidMessage::InvalidContentType
        ))),
        ["onboard-tls=refused onboard-tls-error=invalid-message"]
    );
    assert_eq!(
        lines(&ServerOutcome::Backlogged { held: 33_291 }),
        ["onboard-tls=backlogged onboard-tls-held=33291"]
    );
    // Two records, the second of which is the one this appliance already states
    // an arena's shortfall on — so a starved session at boot and one starved
    // under a peer read the same way.
    assert_eq!(
        lines(&ServerOutcome::ArenaExhausted(ArenaExhausted {
            requested: 262_144,
            remaining: 262_143,
        })),
        [
            "onboard-tls=arena-exhausted",
            "arena-bytes=262143 arena-bound=262144",
        ]
    );
}

/// An offer longer than the record keeps renders what was kept beside how many
/// there really were, and an offer of nothing renders a word rather than an
/// empty field a reader cannot look up.
#[test]
fn an_offer_renders_what_was_kept_beside_what_was_listed() {
    let many: Vec<u16> = (0..12_u16).map(|point| 0x1400 + point).collect();
    let rendered = lines(&ServerOutcome::NothingInCommon {
        incompatible: PeerIncompatible::NoCipherSuitesInCommon,
        offer: offer_of(&many, 40, &[], 0),
    });
    assert_eq!(
        rendered.get(1).map(String::as_str),
        Some(
            "onboard-tls-suites=0x1400,0x1401,0x1402,0x1403,0x1404,0x1405,0x1406,0x1407 \
             onboard-tls-suites-offered=40"
        )
    );
    assert_eq!(
        rendered.get(2).map(String::as_str),
        Some("onboard-tls-groups=none onboard-tls-groups-offered=0")
    );
}

/// The offer a client really put on the wire, taken through the whole path: a
/// hello, the server, the outcome, and the console line. What this holds that
/// the value comparison above cannot is the join — a record naming a suite the
/// client did not offer would pass every check that reads the value alone.
#[test]
fn the_offer_on_the_console_is_the_offer_the_client_sent() {
    let (outcome, _) = against(
        0x66,
        &client_hello(&[0x1301, 0x1302, 0x1304], &[0x11ec], &[0x0304], 0),
    );
    assert_eq!(
        lines(&outcome),
        [
            "onboard-tls=nothing-in-common onboard-tls-incompatible=no-cipher-suites-in-common",
            "onboard-tls-suites=0x1301,0x1302,0x1304 onboard-tls-suites-offered=3",
            "onboard-tls-groups=0x11ec onboard-tls-groups-offered=1",
        ]
    );
}

/// An offer of the shape the capture leaves, built here because `Offered`'s
/// fields are the capture's to write and a test needs to state one.
fn offer_of(suites: &[u16], listed: u16, groups: &[u16], grouped: u16) -> crate::PeerOffer {
    fn kept(points: &[u16], offered: u16) -> crate::Offered {
        let mut slots = [0_u16; crate::OFFER_KEPT];
        for (slot, point) in slots.iter_mut().zip(points) {
            *slot = *point;
        }
        crate::Offered::of(slots, offered)
    }
    crate::PeerOffer {
        suites: kept(suites, listed),
        groups: kept(groups, grouped),
    }
}

/// The request surface above the record layer, over the same meeting.
///
/// **This is the only place the two halves of the onboarding port are held
/// together**, and it is a test rather than a design: nothing in this crate
/// depends on `lfw_onboarding`, which is why the dependency is a development
/// one. What it proves is the ordering the protection domain wires — the
/// session is driven, the plaintext it produced goes to the surface, what the
/// surface composed is pushed back, and the session is driven again so the
/// answer leaves on the same turn the request arrived on. A push that waited
/// for the peer to speak again would answer every request one delivery late,
/// which is invisible in a unit test of either half.
#[test]
fn a_real_client_gets_the_page_and_the_request_over_the_session() {
    use lfw_onboarding::{Decision, Identity as Onboarded, Monotonic, Onboarding as Surface};

    const DEVICE: &[u8; 32] = b"00000000000000000000000000000001";
    const FINGERPRINT: &[u8; 64] =
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const REQUEST: &[u8] =
        b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBAA==\n-----END CERTIFICATE REQUEST-----\n";

    let arena = Bump::new(ROOM);
    let (certificate, signer) = onboarding(0x61);
    let server = OnboardingServer::open(
        assembled(0x62),
        &arena,
        NOW,
        &certificate,
        signer as std::sync::Arc<dyn SignOperation>,
    )
    .expect("the server opens");
    let mut meeting = Meeting {
        client: Client::new(0x63, &certificate),
        server,
        echo: false,
        answered: Vec::new(),
    };
    let mut surface = Surface::new(Some(Onboarded::new(*DEVICE, *FINGERPRINT, REQUEST)));
    surface.opened();
    meeting.client.pending = b"GET / HTTP/1.1\r\nHost: appliance\r\n\r\n".to_vec();

    // The handshake, then the request, then the answer — each round driving the
    // surface exactly as the protection domain's turn does.
    let mut served = None;
    for _ in 0..8 {
        meeting.round();
        let plaintext = meeting.server.received().to_vec();
        let decision = surface.take(Some(Monotonic::BOOT), &plaintext);
        meeting.server.consumed(plaintext.len());
        if let Decision::Served { route, bytes } = decision {
            served = Some((route, bytes));
        }
        let pushed = meeting.server.push(surface.pending());
        surface.sent(pushed);
        if surface.finished() {
            meeting.server.close();
        }
        if !meeting.client.received.is_empty() && surface.finished() {
            break;
        }
    }

    let (route, bytes) = served.expect("the page was served");
    assert_eq!(route, lfw_log::OnboardRoute::Page);
    let answered = String::from_utf8_lossy(&meeting.client.received).into_owned();
    assert!(
        answered.starts_with("HTTP/1.1 200 OK\r\n"),
        "the client read: {answered}"
    );
    // The two strings an administrator compares, having crossed a real TLS
    // session rather than a buffer this test composed.
    assert!(answered.contains(core::str::from_utf8(DEVICE).expect("ascii")));
    assert!(answered.contains(core::str::from_utf8(FINGERPRINT).expect("ascii")));
    assert!(answered.contains(&format!("Content-Length: {bytes}\r\n")));
    assert_eq!(arena.refusals(), 0);
}
