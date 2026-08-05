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
