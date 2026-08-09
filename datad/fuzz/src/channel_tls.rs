//! `lfw_tls`'s channel client: the TLS 1.3 end this appliance dials a
//! management server with, driven the way the transport drives it — deliveries
//! of arbitrary size and arbitrary content, each answered into a buffer of an
//! arbitrary size.
//!
//! # What this target cannot reach, and what covers it instead
//!
//! **No stream of bytes completes a handshake with this end**, and that is the
//! protocol rather than a weakness here: the server's flight is bound to the
//! client's own ephemeral key share and transcript, both fresh per session, so
//! recorded bytes are stale the moment they are recorded. Everything past the
//! confirmation — the traffic keys, records under them, and what a peer that
//! *did* authenticate can then do — is therefore out of this target's reach,
//! and is stated here rather than left to be assumed covered.
//!
//! It is reached in `lfw_tls`'s own suite instead, where a real rustls server
//! holding the endpoint certificate the delivered anchor issued completes the
//! handshake and then misbehaves — cutting its flight short, saying nothing,
//! and putting records the traffic keys cannot open on the wire. What is left
//! here is the whole of the surface a peer reaches *without* a certificate the
//! appliance was told to trust, which is every byte before that confirmation.
//!
//! # Adversary
//!
//! A **management-plane attacker up to and including a compromised management
//! server**, with the network in between. Every byte here is that party's, and
//! so is the pacing: how much comes back at once, where the pieces fall, and
//! how much room the wire has for the answer. That the peer would be
//! *authenticated* if the handshake completed is not a reason to model it as
//! well-behaved — a compromised server holds a valid certificate, and what
//! bounds it is the buffering and the arena rather than the handshake.
//!
//! What the anchor and the certificate are is drawn from the input too, because
//! neither is this appliance's own choice: both arrive over a delegation from
//! another protection domain, having been installed by a package a peer
//! uploaded. A harness that always handed over a well-formed pair would delete
//! the two arms that exist for the pair being wrong.
//!
//! # What is asserted, beyond not crashing
//!
//! * **Containment.** The answer is written into a guarded buffer, so a write
//!   past what the client was given fails here rather than becoming a byte of
//!   some other structure — and the length it reports is held to what it
//!   actually touched, which the borrow checker does not do.
//! * **Boundedness.** Neither direction outgrows what the client declares it
//!   holds, at any point in the run.
//! * **Nothing reaches the protocol above an unestablished session.** The
//!   plaintext a peer can put in front of the channel's framing is empty until
//!   the peer confirmed the handshake, so a state machine that offered a record
//!   decrypted under an unfinished key schedule fails here.
//! * **An outcome settles once.** The first answer is the one that stays: a
//!   later consequence of a failure must not displace the cause, because the
//!   cause is what an operator goes and looks at.
//! * **Finished is final.** A session the client has finished with produces no
//!   further byte and does not become unfinished, whatever arrives afterwards.
//! * **A refused appliance is never reported as an established channel.** An
//!   outcome that carries a peer's fatal alert stays that alert, which is the
//!   one property this end's ordering exists to hold.

use std::{
    sync::{Arc, Mutex, OnceLock},
    vec::Vec,
};

use crate::{any_index, any_u16, guard::Guarded};
use arbitrary::Unstructured;
use lfw_crypto::{Drbg, Entropy, SEED_LEN};
use lfw_tls::{
    Bump, CertificateKind, ChannelClient, ClientOutcome, CryptoProvider, HELD_MAX, Identity,
    LocalKey, SignOperation, provider,
};

/// The arena the cryptography domain gives a session, in the size it gives it.
const ARENA: usize = 2 * 1024 * 1024;

/// Deliveries one input is cut into, at most.
///
/// A libFuzzer time budget and not a bound on the adversary's authority: the
/// cut *points* are arbitrary and every prefix reaches the client regardless,
/// so no arrival pattern is excluded by it.
const MAX_DELIVERIES: usize = 24;

/// The most room an answer is ever offered, which is what the channel's stream
/// keeps for what goes on the wire.
const ANSWER_ROOM: usize = 4096;

/// A wall clock somewhere inside the certificates' validity.
const NOW: u64 = 1_784_000_000;

/// The address the delivered endpoint certificate names and this appliance
/// dials.
const ENDPOINT: [u8; 4] = [127, 0, 0, 1];

const AUTHORITY: &[u8] = b"librefirewall management";
const ENDPOINT_NAME: &[u8] = b"127.0.0.1";
const DEVICE: &[u8] = b"00000000000000000000000000000001";

pub fn channel_tls_harness(data: &[u8]) {
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
    // Which of the delivered pair, if either, is not the one that was issued.
    // Both come over a delegation and both were installed by a package a peer
    // uploaded, so neither is this appliance's own to get right, and a harness
    // that always handed over a well-formed pair would delete the arms that
    // exist for the pair being wrong.
    let installed = any_index(&mut unstructured, 4);
    let stream = unstructured.take_rest();
    cuts.sort_unstable();

    let arena = Bump::new(ARENA);
    if spoken_for > 0 {
        let _ = arena.allocate(spoken_for, 16);
    }
    let installation = delivered();
    let anchor: &[u8] = match installed {
        1 => stream,
        2 => &[],
        _ => &installation.anchor,
    };
    let certificate: &[u8] = if installed == 3 {
        stream
    } else {
        &installation.device
    };
    let Ok(mut client) = ChannelClient::open(
        Arc::clone(assembled()),
        &arena,
        NOW,
        ENDPOINT,
        certificate,
        Arc::clone(&installation.operation),
        anchor,
    ) else {
        // An arena short of a phase's reserve, an anchor no verifier can be
        // built over, or nothing to present: each is the answer and not a
        // failure to find.
        return;
    };

    let mut settled: Option<ClientOutcome> = None;
    let mut finished = false;
    let mut at = 0_usize;
    // The first turn takes nothing and puts the dial on the wire: this end
    // speaks first, which is the one place the two incremental ends differ.
    for cut in core::iter::once(0)
        .chain(cuts)
        .chain(core::iter::once(stream.len()))
        .map(|cut| cut.min(stream.len()))
    {
        let end = cut.max(at);
        let delivery = stream.get(at..end).unwrap_or_default();
        at = end;

        let mut guarded = Guarded::new(room);
        let turn = client.advance(delivery, guarded.out());
        guarded.assert_margins_intact("the channel client's answer");
        assert!(
            turn.sent <= guarded.capacity(),
            "the client reported writing {} bytes into a buffer of {}",
            turn.sent,
            guarded.capacity()
        );
        assert!(
            guarded.touched_len() <= turn.sent,
            "the client wrote further into the buffer than the length it reported"
        );

        assert!(
            client.received().len() <= HELD_MAX,
            "the plaintext the protocol above has not taken outgrew what one direction holds"
        );
        assert!(
            client.received().is_empty(),
            "a record reached the protocol above a handshake no peer here could have completed"
        );
        if let Some(previous) = &settled {
            assert_eq!(
                Some(previous),
                client.outcome(),
                "a later consequence displaced the cause"
            );
        }
        assert!(
            !matches!(client.outcome(), Some(ClientOutcome::Established(_))),
            "a session established against a peer holding no certificate this end trusts"
        );
        settled = client.outcome().cloned();
        if finished {
            assert_eq!(turn.sent, 0, "a finished session put more on the wire");
            assert!(turn.finished, "a finished session became unfinished");
        }
        finished = turn.finished;

        // The protocol above, standing in for the framing that does not exist
        // yet: it offers what it has, which is what puts the record layer's
        // write path under a length this end did not choose.
        assert!(
            client.push(delivery) <= delivery.len(),
            "the client claimed to have taken more plaintext than it was offered"
        );
    }

    // However the run ended, the session ends: a client asked how the handshake
    // went always has an answer once the transport is gone.
    client.close();
    client.ended();
    let outcome = client.outcome().cloned();
    assert!(
        outcome.is_some(),
        "a session that ended settled on no outcome at all"
    );
    assert!(
        !matches!(outcome, Some(ClientOutcome::Established(_))),
        "a transport that went away left an established channel behind a peer that never authenticated"
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

/// What a configuration package installed, and the key half the store domain
/// keeps: the trust anchor this appliance validates its server against, the
/// device certificate it presents, and a capability over the key inside it.
struct Installed {
    anchor: Vec<u8>,
    device: Vec<u8>,
    operation: Arc<dyn SignOperation>,
}

/// One management authority and everything it issued, built once.
///
/// An authority and two issued certificates per input would spend the whole run
/// in ECDSA key generation rather than in the state machine under test, and
/// nothing an adversary reaches depends on which authority this is.
fn delivered() -> &'static Installed {
    static DELIVERED: OnceLock<Installed> = OnceLock::new();
    DELIVERED.get_or_init(|| {
        let seconds = i64::try_from(NOW).unwrap_or(i64::MAX);
        let authority =
            Identity::self_signed(entropy(), seconds, CertificateKind::ManagementCa, AUTHORITY)
                .expect("the generator produces a usable authority");
        // Issued and never used to answer: it exists so the authority this
        // harness builds is one that really did issue an endpoint, which is
        // the shape a package delivers.
        let _endpoint = Identity::issued_by(
            &authority,
            entropy(),
            seconds,
            CertificateKind::ChannelEndpoint { address: ENDPOINT },
            ENDPOINT_NAME,
            AUTHORITY,
        )
        .expect("an endpoint certificate");
        let device = Identity::issued_by(
            &authority,
            entropy(),
            seconds,
            CertificateKind::Device,
            DEVICE,
            AUTHORITY,
        )
        .expect("a device certificate");
        Installed {
            anchor: authority.certificate().to_vec(),
            device: device.certificate().to_vec(),
            operation: Arc::new(LocalKey::new(device.into_key())),
        }
    })
}

/// The node's generator behind the shared-borrow interface the library's
/// key-exchange list requires, seeded once so a run is reproducible from its
/// input alone.
fn entropy() -> &'static dyn Entropy {
    static SOURCE: OnceLock<Seeded> = OnceLock::new();
    SOURCE.get_or_init(|| Seeded(Mutex::new(Drbg::from_seed(&[0xc5; SEED_LEN]))))
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
