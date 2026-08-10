use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use lfw_log::{DomainDetail, OnboardOutcome, TlsIncompatible, TlsRefusal};
use rustls::{
    AlertDescription, CipherSuite, Error, NamedGroup, PeerIncompatible, ServerConfig,
    crypto::CryptoProvider,
    pki_types::CertificateDer,
    server::{ClientHello, ResolvesServerCert, UnbufferedServerConnection},
    sign::CertifiedKey,
    time_provider::TimeProvider,
    unbuffered::{ConnectionState, UnbufferedStatus},
    version::TLS13,
};

use crate::{
    arena::{ArenaExhausted, Bump},
    provider::Clock,
    session::{
        Established, HELD_MAX, Held, MAX_STATES, Turn, absorb, drop_front, encode_error,
        encode_into, encrypt_error, headroom,
    },
    sign::{EcdsaP256SigningKey, SignOperation},
};

/// Code points of one kind kept out of a client's offer.
///
/// A client lists as many as it likes, and this end keeps the first few with
/// the number it really listed beside them — so a record that dropped some
/// says so rather than reading as the whole offer. Eight, because the question
/// the record answers is whether the client offered anything this appliance
/// has, and this appliance has one of each — and because eight is what the
/// console record holds, which is the harder bound of the two.
///
/// It is held equal to that one by the type rather than by an assertion:
/// [`ServerOutcome::records`] hands an `[u16; Self]` to a field declared
/// `[u16; lfw_log::MAX_OFFERED_POINTS]`, so a disagreement is a type error at
/// the one place the two meet.
pub const OFFER_KEPT: usize = 8;

/// Code points a client offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offered {
    kept: [u16; OFFER_KEPT],
    length: u8,
    offered: u16,
}

impl Offered {
    /// The first few code points a client listed, with the number it really
    /// listed beside them.
    ///
    /// The one constructor, so the relationship between the two — how much of
    /// `kept` is the offer — is decided once. Crate-visible rather than public:
    /// what builds one is the capture below, and what states one is this
    /// crate's own tests.
    pub(crate) fn of(kept: [u16; OFFER_KEPT], offered: u16) -> Self {
        let length = usize::from(offered).min(OFFER_KEPT);
        Self {
            kept,
            length: u8::try_from(length).unwrap_or(u8::MAX),
            offered,
        }
    }

    /// The code points kept, in the order the client listed them.
    #[must_use]
    pub fn points(&self) -> &[u16] {
        self.kept
            .get(..usize::from(self.length))
            .unwrap_or_default()
    }

    /// How many the client really listed, which may be more than
    /// [`Self::points`] holds.
    #[must_use]
    pub const fn offered(&self) -> u16 {
        self.offered
    }
}

/// What a client offered, read where the library had parsed it and had not yet
/// decided against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerOffer {
    pub suites: Offered,
    pub groups: Offered,
}

/// How one onboarding handshake ended.
///
/// **One variant per cause and none covering two.** A failure to establish the
/// management connection is answered from the console alone, and a token
/// standing for three causes names none of them — so each of these is a
/// different thing to go and look at, and the domain that reports them gives
/// each its own.
///
/// `PartialEq` and not `Eq`, because the library's own error type is only the
/// former — it carries an `f32` in one arm this crate cannot reach.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerOutcome {
    /// The handshake completed.
    Established(Established),
    /// The peer opened the session and sent no byte at all, so there was no
    /// client hello to answer.
    NoClientHello,
    /// The library and the peer had no protocol in common, in the library's own
    /// vocabulary. Distinct from [`Self::NothingInCommon`]: this is the offer
    /// the library rejected before it had a suite or a group to compare — a
    /// client with no TLS 1.3, one with no supported-versions extension at all.
    Incompatible(PeerIncompatible),
    /// The peer offered no cipher suite, or no key-exchange group, that this
    /// appliance has — with what it did offer.
    NothingInCommon {
        incompatible: PeerIncompatible,
        offer: PeerOffer,
    },
    /// The peer gave up on the session with a fatal alert, and this is the one
    /// it sent.
    AlertReceived(AlertDescription),
    /// This end refused the session, in the library's own error vocabulary.
    Refused(Error),
    /// The peer went away before the handshake completed.
    PeerClosed,
    /// The arena had less than one phase's reserve free. The session is over
    /// and nothing partial is left behind it.
    ArenaExhausted(ArenaExhausted),
    /// A direction outgrew [`HELD_MAX`], carrying what it would have held.
    Backlogged { held: usize },
    /// Neither the library nor this end could make progress.
    Stalled,
}

/// The most console records one outcome owes.
///
/// Three, and it is the mismatch that decides it: the outcome itself, the
/// suites a client offered, and the groups it offered. Every other outcome
/// takes one or two.
pub const OUTCOME_RECORDS: usize = 3;

impl ServerOutcome {
    /// The console records this outcome owes, in the order they are emitted.
    ///
    /// Here rather than in the protection domain that emits them, because the
    /// two vocabularies it maps from are the adopted library's and this is the
    /// only crate that sees them — so a release that renames a variant fails
    /// this build rather than a domain nothing host-tests. What the domain
    /// supplies is the lifecycle point they ride on; what is decided here is
    /// which facts reach an operator.
    ///
    /// **Neither the library's rendering nor a peer's bytes travel.** Each
    /// variant is named by a token out of a closed vocabulary and accompanied
    /// by numbers this end computed or a registry defines, so nothing an
    /// adversary chose reaches a console line as itself.
    #[must_use]
    pub fn records(&self) -> [Option<DomainDetail>; OUTCOME_RECORDS] {
        let one = |detail| [Some(detail), None, None];
        match self {
            Self::Established(Established {
                version,
                suite,
                group,
            }) => one(DomainDetail::OnboardingHandshake {
                outcome: OnboardOutcome::Established,
                version: *version,
                suite: *suite,
                group: *group,
            }),
            Self::NoClientHello => one(ended(OnboardOutcome::NoClientHello)),
            Self::PeerClosed => one(ended(OnboardOutcome::PeerClosed)),
            Self::Stalled => one(ended(OnboardOutcome::Stalled)),
            Self::Incompatible(incompatible) => one(DomainDetail::OnboardingIncompatible {
                outcome: OnboardOutcome::Incompatible,
                incompatible: named(incompatible),
            }),
            // Three, because the offer is the whole of what makes a mismatch
            // actionable: an administrator compares two lists against what this
            // appliance carries, and a token saying only that they did not
            // intersect sends them nowhere.
            Self::NothingInCommon {
                incompatible,
                offer,
            } => [
                Some(DomainDetail::OnboardingIncompatible {
                    outcome: OnboardOutcome::NothingInCommon,
                    incompatible: named(incompatible),
                }),
                Some(DomainDetail::OnboardingSuites {
                    points: offer.suites.kept,
                    offered: offer.suites.offered,
                }),
                Some(DomainDetail::OnboardingGroups {
                    points: offer.groups.kept,
                    offered: offer.groups.offered,
                }),
            ],
            // The alert as the registry numbers it and not as the library
            // spells it, on the same terms the version, the suite and the group
            // above cross under: a name is the registry's to change, and an
            // operator holding a capture against a specification is comparing
            // numbers either way.
            Self::AlertReceived(alert) => one(DomainDetail::OnboardingAlert {
                outcome: OnboardOutcome::AlertReceived,
                alert: u16::from(u8::from(*alert)),
            }),
            Self::Refused(error) => one(DomainDetail::OnboardingRefused {
                outcome: OnboardOutcome::Refused,
                refusal: refusal(error),
            }),
            // Two: the outcome, and what was asked for against what was left —
            // which is the record this appliance already states an arena's
            // shortfall on, so a starved session at boot and one under a peer
            // read the same way.
            Self::ArenaExhausted(ArenaExhausted {
                requested,
                remaining,
            }) => [
                Some(ended(OnboardOutcome::ArenaExhausted)),
                Some(DomainDetail::Arena {
                    bytes: *remaining as u64,
                    bound: *requested as u64,
                }),
                None,
            ],
            Self::Backlogged { held } => one(DomainDetail::OnboardingBacklogged {
                outcome: OnboardOutcome::Backlogged,
                held: *held as u64,
            }),
        }
    }
}

/// An outcome whose whole fact is the way it ended.
const fn ended(outcome: OnboardOutcome) -> DomainDetail {
    DomainDetail::OnboardingEnded { outcome }
}

/// The library's incompatibility as the console names it.
///
/// Every member is matched explicitly, so a release that renames one fails this
/// build. The wildcard is not slack: the library's type is open, so a release
/// that *adds* a member has to land somewhere, and it lands on a token that
/// says this build cannot name it rather than on a neighbour that would read as
/// a diagnosis.
pub(crate) fn named(incompatible: &PeerIncompatible) -> TlsIncompatible {
    match incompatible {
        PeerIncompatible::EcPointsExtensionRequired => TlsIncompatible::EcPointsExtensionRequired,
        PeerIncompatible::ExtendedMasterSecretExtensionRequired => {
            TlsIncompatible::ExtendedMasterSecretExtensionRequired
        }
        PeerIncompatible::IncorrectCertificateTypeExtension => {
            TlsIncompatible::IncorrectCertificateTypeExtension
        }
        PeerIncompatible::KeyShareExtensionRequired => TlsIncompatible::KeyShareExtensionRequired,
        PeerIncompatible::NamedGroupsExtensionRequired => {
            TlsIncompatible::NamedGroupsExtensionRequired
        }
        PeerIncompatible::NoCertificateRequestSignatureSchemesInCommon => {
            TlsIncompatible::NoCertificateRequestSignatureSchemesInCommon
        }
        PeerIncompatible::NoCipherSuitesInCommon => TlsIncompatible::NoCipherSuitesInCommon,
        PeerIncompatible::NoEcPointFormatsInCommon => TlsIncompatible::NoEcPointFormatsInCommon,
        PeerIncompatible::NoKxGroupsInCommon => TlsIncompatible::NoKxGroupsInCommon,
        PeerIncompatible::NoSignatureSchemesInCommon => TlsIncompatible::NoSignatureSchemesInCommon,
        PeerIncompatible::NullCompressionRequired => TlsIncompatible::NullCompressionRequired,
        PeerIncompatible::ServerDoesNotSupportTls12Or13 => {
            TlsIncompatible::ServerDoesNotSupportTls12Or13
        }
        PeerIncompatible::ServerSentHelloRetryRequestWithUnknownExtension => {
            TlsIncompatible::ServerSentHelloRetryRequestWithUnknownExtension
        }
        PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig => {
            TlsIncompatible::ServerTlsVersionIsDisabledByOurConfig
        }
        PeerIncompatible::SignatureAlgorithmsExtensionRequired => {
            TlsIncompatible::SignatureAlgorithmsExtensionRequired
        }
        PeerIncompatible::SupportedVersionsExtensionRequired => {
            TlsIncompatible::SupportedVersionsExtensionRequired
        }
        PeerIncompatible::Tls12NotOffered => TlsIncompatible::Tls12NotOffered,
        PeerIncompatible::Tls12NotOfferedOrEnabled => TlsIncompatible::Tls12NotOfferedOrEnabled,
        PeerIncompatible::Tls13RequiredForQuic => TlsIncompatible::Tls13RequiredForQuic,
        PeerIncompatible::UncompressedEcPointsRequired => {
            TlsIncompatible::UncompressedEcPointsRequired
        }
        PeerIncompatible::UnsolicitedCertificateTypeExtension => {
            TlsIncompatible::UnsolicitedCertificateTypeExtension
        }
        PeerIncompatible::ServerRejectedEncryptedClientHello(_) => {
            TlsIncompatible::ServerRejectedEncryptedClientHello
        }
        _ => TlsIncompatible::Unrecognized,
    }
}

/// The library's error as the console names it, on [`named`]'s terms.
///
/// The top-level variant and no deeper. Several of these carry a vocabulary of
/// their own naming which field of which message was malformed, and mirroring
/// those would multiply this list many times over to separate causes an
/// administrator answers identically — the peer is not speaking this protocol
/// correctly. Where the difference *is* actionable the library puts it in a
/// different variant, which is what this list carries.
pub(crate) fn refusal(error: &Error) -> TlsRefusal {
    match error {
        Error::InappropriateMessage { .. } => TlsRefusal::InappropriateMessage,
        Error::InappropriateHandshakeMessage { .. } => TlsRefusal::InappropriateHandshakeMessage,
        Error::InvalidEncryptedClientHello(_) => TlsRefusal::InvalidEncryptedClientHello,
        Error::InvalidMessage(_) => TlsRefusal::InvalidMessage,
        Error::NoCertificatesPresented => TlsRefusal::NoCertificatesPresented,
        Error::UnsupportedNameType => TlsRefusal::UnsupportedNameType,
        Error::DecryptError => TlsRefusal::DecryptError,
        Error::EncryptError => TlsRefusal::EncryptError,
        Error::PeerIncompatible(_) => TlsRefusal::PeerIncompatible,
        Error::PeerMisbehaved(_) => TlsRefusal::PeerMisbehaved,
        Error::AlertReceived(_) => TlsRefusal::AlertReceived,
        Error::InvalidCertificate(_) => TlsRefusal::InvalidCertificate,
        Error::InvalidCertRevocationList(_) => TlsRefusal::InvalidCertRevocationList,
        Error::General(_) => TlsRefusal::General,
        Error::FailedToGetCurrentTime => TlsRefusal::FailedToGetCurrentTime,
        Error::FailedToGetRandomBytes => TlsRefusal::FailedToGetRandomBytes,
        Error::HandshakeNotComplete => TlsRefusal::HandshakeNotComplete,
        Error::PeerSentOversizedRecord => TlsRefusal::PeerSentOversizedRecord,
        Error::NoApplicationProtocol => TlsRefusal::NoApplicationProtocol,
        Error::BadMaxFragmentSize => TlsRefusal::BadMaxFragmentSize,
        Error::InconsistentKeys(_) => TlsRefusal::InconsistentKeys,
        Error::Other(_) => TlsRefusal::Other,
        _ => TlsRefusal::Unrecognized,
    }
}

/// The onboarding server: one TLS 1.3 session, driven a delivery at a time.
///
/// # Adversary
///
/// An **unauthenticated management-plane attacker**. Every byte handed to
/// [`Self::advance`] was chosen by whoever reached the onboarding port, and so
/// was the pacing: how much arrives, in what pieces, and when. Nothing here
/// parses one — the library does — and everything a peer can grow is bounded by
/// [`HELD_MAX`] and refused rather than grown.
///
/// # Why it is incremental rather than a call
///
/// The bytes arrive over a relay from the domain that owns the network, one
/// bounded item at a time, and the answer goes back the same way. So this holds
/// a session across calls: what the peer has sent and the library has not
/// consumed, what the library has produced and the wire has not taken, and the
/// plaintext each direction owes the protocol above.
///
/// # There is no protocol above it here
///
/// This terminates the record layer and nothing else. Plaintext the peer sent
/// is offered to its owner ([`Self::received`]) and plaintext to send comes
/// from its owner ([`Self::push`]); this type decides nothing about either. The
/// onboarding protocol is a different thing in the same domain, and keeping it
/// out of here is what keeps this testable against a real client byte for byte.
///
/// # The client is not authenticated, and that is the phase rather than an
/// omission
///
/// An appliance that has not been onboarded holds no anchor to judge an
/// administrator's certificate against — the anchor is what onboarding
/// delivers. What the administrator judges instead is this appliance's own
/// certificate, compared against the fingerprint its console printed.
pub struct OnboardingServer<'arena> {
    arena: &'arena Bump,
    connection: UnbufferedServerConnection,
    capture: Arc<Capture>,
    /// Peer bytes the library has not consumed.
    incoming: Vec<u8>,
    /// Records the library produced that the wire has not taken.
    outgoing: Vec<u8>,
    /// Plaintext the peer sent that the protocol above has not taken.
    plaintext: Vec<u8>,
    /// Plaintext the protocol above gave, not yet encrypted.
    pending: Vec<u8>,
    outcome: Option<ServerOutcome>,
    /// Whether any byte at all has arrived, which is what tells a peer that
    /// said nothing from one that stopped part way.
    heard: bool,
    handshaked: bool,
    /// Whether this end owes the peer a close notification.
    closing: bool,
    closed: bool,
    peer_closed: bool,
    over: bool,
}

impl<'arena> OnboardingServer<'arena> {
    /// Begin a session presenting `certificate`, signing under `operation`.
    ///
    /// `certificate` is the appliance's own, as the domain that holds the
    /// private half delivered it; `operation` reaches that same private half.
    /// Nothing here checks that the two belong together — the domain that
    /// answered both is the only party that knows, and a client that is shown a
    /// signature under a key the certificate does not bind refuses the
    /// handshake, which is where the mismatch becomes visible.
    ///
    /// The provider is taken already assembled rather than built from a source
    /// of randomness, because assembling one leaks two allocations that never
    /// come back ([`crate::provider`]) — so a session that assembled its own
    /// would cost the region two more every time a peer connected, and a
    /// session is exactly the thing a peer decides how often there is.
    ///
    /// # Errors
    /// A [`ServerOutcome`] the session never got past: the arena short of a
    /// phase's reserve, an identity domain that answered with no certificate,
    /// or a configuration the library would not build.
    pub fn open(
        provider: Arc<CryptoProvider>,
        arena: &'arena Bump,
        now: u64,
        certificate: &[u8],
        operation: Arc<dyn SignOperation>,
    ) -> Result<Self, ServerOutcome> {
        headroom(arena).map_err(ServerOutcome::ArenaExhausted)?;
        if certificate.is_empty() {
            // Refused here rather than at the `Certificate` message, where an
            // empty chain would go out as a well-formed message with nothing in
            // it and come back as a peer that rejected this appliance.
            return Err(ServerOutcome::Refused(Error::NoCertificatesPresented));
        }
        let chain = vec![CertificateDer::from(certificate.to_vec())];
        let key = Arc::new(CertifiedKey::new(
            chain,
            Arc::new(EcdsaP256SigningKey::new(operation)),
        ));
        let capture = Arc::new(Capture::new());
        let clock: Arc<dyn TimeProvider> = Arc::new(Clock::at(now));
        let mut config = ServerConfig::builder_with_details(provider, clock)
            .with_protocol_versions(&[&TLS13])
            .map_err(ServerOutcome::Refused)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Offering {
                key,
                capture: Arc::clone(&capture),
            }));
        // No resumption. A ticket is state this end would keep on behalf of a
        // peer it has not authenticated, to shorten a handshake that happens
        // once per onboarding.
        config.send_tls13_tickets = 0;
        let connection =
            UnbufferedServerConnection::new(Arc::new(config)).map_err(ServerOutcome::Refused)?;
        Ok(Self {
            arena,
            connection,
            capture,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plaintext: Vec::new(),
            pending: Vec::new(),
            outcome: None,
            heard: false,
            handshaked: false,
            closing: false,
            closed: false,
            peer_closed: false,
            over: false,
        })
    }

    /// Take what the peer sent — nothing, where the caller is only asking
    /// whether there is anything to send — and write what goes back into `out`.
    pub fn advance(&mut self, received: &[u8], out: &mut [u8]) -> Turn {
        if !received.is_empty() {
            self.heard = true;
        }
        // A session that is over takes nothing further in — a peer that goes on
        // sending at one must not go on making it hold bytes — and what is left
        // to do is put the last of the answer, an alert among the things it can
        // be, on the wire.
        if !self.over {
            if let Err(exhausted) = headroom(self.arena) {
                // Before the turn and not inside it: an allocation that does
                // not fit has no return path in this language, so the refusal
                // has to happen while there is still room to refuse in.
                self.settle(ServerOutcome::ArenaExhausted(exhausted));
            } else if let Err(held) = absorb(&mut self.incoming, received) {
                self.settle(ServerOutcome::Backlogged { held });
            } else {
                self.pump();
            }
        }
        let sent = self.drain(out);
        Turn {
            sent,
            finished: self.over && self.outgoing.is_empty(),
        }
    }

    /// Plaintext the peer sent that the protocol above has not taken.
    #[must_use]
    pub fn received(&self) -> &[u8] {
        &self.plaintext
    }

    /// Drop the first `bytes` of what the peer sent, which have been taken.
    pub fn consumed(&mut self, bytes: usize) {
        drop_front(&mut self.plaintext, bytes);
    }

    /// Give the peer `plaintext`, answering how much there was room for.
    ///
    /// A count and not a refusal, on the transport's own terms: the protocol
    /// above writes what it has, learns how much went, and comes back for the
    /// rest.
    pub fn push(&mut self, plaintext: &[u8]) -> usize {
        let room = HELD_MAX.saturating_sub(self.pending.len());
        let len = plaintext.len().min(room);
        let Some(taken) = plaintext.get(..len) else {
            return 0;
        };
        self.pending.extend_from_slice(taken);
        len
    }

    /// Say goodbye once there is nothing left to send. The notification is a
    /// record like any other and leaves on a later turn.
    pub fn close(&mut self) {
        self.closing = true;
    }

    /// The transport is gone, so whatever this session was going to be, it is
    /// over.
    pub fn ended(&mut self) {
        let outcome = if self.heard {
            ServerOutcome::PeerClosed
        } else {
            ServerOutcome::NoClientHello
        };
        self.settle(outcome);
    }

    /// How the handshake ended, once it has.
    ///
    /// The handshake, and not the session: a session that established and was
    /// then dropped reads [`ServerOutcome::Established`] here, because what
    /// became of it afterwards is the relay's account and not this one's.
    #[must_use]
    pub fn outcome(&self) -> Option<&ServerOutcome> {
        self.outcome.as_ref()
    }

    /// Drive the library until it wants bytes from the peer or has nothing left
    /// to say.
    fn pump(&mut self) {
        // Whether a refusal has already been recorded. One more turn is taken
        // after it, because the library queues its fatal alert as it refuses
        // and only hands it over on the call after — and a peer that is owed a
        // reason gets it.
        let mut faulted = false;
        let mut ran_out = true;
        for _ in 0..MAX_STATES {
            let mut settle = None;
            let mut established = false;
            let mut blocked = false;
            let discard = {
                let Self {
                    connection,
                    capture,
                    incoming,
                    outgoing,
                    plaintext,
                    pending,
                    closing,
                    closed,
                    peer_closed,
                    over,
                    ..
                } = self;
                let UnbufferedStatus { discard, state } = connection.process_tls_records(incoming);
                match state {
                    Err(error) => settle = Some(settled(error, capture)),
                    Ok(ConnectionState::EncodeTlsData(mut encoder)) => {
                        settle = encode_into(outgoing, |room| {
                            encoder.encode(room).map_err(encode_error)
                        })
                        .err()
                        .map(stopped);
                    }
                    Ok(ConnectionState::TransmitTlsData(transmit)) => transmit.done(),
                    Ok(ConnectionState::WriteTraffic(mut writer)) => {
                        established = true;
                        if pending.is_empty() {
                            if *closing && !*closed {
                                *closed = true;
                                settle = encode_into(outgoing, |room| {
                                    writer.queue_close_notify(room).map_err(encrypt_error)
                                })
                                .err()
                                .map(stopped);
                            } else {
                                blocked = true;
                            }
                        } else {
                            let payload = core::mem::take(pending);
                            settle = encode_into(outgoing, |room| {
                                writer.encrypt(&payload, room).map_err(encrypt_error)
                            })
                            .err()
                            .map(stopped);
                        }
                    }
                    Ok(ConnectionState::ReadTraffic(mut traffic)) => {
                        while let Some(record) = traffic.next_record() {
                            match record {
                                Ok(record) => {
                                    if let Err(held) = absorb(plaintext, record.payload) {
                                        settle = Some(ServerOutcome::Backlogged { held });
                                        break;
                                    }
                                }
                                Err(error) => {
                                    settle = Some(settled(error, capture));
                                    break;
                                }
                            }
                        }
                    }
                    // A peer that said goodbye is answered with goodbye, so the
                    // byte stream has a delimiter at both ends and a truncated
                    // one cannot pass for a complete one.
                    Ok(ConnectionState::PeerClosed) => {
                        *peer_closed = true;
                        *closing = true;
                    }
                    Ok(ConnectionState::Closed) => {
                        *peer_closed = true;
                        *over = true;
                        blocked = true;
                    }
                    // Every remaining state ends this turn: the handshake wants
                    // bytes, or the state is one a later library version added
                    // and this pump cannot drive.
                    Ok(_) => blocked = true,
                }
                discard
            };
            drop_front(&mut self.incoming, discard);
            if established && !self.handshaked {
                self.handshaked = true;
                self.establish();
            }
            if let Some(outcome) = settle {
                if faulted {
                    ran_out = false;
                    break;
                }
                faulted = true;
                self.settle(outcome);
                continue;
            }
            if faulted {
                // The one turn after a refusal is the alert's, and there is no
                // second: asked again, the library would decide against the
                // same record a second time.
                ran_out = false;
                break;
            }
            if blocked {
                ran_out = false;
                break;
            }
        }
        if ran_out {
            self.settle(ServerOutcome::Stalled);
        }
        if self.peer_closed && !self.handshaked {
            self.settle(ServerOutcome::PeerClosed);
        }
    }

    /// Record the three code points a completed handshake settled on.
    fn establish(&mut self) {
        let three = self.connection.protocol_version().zip(
            self.connection
                .negotiated_cipher_suite()
                .zip(self.connection.negotiated_key_exchange_group()),
        );
        let Some((version, (suite, group))) = three else {
            // The library says it can encrypt application data and does not say
            // what it negotiated. Reported in its own vocabulary rather than
            // guessed at.
            self.settle(ServerOutcome::Refused(Error::HandshakeNotComplete));
            return;
        };
        self.record(ServerOutcome::Established(Established {
            version: version.into(),
            suite: suite.suite().into(),
            group: group.name().into(),
        }));
    }

    /// Record an outcome and end the session.
    fn settle(&mut self, outcome: ServerOutcome) {
        self.record(outcome);
        self.over = true;
    }

    /// Keep the **first** outcome: what happened first is what an operator has
    /// to look at, and a later consequence of it would displace the cause.
    fn record(&mut self, outcome: ServerOutcome) {
        if self.outcome.is_none() {
            self.outcome = Some(outcome);
        }
    }

    /// Take what the wire has room for off the front of what is owed it.
    fn drain(&mut self, out: &mut [u8]) -> usize {
        let len = self.outgoing.len().min(out.len());
        match (self.outgoing.get(..len), out.get_mut(..len)) {
            (Some(taken), Some(room)) => room.copy_from_slice(taken),
            _ => return 0,
        }
        drop_front(&mut self.outgoing, len);
        len
    }
}

/// The outcome one refusal by the library is reported as.
///
/// Two decisions live here, and both are about not restating what a third party
/// already said.
///
/// A `PeerIncompatible` travels **as the library's own discriminant**, and this
/// end does not go back to the peer's bytes to recover what it must have
/// offered. A fixed-offset read of a client hello would put a parser of
/// external input inside the domain that holds the private key, to answer a
/// question the discriminants already answer: a client that offered no TLS 1.3,
/// one that sent no supported-versions extension at all, and one whose suites
/// this appliance does not have are three separate values.
///
/// A refusal this end decided travels **as the library's error variant** and
/// not as the alert byte that went out beside it. The library exposes no
/// outgoing alert on this path, so a table from error to alert code would be a
/// first-party claim about a third party's behaviour that a version bump
/// falsifies with nothing failing. The variant is what this end decided, and it
/// is checkable: a release that renames it fails the build, which is a check
/// rather than a drift.
fn settled(error: Error, capture: &Capture) -> ServerOutcome {
    match error {
        Error::AlertReceived(alert) => ServerOutcome::AlertReceived(alert),
        Error::PeerIncompatible(incompatible) => {
            match (nothing_in_common(&incompatible), capture.taken()) {
                (true, Some(offer)) => ServerOutcome::NothingInCommon {
                    incompatible,
                    offer,
                },
                _ => ServerOutcome::Incompatible(incompatible),
            }
        }
        other => ServerOutcome::Refused(other),
    }
}

/// A write this end could not finish, as this end reports it.
fn stopped(held: Held) -> ServerOutcome {
    match held {
        Held::Backlogged(held) => ServerOutcome::Backlogged { held },
        Held::Refused(error) => ServerOutcome::Refused(error),
        Held::Stalled => ServerOutcome::Stalled,
    }
}

/// Whether an incompatibility is one the client's own offer explains.
const fn nothing_in_common(incompatible: &PeerIncompatible) -> bool {
    matches!(
        incompatible,
        PeerIncompatible::NoCipherSuitesInCommon | PeerIncompatible::NoKxGroupsInCommon
    )
}

/// The certificate this appliance presents, and the record of what the client
/// offered on its way past.
///
/// First-party rather than the library's own single-certificate resolver for
/// the capture alone: resolving the certificate is the one point at which a
/// client's offered suites and groups are parsed and still in hand, and the
/// library decides against an offer with nothing in common a few lines later.
/// Reading them here costs nothing and needs no parser of this appliance's own
/// on a path an unauthenticated peer drives.
struct Offering {
    key: Arc<CertifiedKey>,
    capture: Arc<Capture>,
}

impl core::fmt::Debug for Offering {
    /// Names what it resolves to and nothing else. The library requires a
    /// rendering of this type and what is inside it is a certificate and a way
    /// to use a private key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the appliance's own certificate")
    }
}

impl ResolvesServerCert for Offering {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.capture
            .record(hello.cipher_suites(), hello.named_groups());
        Some(Arc::clone(&self.key))
    }
}

/// Where the resolver leaves what a client offered.
///
/// Atomics, and for the arena's reason: the library requires the resolver to be
/// `Sync`, and this is what makes it so without a claim the compiler cannot
/// check. A protection domain runs one thread, so nothing here is ever
/// contended.
struct Capture {
    suites: [AtomicU16; OFFER_KEPT],
    suite_count: AtomicU32,
    groups: [AtomicU16; OFFER_KEPT],
    group_count: AtomicU32,
    seen: AtomicBool,
}

impl Capture {
    const fn new() -> Self {
        Self {
            suites: [const { AtomicU16::new(0) }; OFFER_KEPT],
            suite_count: AtomicU32::new(0),
            groups: [const { AtomicU16::new(0) }; OFFER_KEPT],
            group_count: AtomicU32::new(0),
            seen: AtomicBool::new(false),
        }
    }

    fn record(&self, suites: &[CipherSuite], groups: Option<&[NamedGroup]>) {
        keep(&self.suites, &self.suite_count, suites);
        keep(&self.groups, &self.group_count, groups.unwrap_or_default());
        self.seen.store(true, Ordering::Release);
    }

    /// What was captured, or nothing where the library decided against the
    /// client before ever asking for a certificate.
    fn taken(&self) -> Option<PeerOffer> {
        self.seen.load(Ordering::Acquire).then(|| PeerOffer {
            suites: read(&self.suites, &self.suite_count),
            groups: read(&self.groups, &self.group_count),
        })
    }
}

fn keep<T: Copy + Into<u16>>(into: &[AtomicU16; OFFER_KEPT], count: &AtomicU32, points: &[T]) {
    for (slot, point) in into.iter().zip(points) {
        slot.store((*point).into(), Ordering::Relaxed);
    }
    count.store(
        u32::try_from(points.len()).unwrap_or(u32::MAX),
        Ordering::Relaxed,
    );
}

fn read(from: &[AtomicU16; OFFER_KEPT], count: &AtomicU32) -> Offered {
    let mut kept = [0_u16; OFFER_KEPT];
    for (slot, point) in kept.iter_mut().zip(from.iter()) {
        *slot = point.load(Ordering::Relaxed);
    }
    // Saturated rather than wrapped: a client listing more than a `u16` can
    // count is one whose hello did not fit a record, and the number that says
    // "more than this record can state" is the widest one it can.
    Offered::of(
        kept,
        u16::try_from(count.load(Ordering::Relaxed)).unwrap_or(u16::MAX),
    )
}
