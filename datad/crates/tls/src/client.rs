use alloc::{sync::Arc, vec, vec::Vec};

use lfw_log::{ChannelOutcome, DomainDetail, TlsCertificateRefusal};
use rustls::{
    AlertDescription, CertificateError, ClientConfig, Error, PeerIncompatible, PeerMisbehaved,
    RootCertStore,
    client::{Resumption, UnbufferedClientConnection, WebPkiServerVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, IpAddr, Ipv4Addr, ServerName},
    sign::{CertifiedKey, SingleCertAndKey},
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

/// How one management-channel handshake ended.
///
/// **One variant per cause and none covering two.** A failure to establish the
/// management connection is answered from the console alone, and a token
/// standing for three causes names none of them — so each of these is a
/// different thing to go and look at.
///
/// Ten of them are the shape [`crate::ServerOutcome`] has, because both ends of
/// a handshake fail in the same ten ways. Two are only a client's, and they are
/// the two that matter most on this end: this appliance is the party that
/// *validates* a peer, against an anchor somebody delivered to it, so "the
/// anchor did not vouch for the server" and "the anchor is not usable at all"
/// are the two answers a server never has to give and an operator here most
/// often needs.
///
/// `PartialEq` and not `Eq`, because the library's own error type is only the
/// former — it carries an `f32` in one arm this crate cannot reach.
#[derive(Clone, Debug, PartialEq)]
pub enum ClientOutcome {
    /// The handshake completed **and the peer went on with the session**, which
    /// on this end are two moments: a TLS 1.3 client finishes before the server
    /// has judged the certificate it just sent, and the protocol has no message
    /// for "accepted". A server refusing inside the handshake never reaches
    /// this; one giving up later reaches it, then [`ChannelClient::ending`].
    Established(Established),
    /// The peer took the connection and sent no byte at all, so there was no
    /// server hello to read. A management server that is listening and not
    /// answering, which is a different thing from one that is not there —
    /// whether anything answered the dial at all is the transport's account and
    /// not this one's.
    NoServerHello,
    /// The library and the peer had no protocol in common, in the library's own
    /// vocabulary. A server that answered under TLS 1.2 reaches this.
    Incompatible(PeerIncompatible),
    /// The peer broke the protocol, in the library's own vocabulary. A server
    /// that selected a cipher suite or a key-exchange group this appliance did
    /// not offer reaches this — which is the client's shape of a mismatch, the
    /// two ends not being symmetric in it: a client lists what it has and a
    /// server picks one, so this end learns that the pick was wrong rather than
    /// that two lists failed to intersect.
    ///
    /// The discriminant travels whole and this end does not go back to the
    /// peer's bytes to recover what it must have picked. A fixed-offset read of
    /// a server hello would put a parser of external input inside the domain
    /// that holds the device key, to answer a question the discriminants
    /// already answer.
    Misbehaved(PeerMisbehaved),
    /// The delivered anchor did not vouch for the certificate the server
    /// presented, in the validator's own vocabulary: an issuer it does not
    /// know, a certificate outside its validity, one that does not name the
    /// address this appliance dialled.
    ///
    /// Its own variant rather than an arm of [`Self::Refused`], because it is
    /// the failure this end exists to be able to report. An appliance whose
    /// channel will not come up has two candidate faults an operator can act on
    /// — the wrong anchor was delivered, or the server is not the one it was
    /// delivered for — and which of the two it is lives in this discriminant.
    ServerCertificateRejected(CertificateError),
    /// The delivered anchor is not something a verifier can be built over at
    /// all. Distinct from [`Self::ServerCertificateRejected`] because the fault
    /// is in what was *installed* rather than in what the peer presented, and
    /// those send an operator to two different places.
    ///
    /// It carries nothing. Every way a delivered anchor can be unusable has one
    /// answer — the package that installed it is wrong — and the library's
    /// rendering of which way would be a third-party vocabulary on an operator
    /// surface for a distinction nobody acts on.
    AnchorRejected,
    /// The peer gave up on the session with a fatal alert, and this is the one
    /// it sent. **This is how the appliance learns its own certificate was
    /// refused**: the server judges the device certificate and says so in the
    /// alert rather than in anything this end can inspect, so the registry code
    /// point is the whole of the fact — an unknown authority, an expired or
    /// unrecognized certificate and a malformed one are three different numbers
    /// and three different things to go and fix.
    AlertReceived(AlertDescription),
    /// This end refused the session, in the library's own error vocabulary, for
    /// a reason none of the arms above names.
    Refused(Error),
    /// The peer went away, before the handshake completed or after it.
    PeerClosed,
    /// The arena had less than one phase's reserve free. The session is over
    /// and nothing partial is left behind it.
    ArenaExhausted(ArenaExhausted),
    /// A direction outgrew [`HELD_MAX`], carrying what it would have held.
    Backlogged { held: usize },
    /// Neither the library nor this end could make progress.
    Stalled,
}

/// The management channel's client: one TLS 1.3 session out of this appliance,
/// driven a delivery at a time.
///
/// # Adversary
///
/// A **management-plane attacker up to and including a compromised management
/// server**, and the network between. Every byte handed to [`Self::advance`]
/// came back off the wire, and so did the pacing: how much arrives, in what
/// pieces, and when. That the peer is *authenticated* is not a reason to relax
/// any of it — a compromised management server holds a valid certificate, and
/// what bounds it is [`HELD_MAX`] and the arena rather than the handshake.
///
/// # What this appliance decides, and what it is told
///
/// It authenticates the server against **the delivered anchor and nothing
/// else** — no system roots, no other authority — and it checks that
/// certificate against the address it dialled rather than a name anything
/// resolved, so no resolver enters the trust decision. It authenticates
/// *itself* by presenting the device certificate and signing under a key it
/// does not hold, exactly as the onboarding server does.
///
/// Which of the two ends judged what is the whole of why the outcome vocabulary
/// splits the way it does: what this end decided about the peer is a
/// [`ClientOutcome::ServerCertificateRejected`], and what the peer decided about
/// this end arrives as a [`ClientOutcome::AlertReceived`] and in no other form,
/// on [`Self::ending`] rather than [`Self::outcome`].
///
/// # There is no protocol above it here
///
/// This terminates the record layer and nothing else. Plaintext the peer sent
/// is offered to its owner ([`Self::received`]) and plaintext to send comes
/// from its owner ([`Self::push`]); this type decides nothing about either. The
/// channel's framing is a different thing in the same domain, and keeping it
/// out of here is what keeps this testable against a real server byte for byte.
pub struct ChannelClient<'arena> {
    arena: &'arena Bump,
    connection: UnbufferedClientConnection,
    /// Peer bytes the library has not consumed.
    incoming: Vec<u8>,
    /// Records the library produced that the wire has not taken.
    outgoing: Vec<u8>,
    /// Plaintext the peer sent that the protocol above has not taken.
    plaintext: Vec<u8>,
    /// Plaintext the protocol above gave, not yet encrypted.
    pending: Vec<u8>,
    outcome: Option<ClientOutcome>,
    /// The second and last outcome slot: see [`Self::record`].
    ending: Option<ClientOutcome>,
    /// The three code points this end settled on, once it has them. Held rather
    /// than reported on sight: what they mean is that *this* end finished, and
    /// that is not yet the handshake's outcome.
    negotiated: Option<Established>,
    /// Whether any byte at all has come back, which is what tells a server that
    /// answered nothing from one that stopped part way.
    heard: bool,
    handshaked: bool,
    /// Whether this end owes the peer a close notification.
    closing: bool,
    closed: bool,
    peer_closed: bool,
    over: bool,
}

impl<'arena> ChannelClient<'arena> {
    /// Begin a session to `endpoint`, presenting `certificate`, signing under
    /// `operation`, and validating the server against `anchor`.
    ///
    /// `endpoint` is the address literal the configuration package installed
    /// and the transport below dialled, and it is what the server's certificate
    /// is held to. It is an address and not a name because that is what the
    /// channel's contract fixes, and it is passed rather than read because this
    /// crate owns no store.
    ///
    /// The verifier is built here, per session, rather than once at bring-up:
    /// the anchor is a *delivered* value, so there is nothing to build before
    /// one has been delivered. The anchor is parsed by the store that will use
    /// it rather than checked somewhere and handed in, so bytes that are not a
    /// certificate are refused by the same code that would otherwise have to
    /// trust them.
    ///
    /// Nothing here checks that `certificate` and `operation` belong together —
    /// the domain that answered both is the only party that knows, and a server
    /// shown a signature under a key the certificate does not bind refuses the
    /// handshake, which is where the mismatch becomes visible as an alert.
    ///
    /// # Errors
    /// A [`ClientOutcome`] the session never got past: the arena short of a
    /// phase's reserve, an identity domain that answered with no certificate,
    /// an anchor no verifier can be built over, or a configuration the library
    /// would not build.
    pub fn open(
        provider: Arc<CryptoProvider>,
        arena: &'arena Bump,
        now: u64,
        endpoint: [u8; 4],
        certificate: &[u8],
        operation: Arc<dyn SignOperation>,
        anchor: &[u8],
    ) -> Result<Self, ClientOutcome> {
        headroom(arena).map_err(ClientOutcome::ArenaExhausted)?;
        if certificate.is_empty() {
            // Refused here rather than at the `Certificate` message, where an
            // empty chain would go out as a well-formed message with nothing in
            // it and come back as a server that rejected this appliance.
            return Err(ClientOutcome::Refused(Error::NoCertificatesPresented));
        }
        let mut anchors = RootCertStore::empty();
        anchors
            .add(CertificateDer::from(anchor.to_vec()))
            .map_err(|_| ClientOutcome::AnchorRejected)?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(anchors), Arc::clone(&provider))
                .build()
                .map_err(|_| ClientOutcome::AnchorRejected)?;

        let chain = vec![CertificateDer::from(certificate.to_vec())];
        let key = CertifiedKey::new(chain, Arc::new(EcdsaP256SigningKey::new(operation)));
        let clock: Arc<dyn TimeProvider> = Arc::new(Clock::at(now));
        let mut config = ClientConfig::builder_with_details(provider, clock)
            .with_protocol_versions(&[&TLS13])
            .map_err(ClientOutcome::Refused)?
            .with_webpki_verifier(verifier)
            .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
        // No resumption. The channel is one long-lived session, so a ticket
        // would buy a shortened handshake this appliance holds at most once per
        // boot — for state kept on a peer's behalf in a bounded region a peer
        // decides how often there is a session in.
        config.resumption = Resumption::disabled();
        let connection = UnbufferedClientConnection::new(
            Arc::new(config),
            ServerName::IpAddress(IpAddr::V4(Ipv4Addr::from(endpoint))),
        )
        .map_err(ClientOutcome::Refused)?;
        Ok(Self {
            arena,
            connection,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plaintext: Vec::new(),
            pending: Vec::new(),
            outcome: None,
            ending: None,
            negotiated: None,
            heard: false,
            handshaked: false,
            closing: false,
            closed: false,
            peer_closed: false,
            over: false,
        })
    }

    /// Take what the peer sent — nothing, where the caller is only asking
    /// whether there is anything to send — and write what goes out into `out`.
    ///
    /// The first call takes nothing and produces the client hello: this end
    /// speaks first, which is the one place the two incremental ends differ in
    /// how they are driven.
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
                self.settle(ClientOutcome::ArenaExhausted(exhausted));
            } else if let Err(held) = absorb(&mut self.incoming, received) {
                self.settle(ClientOutcome::Backlogged { held });
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
    ///
    /// A session whose handshake this end had finished is settled as finished
    /// even where the peer never said another word: the transport going away is
    /// the transport's account, and a handshake that got that far did get that
    /// far, and [`Self::ending`] stays empty for the same reason.
    pub fn ended(&mut self) {
        if self.handshaked {
            self.confirmed();
            self.over = true;
            return;
        }
        let outcome = if self.heard {
            ClientOutcome::PeerClosed
        } else {
            ClientOutcome::NoServerHello
        };
        self.settle(outcome);
    }

    /// How the handshake ended, once it has.
    ///
    /// The handshake, and not the session: one that established and was then
    /// refused, closed or flooded still reads [`ClientOutcome::Established`]
    /// here, and [`Self::ending`] carries what became of it.
    #[must_use]
    pub fn outcome(&self) -> Option<&ClientOutcome> {
        self.outcome.as_ref()
    }

    /// How a session that established then ended, once it has. **The only place
    /// a refused appliance becomes legible**, a server's verdict on a device
    /// certificate arriving too late to be the handshake's own outcome.
    #[must_use]
    pub fn ending(&self) -> Option<&ClientOutcome> {
        self.ending.as_ref()
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
            let mut confirmed = false;
            let mut blocked = false;
            let discard = {
                let Self {
                    connection,
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
                    Err(error) => settle = Some(settled(error)),
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
                                    confirmed = true;
                                    if let Err(held) = absorb(plaintext, record.payload) {
                                        settle = Some(ClientOutcome::Backlogged { held });
                                        break;
                                    }
                                }
                                Err(error) => {
                                    settle = Some(settled(error));
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
                        confirmed = true;
                    }
                    Ok(ConnectionState::Closed) => {
                        *peer_closed = true;
                        *over = true;
                        confirmed = true;
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
            if established {
                self.negotiate();
            }
            // Only where this end's own handshake finished. A peer that closes
            // before it did is a peer that closed, and the tail below names it
            // — where this ran first it would take the outcome with a token
            // saying the library never told this end what it negotiated, which
            // is true and is not what happened.
            if confirmed && self.handshaked {
                self.confirmed();
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
            self.settle(ClientOutcome::Stalled);
        }
        // A goodbye accounts for the session whether or not the handshake had
        // finished — after one it is what tells a clean close from an alert.
        if self.peer_closed {
            self.settle(ClientOutcome::PeerClosed);
        }
    }

    /// Keep the three code points this end settled on, the first time it can
    /// encrypt application data.
    ///
    /// Kept and not reported. **A TLS 1.3 client finishes its handshake before
    /// the server has judged the certificate it just sent**, and there is no
    /// message in the protocol by which the server says it accepted one — so
    /// this end being able to write is not yet evidence that the session came
    /// up. Reporting it here would put `established` on the console for exactly
    /// the appliance whose device certificate the management server refuses,
    /// which is the one failure this whole vocabulary exists to name.
    fn negotiate(&mut self) {
        if self.handshaked {
            return;
        }
        self.handshaked = true;
        let three = self.connection.protocol_version().zip(
            self.connection
                .negotiated_cipher_suite()
                .zip(self.connection.negotiated_key_exchange_group()),
        );
        self.negotiated = three.map(|(version, (suite, group))| Established {
            version: version.into(),
            suite: suite.suite().into(),
            group: group.name().into(),
        });
    }

    /// The peer went on with the session, which is the only evidence this
    /// protocol offers that it accepted this appliance — a record under the
    /// traffic keys, or a goodbye rather than an alert.
    ///
    /// Recorded and not settled: the session continues, and what becomes of it
    /// afterwards is the transport's account rather than the handshake's.
    ///
    /// Only ever reached with this end's own handshake behind it, so an absent
    /// pair of code points here is the library contradicting itself rather than
    /// a session that never got that far.
    fn confirmed(&mut self) {
        if self.outcome.is_some() {
            // Once: a second would take the slot the session's ending is owed.
            return;
        }
        let Some(established) = self.negotiated else {
            // The library said it could encrypt application data and did not
            // say what it negotiated. Reported in its own vocabulary rather
            // than guessed at.
            self.settle(ClientOutcome::Refused(Error::HandshakeNotComplete));
            return;
        };
        self.record(ClientOutcome::Established(established));
    }

    /// Record an outcome and end the session.
    fn settle(&mut self, outcome: ClientOutcome) {
        self.record(outcome);
        self.over = true;
    }

    /// Keep the **first** outcome, and — only where that was a session that came
    /// up — the one that ended it. Two slots and never a third, neither a peer's
    /// to multiply: a later consequence never displaces the cause.
    fn record(&mut self, outcome: ClientOutcome) {
        match &self.outcome {
            None => self.outcome = Some(outcome),
            Some(ClientOutcome::Established(_)) if self.ending.is_none() => {
                self.ending = Some(outcome);
            }
            Some(_) => (),
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
/// Each arm lifts a discriminant out of the library's error type and no deeper,
/// on the same terms this crate reports every third-party vocabulary: the
/// variant is what one of the two ends decided, a release that renames it fails
/// this build, and nothing here restates it in words of this appliance's own.
///
/// Two of the arms are lifted out of [`ClientOutcome::Refused`] where the server
/// leaves them folded in, and both for the same reason: on this end they are
/// what an operator is actually looking for. A certificate the delivered anchor
/// rejected is the channel's most likely failure and its discriminant says which
/// of a handful of things to go and fix; a server that picked outside what this
/// appliance offered is the mismatch case, which on the other end is a whole
/// variant of its own carrying the peer's list.
fn settled(error: Error) -> ClientOutcome {
    match error {
        Error::AlertReceived(alert) => ClientOutcome::AlertReceived(alert),
        Error::PeerIncompatible(incompatible) => ClientOutcome::Incompatible(incompatible),
        Error::PeerMisbehaved(misbehaved) => ClientOutcome::Misbehaved(misbehaved),
        Error::InvalidCertificate(certificate) => {
            ClientOutcome::ServerCertificateRejected(certificate)
        }
        other => ClientOutcome::Refused(other),
    }
}

/// A write this end could not finish, as this end reports it.
fn stopped(held: Held) -> ClientOutcome {
    match held {
        Held::Backlogged(held) => ClientOutcome::Backlogged { held },
        Held::Refused(error) => ClientOutcome::Refused(error),
        Held::Stalled => ClientOutcome::Stalled,
    }
}

/// The most console records one channel outcome owes.
///
/// Two, and it is the exhausted arena that decides it: the outcome itself, and
/// what was asked for against what was left. Every other outcome takes one.
///
/// One fewer than the onboarding server's, and the difference is the whole
/// asymmetry between the two ends: a server that finds nothing in common has a
/// client's two offer lists to print, and this end has none — a client lists
/// what it has and a server picks one, so what this end learns is that the pick
/// was wrong.
pub const CHANNEL_OUTCOME_RECORDS: usize = 2;

impl ClientOutcome {
    /// The console records this outcome owes, in the order they are emitted.
    ///
    /// Here rather than in the protection domain that emits them, on
    /// [`crate::ServerOutcome::records`]'s terms: the two vocabularies it maps
    /// from are the adopted library's and this is the only crate that sees them,
    /// so a release that renames a variant fails this build rather than a domain
    /// nothing host-tests.
    ///
    /// **The discriminant travels and the context never does.** Three of the
    /// library's certificate errors come in two shapes, one bare and one
    /// carrying what the peer presented, the instant it was judged against, or
    /// an algorithm identifier — and the pair share one token here, because the
    /// cause is the same and the context is a peer's own bytes. Nothing an
    /// adversary chose reaches a console line as itself, from any arm.
    #[must_use]
    pub fn records(&self) -> [Option<DomainDetail>; CHANNEL_OUTCOME_RECORDS] {
        let one = |detail| [Some(detail), None];
        match self {
            Self::Established(Established {
                version,
                suite,
                group,
            }) => one(DomainDetail::ChannelHandshake {
                outcome: ChannelOutcome::Established,
                version: *version,
                suite: *suite,
                group: *group,
            }),
            Self::NoServerHello => one(ended(ChannelOutcome::NoServerHello)),
            Self::PeerClosed => one(ended(ChannelOutcome::PeerClosed)),
            Self::Stalled => one(ended(ChannelOutcome::Stalled)),
            Self::AnchorRejected => one(ended(ChannelOutcome::AnchorRejected)),
            // The library's own account of which field of which message a
            // server got wrong is deliberately not carried. Dozens of members
            // name the shape of one broken or hostile peer, and an
            // administrator answers every one of them the same way; where the
            // distinction is actionable the library puts it in a different
            // error, which the arms around this one carry.
            Self::Misbehaved(_) => one(ended(ChannelOutcome::Misbehaved)),
            Self::Incompatible(incompatible) => one(DomainDetail::ChannelIncompatible {
                outcome: ChannelOutcome::Incompatible,
                incompatible: crate::server::named(incompatible),
            }),
            Self::ServerCertificateRejected(error) => one(DomainDetail::ChannelCertificate {
                outcome: ChannelOutcome::ServerCertificateRejected,
                refusal: certificate(error),
            }),
            // The alert as the registry numbers it and not as the library
            // spells it, on the code points above's terms.
            Self::AlertReceived(alert) => one(DomainDetail::ChannelAlert {
                outcome: ChannelOutcome::AlertReceived,
                alert: u16::from(u8::from(*alert)),
            }),
            Self::Refused(error) => one(DomainDetail::ChannelRefused {
                outcome: ChannelOutcome::Refused,
                refusal: crate::server::refusal(error),
            }),
            // Two: the outcome, and what was asked for against what was left —
            // the record this appliance already states an arena's shortfall on,
            // so a starved session at boot, one under an onboarding peer and one
            // under a management server all read the same way.
            Self::ArenaExhausted(ArenaExhausted {
                requested,
                remaining,
            }) => [
                Some(ended(ChannelOutcome::ArenaExhausted)),
                Some(DomainDetail::Arena {
                    bytes: *remaining as u64,
                    bound: *requested as u64,
                }),
            ],
            Self::Backlogged { held } => one(DomainDetail::ChannelBacklogged {
                outcome: ChannelOutcome::Backlogged,
                held: *held as u64,
            }),
        }
    }
}

/// An outcome whose whole fact is the way it ended.
const fn ended(outcome: ChannelOutcome) -> DomainDetail {
    DomainDetail::ChannelEnded { outcome }
}

/// The way the delivered anchor refused a server's certificate, as the console
/// names it.
///
/// Every member is matched explicitly, so a release that renames one fails this
/// build; the wildcard is the library's type being open, on
/// [`crate::server::named`]'s terms exactly. **A member carrying context shares
/// its bare sibling's token**: the cause is the same, and the context is the
/// name a peer presented, the instant it was judged against, or the algorithm
/// identifier it used — a peer's own bytes, which no console line repeats.
#[expect(
    deprecated,
    reason = "the library has deprecated six of its bare members in favour of the context-bearing \
              siblings matched beside them. Both shapes are still constructible by a custom \
              verifier and both still name a cause, so a mirror that dropped the bare ones would \
              land them on the token that says this build cannot name what happened"
)]
fn certificate(error: &CertificateError) -> TlsCertificateRefusal {
    match error {
        CertificateError::BadEncoding => TlsCertificateRefusal::BadEncoding,
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
            TlsCertificateRefusal::Expired
        }
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            TlsCertificateRefusal::NotValidYet
        }
        CertificateError::Revoked => TlsCertificateRefusal::Revoked,
        CertificateError::UnhandledCriticalExtension => {
            TlsCertificateRefusal::UnhandledCriticalExtension
        }
        CertificateError::UnknownIssuer => TlsCertificateRefusal::UnknownIssuer,
        CertificateError::UnknownRevocationStatus => TlsCertificateRefusal::UnknownRevocationStatus,
        CertificateError::ExpiredRevocationList
        | CertificateError::ExpiredRevocationListContext { .. } => {
            TlsCertificateRefusal::ExpiredRevocationList
        }
        CertificateError::BadSignature => TlsCertificateRefusal::BadSignature,
        CertificateError::UnsupportedSignatureAlgorithm
        | CertificateError::UnsupportedSignatureAlgorithmContext { .. } => {
            TlsCertificateRefusal::UnsupportedSignatureAlgorithm
        }
        CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
            TlsCertificateRefusal::UnsupportedSignatureAlgorithmForPublicKey
        }
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            TlsCertificateRefusal::NotValidForName
        }
        CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
            TlsCertificateRefusal::InvalidPurpose
        }
        CertificateError::InvalidOcspResponse => TlsCertificateRefusal::InvalidOcspResponse,
        CertificateError::ApplicationVerificationFailure => {
            TlsCertificateRefusal::ApplicationVerificationFailure
        }
        CertificateError::Other(_) => TlsCertificateRefusal::Other,
        _ => TlsCertificateRefusal::Unrecognized,
    }
}
