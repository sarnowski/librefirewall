use alloc::{format, sync::Arc, vec, vec::Vec};

use lfw_crypto::{DIGEST_LEN, Entropy, sha256};
use lfw_x509::CertificateKind;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{UnbufferedClientConnection, WebPkiServerVerifier},
    pki_types::{CertificateDer, IpAddr, Ipv4Addr, ServerName},
    server::{UnbufferedServerConnection, WebPkiClientVerifier},
    sign::{CertifiedKey, SingleCertAndKey},
    unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus},
    version::TLS13,
};

use crate::{
    arena::{ArenaExhausted, Bump},
    identity::{Identity, IdentityError},
    provider::{Clock, provider},
    sign::{EcdsaP256SigningKey, LocalKey},
};

/// Bytes of arena headroom a session must have before each of its allocating
/// phases.
///
/// A phase is one span of work that cannot be refused part-way through: the
/// setting up of the two ends, and each call into the TLS library after that.
/// Once such a span has started allocating, an allocation that does not fit
/// has no return path in this language — the allocation-failure path
/// diverges — so the refusal has to happen before the span, and this is how
/// much room a span is required to have.
///
/// **The setup counts, and that is the correction this number encodes.** A
/// guard that watched only the steps would let the two identities, their
/// certificates, the trust anchor and the two configurations be built on an
/// arena that could not hold them — which is a fault and not a refusal, and is
/// exactly what an earlier arrangement of this code did. The whole of one
/// session measures well under a hundred and twenty kilobytes on the shipped
/// image, which the domain reports; this sits at twice that, so a session
/// refused here is refused with room still under it and the arena's own
/// refusal counter stays at zero.
pub const STEP_RESERVE: usize = 256 * 1024;

/// Bytes a wire buffer is first offered, and grows from where a record does
/// not fit.
const WIRE_CHUNK: usize = 4096;

/// Turns of the pump before a session is called stalled. A liveness bound and
/// not a protocol constant: a handshake is a dozen records, and what this
/// exists to stop is the shape where neither side can progress.
const MAX_TURNS: u32 = 64;

/// States one end may pass through in one turn.
const MAX_STATES: u32 = 64;

/// Why a session did not establish, or did not stay established.
///
/// `PartialEq` and not `Eq`, because the library's own error type is only the
/// former — it carries a `f32` in one arm this crate cannot reach.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionError {
    /// The arena had less than [`STEP_RESERVE`] free before a step. The
    /// session is over and nothing partial is left behind it.
    ArenaExhausted(ArenaExhausted),
    /// An identity could not be built.
    Identity(IdentityError),
    /// The TLS library refused, at configuration or on the wire.
    Tls(rustls::Error),
    /// Neither end could make progress.
    Stalled,
    /// The handshake completed and an end saw no peer certificate, which a
    /// mutually-authenticated configuration does not permit.
    NoPeerCertificate,
    /// The peer's certificate is not the one this session issued it.
    WrongPeerCertificate,
    /// What came back is not what went out.
    NotEchoed,
    /// The session did not close cleanly: one end never saw the other's
    /// close notification, so the byte stream has no delimiter and a truncated
    /// one would be indistinguishable from a complete one.
    NotClosed,
}

impl From<IdentityError> for SessionError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<rustls::Error> for SessionError {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}

/// What one completed session established.
///
/// Numbers and one digest, deliberately: no key, no certificate body, no
/// plaintext. The three code points are what an operator compares against the
/// protocol registries; the digest identifies the authenticated peer without
/// putting its certificate on a surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    pub version: u16,
    pub suite: u16,
    pub group: u16,
    /// Bytes of application data that made the round trip unchanged.
    pub echoed: u32,
    /// SHA-256 over the client's end-entity certificate, as the server that
    /// authenticated it saw it.
    pub peer_certificate: [u8; DIGEST_LEN],
}

/// The address the endpoint certificate names and the client dials.
///
/// A literal and not a name, because that is what the channel contract fixes:
/// an appliance is told an address and validates the certificate against
/// exactly what it dialed, so no resolver enters the trust decision.
const ENDPOINT: [u8; 4] = [127, 0, 0, 1];

/// The three names this session issues under. The device identifier is a
/// fixed one here because this session proves the stack rather than an
/// appliance's identity, which the store domain will generate.
const AUTHORITY_NAME: &[u8] = b"librefirewall management";
const ENDPOINT_NAME: &[u8] = b"127.0.0.1";
const DEVICE_NAME: &[u8] = b"00000000000000000000000000000001";

/// Run one mutually-authenticated TLS 1.3 session with both ends here, over a
/// transport that is two buffers.
///
/// This proves the whole stack against itself and needs no network, which is
/// why it can be proved before there is one: the handshake exercises the
/// hybrid key exchange, the signature, the chain validation against an anchor
/// and the key schedule, and the echo afterwards exercises the traffic keys in
/// both directions.
///
/// # Errors
/// [`SessionError`] for every way it can fail, the arena falling below its
/// reserve included — which is the answer the bound exists to be able to give.
pub fn prove_session(
    entropy: &'static dyn Entropy,
    arena: &Bump,
    now: u64,
    payload: &[u8],
) -> Result<Negotiated, SessionError> {
    // Before the setup and not only before the steps: building the two ends
    // allocates more than any single step afterwards does, and it is a span
    // this crate cannot refuse part-way through either.
    require_headroom(arena)?;
    let seconds = i64::try_from(now).unwrap_or(i64::MAX);
    let authority = Identity::self_signed(
        entropy,
        seconds,
        CertificateKind::ManagementCa,
        AUTHORITY_NAME,
    )?;
    let server = Identity::issued_by(
        &authority,
        entropy,
        seconds,
        CertificateKind::ChannelEndpoint { address: ENDPOINT },
        ENDPOINT_NAME,
        AUTHORITY_NAME,
    )?;
    let client = Identity::issued_by(
        &authority,
        entropy,
        seconds,
        CertificateKind::Device,
        DEVICE_NAME,
        AUTHORITY_NAME,
    )?;
    let expected_client = sha256(client.certificate());
    let expected_server = sha256(server.certificate());

    let mut anchors = RootCertStore::empty();
    anchors.add(CertificateDer::from(authority.certificate().to_vec()))?;
    let anchors = Arc::new(anchors);
    let shared = Arc::new(provider(entropy));
    let clock: Arc<dyn rustls::time_provider::TimeProvider> = Arc::new(Clock::at(now));

    let server_config = ServerConfig::builder_with_details(Arc::clone(&shared), Arc::clone(&clock))
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::clone(&anchors), Arc::clone(&shared))
                .build()
                .map_err(unbuildable)?,
        )
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified(server))));

    let client_config = ClientConfig::builder_with_details(Arc::clone(&shared), clock)
        .with_protocol_versions(&[&TLS13])?
        .with_webpki_verifier(
            WebPkiServerVerifier::builder_with_provider(anchors, shared)
                .build()
                .map_err(unbuildable)?,
        )
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified(client))));

    let mut client = Half::new(UnbufferedClientConnection::new(
        Arc::new(client_config),
        ServerName::IpAddress(IpAddr::V4(Ipv4Addr::from(ENDPOINT))),
    )?);
    let mut server = Half::new(UnbufferedServerConnection::new(Arc::new(server_config))?);
    client.pending.extend_from_slice(payload);

    let mut closing = false;
    for _ in 0..MAX_TURNS {
        require_headroom(arena)?;
        let upstream = client.turn()?;
        server.receive(&upstream);
        require_headroom(arena)?;
        // Whatever the server read, it sends straight back, which is what
        // makes the traffic keys proved in both directions rather than only in
        // the one the handshake already exercises.
        let echo = server.take_received();
        server.pending.extend_from_slice(&echo);
        let downstream = server.turn()?;
        client.receive(&downstream);

        let exchanged = client.handshaked
            && server.handshaked
            && client.pending.is_empty()
            && client.received.len() >= payload.len();
        if exchanged && !closing {
            // The stream is delimited by an alert and not by the connection
            // going quiet, which is the difference between a complete stream
            // and a truncated one.
            client.closing = true;
            closing = true;
        }
        if closing && server.peer_closed {
            break;
        }
        // Quiet on both sides is a stall only while there is still something
        // to do: once the close is in flight a turn that moves no bytes is the
        // ordinary way it finishes.
        if !closing && upstream.is_empty() && downstream.is_empty() {
            return Err(SessionError::Stalled);
        }
    }

    if client.received != payload {
        return Err(SessionError::NotEchoed);
    }
    if !server.peer_closed {
        return Err(SessionError::NotClosed);
    }
    if peer_digest(server.connection.peer_certificates())? != expected_client {
        return Err(SessionError::WrongPeerCertificate);
    }
    if peer_digest(client.connection.peer_certificates())? != expected_server {
        return Err(SessionError::WrongPeerCertificate);
    }

    let connection = &client.connection;
    Ok(Negotiated {
        version: connection
            .protocol_version()
            .ok_or(SessionError::Stalled)?
            .into(),
        suite: connection
            .negotiated_cipher_suite()
            .ok_or(SessionError::Stalled)?
            .suite()
            .into(),
        group: connection
            .negotiated_key_exchange_group()
            .ok_or(SessionError::Stalled)?
            .name()
            .into(),
        echoed: u32::try_from(client.received.len()).unwrap_or(u32::MAX),
        peer_certificate: expected_client,
    })
}

/// Refuse before a step rather than fail inside one.
fn require_headroom(arena: &Bump) -> Result<(), SessionError> {
    let remaining = arena.remaining();
    if remaining < STEP_RESERVE {
        return Err(SessionError::ArenaExhausted(ArenaExhausted {
            requested: STEP_RESERVE,
            remaining,
        }));
    }
    Ok(())
}

fn peer_digest(chain: Option<&[CertificateDer<'_>]>) -> Result<[u8; DIGEST_LEN], SessionError> {
    chain
        .and_then(<[CertificateDer<'_>]>::first)
        .map(|certificate| sha256(certificate))
        .ok_or(SessionError::NoPeerCertificate)
}

/// A verifier that would not build is a configuration fault and carries no
/// structure worth propagating past the message it renders.
fn unbuildable(error: rustls::client::VerifierBuilderError) -> rustls::Error {
    rustls::Error::General(format!("{error}"))
}

fn certified(identity: Identity) -> CertifiedKey {
    let chain = vec![CertificateDer::from(identity.certificate().to_vec())];
    CertifiedKey::new(
        chain,
        Arc::new(EcdsaP256SigningKey::new(Arc::new(LocalKey::new(
            identity.into_key(),
        )))),
    )
}

/// One end of the session: its connection, the bytes its peer has sent that it
/// has not consumed, what it has read out of them, and what it owes the wire.
struct Half<C> {
    connection: C,
    incoming: Vec<u8>,
    received: Vec<u8>,
    pending: Vec<u8>,
    /// Set the first time this end can encrypt application data, which is the
    /// point its handshake is done.
    handshaked: bool,
    /// Whether this end should send its close notification once it has nothing
    /// left to say.
    closing: bool,
    closed: bool,
    /// Whether the peer's close notification has arrived.
    peer_closed: bool,
}

impl<C: Unbuffered> Half<C> {
    fn new(connection: C) -> Self {
        Self {
            connection,
            incoming: Vec::new(),
            received: Vec::new(),
            pending: Vec::new(),
            handshaked: false,
            closing: false,
            closed: false,
            peer_closed: false,
        }
    }

    fn receive(&mut self, bytes: &[u8]) {
        self.incoming.extend_from_slice(bytes);
    }

    fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.received)
    }

    /// Drive this end until it needs bytes from its peer, and answer whatever
    /// it produced for the wire.
    fn turn(&mut self) -> Result<Vec<u8>, SessionError> {
        let mut wire = Vec::new();
        for _ in 0..MAX_STATES {
            let UnbufferedStatus { discard, state } = self.connection.records(&mut self.incoming);
            let mut blocked = false;
            match state? {
                ConnectionState::EncodeTlsData(mut encoder) => {
                    into_wire(&mut wire, |out| encoder.encode(out).map_err(encode_error))?;
                }
                ConnectionState::TransmitTlsData(transmit) => transmit.done(),
                ConnectionState::WriteTraffic(mut writer) => {
                    self.handshaked = true;
                    if !self.pending.is_empty() {
                        let payload = core::mem::take(&mut self.pending);
                        into_wire(&mut wire, |out| {
                            writer.encrypt(&payload, out).map_err(encrypt_error)
                        })?;
                    } else if self.closing && !self.closed {
                        self.closed = true;
                        into_wire(&mut wire, |out| {
                            writer.queue_close_notify(out).map_err(encrypt_error)
                        })?;
                    } else {
                        blocked = true;
                    }
                }
                ConnectionState::ReadTraffic(mut traffic) => {
                    while let Some(record) = traffic.next_record() {
                        self.received.extend_from_slice(record?.payload);
                    }
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    self.peer_closed = true;
                    blocked = true;
                }
                // Every remaining state ends this turn: the handshake wants
                // bytes, or the state is one a future library version added
                // and this pump cannot drive.
                _ => blocked = true,
            }
            self.discard(discard);
            if blocked {
                return Ok(wire);
            }
        }
        Err(SessionError::Stalled)
    }

    fn discard(&mut self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let len = self.incoming.len();
        let bytes = bytes.min(len);
        self.incoming.copy_within(bytes.., 0);
        self.incoming.truncate(len.saturating_sub(bytes));
    }
}

/// How much room a write asked for, or the failure it gave instead.
enum Room {
    Needed(usize),
    Failed(SessionError),
}

fn encode_error(error: EncodeError) -> Room {
    match error {
        EncodeError::InsufficientSize(needed) => Room::Needed(needed.required_size),
        other => Room::Failed(SessionError::Tls(rustls::Error::General(format!(
            "{other:?}"
        )))),
    }
}

fn encrypt_error(error: EncryptError) -> Room {
    match error {
        EncryptError::InsufficientSize(needed) => Room::Needed(needed.required_size),
        other => Room::Failed(SessionError::Tls(rustls::Error::General(format!(
            "{other:?}"
        )))),
    }
}

/// Append what `write` produces to `wire`, offering it more room where it says
/// how much it needs. One retry and not a search, because the library reports
/// the exact size.
fn into_wire(
    wire: &mut Vec<u8>,
    mut write: impl FnMut(&mut [u8]) -> Result<usize, Room>,
) -> Result<(), SessionError> {
    let mut room = WIRE_CHUNK;
    for _ in 0..2 {
        let mut scratch = vec![0_u8; room];
        match write(&mut scratch) {
            Ok(len) => {
                wire.extend_from_slice(scratch.get(..len).unwrap_or_default());
                return Ok(());
            }
            Err(Room::Needed(needed)) => room = needed,
            Err(Room::Failed(error)) => return Err(error),
        }
    }
    Err(SessionError::Stalled)
}

/// The one thing both connection types do that the library does not express as
/// a trait: hand back the next state, given whatever the peer has sent.
trait Unbuffered {
    type Data;

    fn records<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data>;
}

impl Unbuffered for UnbufferedClientConnection {
    type Data = rustls::client::ClientConnectionData;

    fn records<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }
}

impl Unbuffered for UnbufferedServerConnection {
    type Data = rustls::server::ServerConnectionData;

    fn records<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }
}
