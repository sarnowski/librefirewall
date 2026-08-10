//! The **management server's** half of the channel this appliance dials, played
//! by this harness against a booted image.
//!
//! [`crate::onboard_install_contract`] is an administrator taking an appliance
//! into a fleet. This is what happens for the rest of that appliance's life: it
//! dials the endpoint the package named, presents the device certificate that
//! run's authority issued, validates the server against the anchor that run
//! delivered, and greets it.
//!
//! # The server is `openssl`, and nothing here speaks TLS
//!
//! What is under test is whether the appliance interoperates with a management
//! server, so the server has to be one this project did not write — exactly the
//! argument [`crate::onboard_tls_contract`] points `openssl s_client` at the
//! onboarding port under, with the directions exchanged. `openssl s_server`
//! terminates the session, requires and verifies the client certificate against
//! the run's own authority, and prints the chain it accepted; this module
//! composes the certificates, the greeting and the arguments, and reads back
//! what `openssl` made of the appliance.
//!
//! # The appliance dials out, so the server is listening before the boot
//!
//! It is started before QEMU and killed after it, and that ordering is the whole
//! of how an outbound channel fits a harness whose other contracts are clients:
//! there is nothing to connect *to* the appliance, so a server started when the
//! boot settled would already have been dialled, reset, and be into the second
//! wait of a schedule that doubles.
//!
//! **The address is QEMU's own user-mode gateway.** The appliance dials the
//! address and port the package named, and the SLIRP stack turns a connection to
//! its gateway into a connection to the host's loopback on the same port — so
//! the server binds that port on 127.0.0.1 and needs no forwarding rule at all.
//! The port is therefore fixed rather than reserved, and the bind failing is
//! reported as what it is: something else on this machine already holds it.
//!
//! # No adversary
//!
//! The server is this harness's own and the console is the appliance's own
//! output. What the appliance faces here is the management plane that owns it,
//! which for a node this run onboarded is this run.

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use lfw_log::{ChannelOutcome, Domain, DomainState, TlsCertificateRefusal};

use crate::console_records::{field, lifecycle_records, value};
use crate::forward_harness::{DIAL_DESTINATION, DIAL_PORT};
use crate::util::run_command;

/// What a boot holds the appliance's dialled channel to, and which server — if
/// any — stands at the far end of it.
///
/// A variant per outcome rather than phases inside one boot, on the dial
/// station's terms: each of these is a different thing for an operator to go and
/// look at, and a server that changed its certificate mid-run would leave a
/// reader working out which half of a transcript a record belonged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChannelContract {
    /// Nothing is started and nothing is read. Every boot whose subject is
    /// something else takes this, and on the socket-backed benches it is the
    /// only possibility — a station plays the wire there and no host process can
    /// reach the guest at all.
    Untouched,
    /// **Nothing is listening**, which is a contract rather than an absence: the
    /// user-mode stack answers a connection to a port nothing holds with a
    /// reset, so the appliance must report the transport failing and go on
    /// re-dialling. It is the first of the three ways a channel does not come
    /// up, and the only one that never reaches TLS.
    NoServer,
    /// A server whose certificate the delivered anchor issued, requiring and
    /// verifying the appliance's own. The session must establish, both greetings
    /// must cross, and the connection must be held.
    Established,
    /// A server holding a certificate from **another** authority. The delivered
    /// anchor must refuse it by name.
    AnchorRejectsTheServer,
    /// A server that requires a client certificate and verifies it against
    /// another authority, so it refuses this appliance. The refusal happens
    /// **inside the handshake** — the server judges the certificate before it
    /// writes a byte of application data, so nothing ever crosses under the
    /// traffic keys — and the appliance must report the alert it was given and
    /// no session coming up.
    RejectsTheAppliance,
}

impl ChannelContract {
    /// Whether a server is started for this boot.
    const fn serves(self) -> bool {
        matches!(
            self,
            Self::Established | Self::AnchorRejectsTheServer | Self::RejectsTheAppliance
        )
    }

    /// Whether the boot reads the appliance's own record of the channel.
    pub(crate) const fn judged(self) -> bool {
        !matches!(self, Self::Untouched)
    }
}

/// The management server for one boot: the process, and where it wrote.
///
/// It is killed on drop as well as by [`Self::finish`], so a boot that failed
/// somewhere else does not leave a listener behind for the next one to meet.
pub(crate) struct Server {
    contract: ChannelContract,
    child: Child,
    transcript: PathBuf,
    verification: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The greeting a server sends: the protocol version, and the two cursors it has
/// durably ingested each ring up to.
///
/// Composed here as bytes rather than through the appliance's own encoder,
/// deliberately: a greeting this harness built out of the code under test would
/// prove that the appliance agrees with itself. The layout is the framing
/// contract's — four bytes of payload length, one type byte, three reserved
/// zeroes, then the payload.
const SERVER_GREETING: [u8; 30] = [
    0, 0, 0, 18, // an eighteen-byte payload
    1,  // the greeting's type byte
    0, 0, 0, // reserved, and zero
    0, 1, // protocol version 1
    0, 0, 0, 0, 0, 0, 0, 0, // the log ring ingested up to nothing
    0, 0, 0, 0, 0, 0, 0, 0, // and the capture ring likewise
    // Four trailing bytes: `openssl s_server` sends what it reads on standard
    // input, and this array is written to a pipe whole. The appliance must take
    // exactly the twenty-six bytes above as one frame and hold these as a
    // partial second one — which is what makes the greeting's own length prefix
    // load-bearing rather than incidental.
    //
    // Fewer than a header, and that is the whole point. A header is eight bytes,
    // so eight trailing zeroes would not be a fragment at all: they would decode
    // as a complete header of length zero and type zero, the appliance would
    // refuse the type it does not know, stop reading the stream and close — and
    // a boot whose subject is what the server says next would never see it said.
    0, 0, 0, 0,
];

/// The greeting the **appliance** sends, as this harness expects to read it off
/// the server's transcript: eight bytes of header and a version.
///
/// Written out rather than encoded, on [`SERVER_GREETING`]'s terms exactly.
const APPLIANCE_GREETING: [u8; 10] = [0, 0, 0, 2, 1, 0, 0, 0, 0, 1];

/// The whole of what the harness sends: the greeting, and nothing after it.
const GREETING_LEN: usize = 26;

/// Start the management server this boot's contract asks for.
///
/// # Errors
/// A certificate that could not be issued, a port something else holds, and a
/// server that would not start.
pub(crate) fn serve(
    root: &Path,
    into: &Path,
    contract: ChannelContract,
) -> Result<Option<Server>, String> {
    if !contract.serves() {
        return Ok(None);
    }
    let (ca_key, ca_certificate) = crate::onboard_install_contract::authority(root)?;
    // The certificate the appliance is shown. For the boot whose subject is an
    // anchor that refuses, it comes from an authority of this run's own that the
    // appliance was never given — a second real certification authority rather
    // than a malformed certificate, because what is under test is the
    // *validation* and not the parser.
    let (server_key, server_certificate) = match contract {
        ChannelContract::AnchorRejectsTheServer => {
            let (other_key, other_certificate) = other_authority(into)?;
            endpoint_certificate(into, &other_key, &other_certificate, "unowned")?
        }
        _ => endpoint_certificate(into, &ca_key, &ca_certificate, "issued")?,
    };
    // Whom the server will accept a client certificate from. For the boot whose
    // subject is a server that refuses this appliance, it is an authority that
    // never issued the device certificate — which is the shape of a fleet an
    // appliance has been moved out of, and the one refusal a real management
    // server most often has to give.
    let client_authority = match contract {
        ChannelContract::RejectsTheAppliance => other_authority(into)?.1,
        _ => ca_certificate,
    };
    hold_the_port()?;
    let greeting = into.join("channel-server-greeting.bin");
    fs::write(&greeting, SERVER_GREETING)
        .map_err(|error| format!("write {}: {error}", greeting.display()))?;
    let transcript = into.join("channel-server.out");
    let verification = into.join("channel-server.err");
    let out = fs::File::create(&transcript)
        .map_err(|error| format!("create {}: {error}", transcript.display()))?;
    let err = fs::File::create(&verification)
        .map_err(|error| format!("create {}: {error}", verification.display()))?;
    let mut command = Command::new("openssl");
    command
        .arg("s_server")
        .args(["-accept", &format!("127.0.0.1:{DIAL_PORT}")])
        .arg("-cert")
        .arg(&server_certificate)
        .arg("-key")
        .arg(&server_key)
        // Require a client certificate and verify it, which is the whole of the
        // mutual authentication: a server that merely asked would accept an
        // appliance presenting nothing and the boot would prove less than it
        // states.
        //
        // **`-verify_return_error` is what makes a failed verification refuse.**
        // `-Verify` on its own installs a callback that prints the error and
        // returns success anyway, so a server pointed at an authority that never
        // issued the appliance's certificate completes the handshake and serves
        // it — which reads on the appliance's console exactly like a server that
        // accepted it, and is a boot asserting the opposite of what it states.
        .args(["-Verify", "1", "-verify_return_error"])
        .arg("-CAfile")
        .arg(&client_authority)
        // The session parameters the channel's contract fixes. Named rather than
        // left to `openssl`'s defaults: a server that negotiated something else
        // would be testing a session neither end ships.
        .args(["-tls1_3", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"])
        .args(["-groups", "X25519MLKEM768"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    let mut child = command
        .spawn()
        .map_err(|error| format!("start the management server: {error}"))?;
    // The greeting goes down the pipe now and the pipe stays open for the life
    // of the boot. `openssl s_server` sends what it reads on standard input and
    // shuts the connection down when that reaches end of file, so a redirect
    // from a file would hang up on the appliance the moment the greeting had
    // gone — which is a server that closes a channel it just agreed, and not
    // what any of these three boots is about.
    if let Some(pipe) = child.stdin.as_mut() {
        pipe.write_all(&SERVER_GREETING)
            .and_then(|()| pipe.flush())
            .map_err(|error| format!("hand the greeting to the management server: {error}"))?;
    }
    Ok(Some(Server {
        contract,
        child,
        transcript,
        verification,
    }))
}

/// Bind the port the appliance dials, and let it go.
///
/// The window between letting it go and `openssl` taking it is accepted, on
/// [`crate::forward_harness::reserve_host_ports`]'s terms. What this catches is
/// the case that would otherwise read as a channel the appliance could not
/// establish: something else on this machine already holding the port, so the
/// appliance's session would reach a server nobody in this run started.
fn hold_the_port() -> Result<(), String> {
    TcpListener::bind(("127.0.0.1", DIAL_PORT)).map_err(|error| {
        format!(
            "bind 127.0.0.1:{DIAL_PORT} for the management server: {error}. The appliance dials \
             {}:{DIAL_PORT} and the user-mode stack turns that into a connection to this port on \
             the host's loopback, so a boot that could not take it would meet whatever else is \
             listening",
            ipv4(DIAL_DESTINATION)
        )
    })?;
    Ok(())
}

/// A second certification authority, generated under the run's own tree.
///
/// It exists for the two refusal boots and for nothing else, and it is a real
/// authority rather than a broken certificate: what those two state is that the
/// **validation** decided, so a peer that failed to parse would prove a
/// different thing.
fn other_authority(into: &Path) -> Result<(PathBuf, PathBuf), String> {
    let key = into.join("channel-other-ca.key");
    let certificate = into.join("channel-other-ca.pem");
    if key.is_file() && certificate.is_file() {
        return Ok((key, certificate));
    }
    run_command(
        Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key),
        "generate a second authority's key",
    )
    .map_err(|error| error.to_string())?;
    run_command(
        Command::new("openssl")
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key)
            .args([
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/CN=librefirewall development authority nobody delivered",
            ])
            .args([
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign",
            ])
            .arg("-out")
            .arg(&certificate),
        "generate a second authority's certificate",
    )
    .map_err(|error| error.to_string())?;
    Ok((key, certificate))
}

/// A server certificate for the address the appliance dials, issued by `ca`.
///
/// The address is in a `subjectAltName` and not only in the subject name,
/// deliberately: the appliance holds the certificate to the address **literal**
/// it dialled rather than to a name, so a certificate carrying the address only
/// as a common name is one it refuses — and a harness that issued one would be
/// asserting a validation nobody performs.
fn endpoint_certificate(
    into: &Path,
    ca_key: &Path,
    ca_certificate: &Path,
    tag: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let address = ipv4(DIAL_DESTINATION);
    let key = into.join(format!("channel-server-{tag}.key"));
    let certificate = into.join(format!("channel-server-{tag}.pem"));
    if key.is_file() && certificate.is_file() {
        return Ok((key, certificate));
    }
    let request = into.join(format!("channel-server-{tag}.csr"));
    let extensions = into.join(format!("channel-server-{tag}.ext"));
    fs::write(
        &extensions,
        format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
             extendedKeyUsage=serverAuth\nsubjectAltName=IP:{address}\n"
        ),
    )
    .map_err(|error| format!("write {}: {error}", extensions.display()))?;
    run_command(
        Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key),
        "generate the management server's key",
    )
    .map_err(|error| error.to_string())?;
    run_command(
        Command::new("openssl")
            .args(["req", "-new", "-key"])
            .arg(&key)
            .args(["-subj", &format!("/CN={address}"), "-out"])
            .arg(&request),
        "compose the management server's certificate request",
    )
    .map_err(|error| error.to_string())?;
    run_command(
        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(&request)
            .arg("-CA")
            .arg(ca_certificate)
            .arg("-CAkey")
            .arg(ca_key)
            .args(["-sha256", "-days", "3650", "-extfile"])
            .arg(&extensions)
            .args(["-set_serial", &serial()])
            .arg("-out")
            .arg(&certificate),
        "issue the management server's certificate",
    )
    .map_err(|error| error.to_string())?;
    Ok((key, certificate))
}

/// A serial number for one issued certificate, distinct within a run.
fn serial() -> String {
    format!(
        "0x{:032x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |since| since.as_nanos())
    )
}

/// An IPv4 address as a certificate and a console line spell it.
fn ipv4(octets: [u8; 4]) -> String {
    let [a, b, c, d] = octets;
    format!("{a}.{b}.{c}.{d}")
}

/// Hold the appliance's own record of the channel, and the server's own record
/// of the appliance, to what this boot's contract says.
///
/// **Both ends, and that is the point of the pair.** The appliance says what it
/// made of the server on a console an operator reads; the server says which
/// certificate it validated and under which chain, which is a fact no reading of
/// the appliance's own output could establish. A boot that asserted only the
/// first would pass against an appliance that reported an established session it
/// had invented.
///
/// # Errors
/// Every disagreement, naming the record or the transcript line that was owed.
pub(crate) fn judge(
    contract: ChannelContract,
    server: Option<Server>,
    serial: &[u8],
    device: &str,
) -> Result<String, String> {
    let log = &String::from_utf8_lossy(serial);
    match contract {
        ChannelContract::Untouched => Ok(String::new()),
        ChannelContract::NoServer => {
            // Nothing was started, so there is nothing to read back but the
            // appliance's own account. What it must say is that the transport
            // failed — the user-mode stack answers a connection to a port
            // nothing holds with a reset — and that it went on re-dialling.
            expect_dial(log, "reset-by-peer")?;
            refuse_any_channel_record(log)?;
            Ok(format!(
                "  refused    channel               appliance->server  {}:{DIAL_PORT}  nothing \
                 listening, and the appliance reported dial-outcome=reset-by-peer and re-dialled",
                ipv4(DIAL_DESTINATION)
            ))
        }
        ChannelContract::Established => {
            let Some(server) = server else {
                return Err(String::from(
                    "this boot's contract is an established channel and no management server was \
                     started for it",
                ));
            };
            let (transcript, verification) = server.finish()?;
            expect_dial(log, "established")?;
            expect_channel(
                log,
                &format!(
                    "channel-tls={} channel-tls-version=0x0304 channel-tls-suite=0x1303 \
                     channel-tls-group=0x11ec",
                    ChannelOutcome::Established
                ),
            )?;
            expect_certificate(&verification, device)?;
            expect_greeting(&transcript)?;
            let records = expect_records(&transcript)?;
            // The frame tally is read after the frames themselves, so a boot
            // that shipped nothing fails on the missing frame rather than on a
            // number.
            expect_frames_beyond_the_greeting(log)?;
            Ok(format!(
                "  answered   channel               appliance->server  {}:{DIAL_PORT}  \
                 TLS 1.3, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768; the server validated \
                 CN={device} against the authority this run issued, both greetings crossed at \
                 version 1, and the appliance shipped {records} bytes of its log ring from \
                 position 0 as UP_RECORDS",
                ipv4(DIAL_DESTINATION)
            ))
        }
        ChannelContract::AnchorRejectsTheServer => {
            let _ = server.map(Server::finish).transpose()?;
            expect_channel(
                log,
                &format!(
                    "channel-tls={} channel-tls-certificate={}",
                    ChannelOutcome::ServerCertificateRejected,
                    TlsCertificateRefusal::UnknownIssuer
                ),
            )?;
            Ok(format!(
                "  refused    channel               appliance->server  {}:{DIAL_PORT}  the \
                 server presented a certificate from an authority nobody delivered, and the \
                 appliance refused it under channel-tls-certificate={}",
                ipv4(DIAL_DESTINATION),
                TlsCertificateRefusal::UnknownIssuer
            ))
        }
        ChannelContract::RejectsTheAppliance => {
            let _ = server.map(Server::finish).transpose()?;
            expect_channel(
                log,
                &format!(
                    "channel-tls={} channel-tls-alert=0x0030",
                    ChannelOutcome::AlertReceived
                ),
            )?;
            // And **no session came up**, which is half of what this boot is
            // for. The server judges the device certificate inside the
            // handshake and writes no application data at all, so this end
            // finishes its own flight and the peer never speaks on the session
            // — and an appliance that called that `established` would put the
            // healthy token on the console for exactly the node its fleet has
            // dropped. The absence is asserted rather than assumed, because it
            // is the one thing a reader of these records acts on.
            refuse_channel_record(log, &format!("channel-tls={}", ChannelOutcome::Established))?;
            Ok(format!(
                "  refused    channel               appliance->server  {}:{DIAL_PORT}  the \
                 server would not verify this appliance's certificate and said so with alert 48, \
                 which the appliance reported as channel-tls={} with no session coming up",
                ipv4(DIAL_DESTINATION),
                ChannelOutcome::AlertReceived
            ))
        }
    }
}

impl Server {
    /// Stop the server and read back what it wrote.
    fn finish(mut self) -> Result<(Vec<u8>, String), String> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let transcript = fs::read(&self.transcript)
            .map_err(|error| format!("read {}: {error}", self.transcript.display()))?;
        let verification = fs::read_to_string(&self.verification)
            .map_err(|error| format!("read {}: {error}", self.verification.display()))?;
        let _ = self.contract;
        Ok((transcript, verification))
    }
}

/// The appliance's own record of the attempt, which is the transport's account
/// and not the session's.
fn expect_dial(log: &str, outcome: &str) -> Result<(), String> {
    let owed = field("dial-outcome", outcome);
    if management(log).iter().any(|record| record.contains(&owed)) {
        return Ok(());
    }
    Err(format!(
        "the appliance never reported {owed} for the channel it dialled. What it did report:\n  {}",
        dial_records(log).join("\n  ")
    ))
}

/// One of the session's own records, verbatim.
fn expect_channel(log: &str, owed: &str) -> Result<(), String> {
    if crypto(log).iter().any(|record| record.contains(owed)) {
        return Ok(());
    }
    Err(format!(
        "the appliance never wrote a record carrying `{owed}`. What the domain that terminates \
         the session did write:\n  {}",
        channel_records(log).join("\n  ")
    ))
}

/// None of the session's records carries `owed`, which is how a boot states
/// what an outcome was **not**.
///
/// A refusal and an established session are the two readings an operator acts
/// on differently, so a boot whose subject is one of them says the other did
/// not happen rather than leaving it to the absence of an assertion.
fn refuse_channel_record(log: &str, owed: &str) -> Result<(), String> {
    let written = channel_records(log);
    if !written.iter().any(|record| record.contains(owed)) {
        return Ok(());
    }
    Err(format!(
        "the appliance wrote a record carrying `{owed}`, which this boot's contract says it cannot \
         have. What the domain that terminates the session wrote:\n  {}",
        written.join("\n  ")
    ))
}

/// No session record at all, which is what a boot with nothing listening owes:
/// the transport never came up, so no TLS session was ever opened over it.
fn refuse_any_channel_record(log: &str) -> Result<(), String> {
    let written = channel_records(log);
    if written.is_empty() {
        return Ok(());
    }
    Err(format!(
        "nothing was listening for this boot, so no TLS session can have been carried on the \
         channel — and the appliance wrote:\n  {}",
        written.join("\n  ")
    ))
}

/// The server's own view of the client certificate it validated.
///
/// Two facts, and neither is derivable from the appliance's console: that the
/// subject is the appliance the store domain named, and that the chain reaches
/// the authority this run issued under. `openssl` prints the chain it walked to
/// its standard error, deepest first.
fn expect_certificate(verification: &str, device: &str) -> Result<(), String> {
    let subject = format!("depth=0 CN={device}");
    if !verification.contains(&subject) {
        return Err(format!(
            "the management server did not validate a certificate for `{device}`, which is the \
             appliance the store domain printed. What it verified:\n{verification}"
        ));
    }
    if !verification.contains("depth=1 CN = librefirewall development management CA")
        && !verification.contains("depth=1 CN=librefirewall development management CA")
    {
        return Err(format!(
            "the management server validated the appliance's certificate under an authority that \
             is not the one this run issued it from. What it verified:\n{verification}"
        ));
    }
    Ok(())
}

/// The appliance's greeting, as it reached the server.
///
/// Compared as bytes against a frame written out by hand, so what is asserted is
/// the wire and not the appliance's own encoder. `openssl s_server` writes the
/// application data it received into the same stream as its own diagnostics, so
/// the frame is looked for inside the transcript rather than at a fixed offset.
fn expect_greeting(transcript: &[u8]) -> Result<(), String> {
    if transcript
        .windows(APPLIANCE_GREETING.len())
        .any(|window| window == APPLIANCE_GREETING)
    {
        return Ok(());
    }
    Err(format!(
        "the appliance's greeting never reached the management server. The channel's framing puts \
         it on the wire as {APPLIANCE_GREETING:02x?} — an eight-byte header and the protocol \
         version — and the server's transcript was:\n{}",
        String::from_utf8_lossy(transcript)
    ))
}

/// The appliance's own account of the framing, once it has shipped something.
///
/// The greeting is one frame each way, so a boot that only greeted reports one
/// sent. What this holds is that the tally moved past it — which is the
/// appliance's own statement that it put a recording frame on the wire, beside
/// the server's statement that one arrived.
fn expect_frames_beyond_the_greeting(log: &str) -> Result<(), String> {
    let written = channel_records(log);
    let owed = field("channel-agreed", "true");
    for record in &written {
        if !record.contains(&owed) {
            continue;
        }
        let Some(sent) = value(record, "channel-frames-sent") else {
            continue;
        };
        let sent: u64 = sent.parse().map_err(|_| {
            format!("the appliance stated a frame tally that is not a number: {record}")
        })?;
        if sent > 1 {
            return Ok(());
        }
    }
    Err(format!(
        "the appliance never reported sending a frame beyond its own greeting. What the domain \
         that terminates the session wrote:\n  {}",
        written.join("\n  ")
    ))
}

/// The first upstream log-ring frame the appliance sent, as the server received
/// it, answering how many ring bytes it carried.
///
/// Composed by hand rather than through the appliance's own encoder, on
/// [`SERVER_GREETING`]'s terms: what is asserted is the wire. The header is four
/// bytes of payload length, the `UP_RECORDS` type byte and three reserved
/// zeroes; the payload is a big-endian ring position and then the ring's own
/// bytes, verbatim.
///
/// Two things are held, and both matter. The position is **zero**, which is the
/// beginning of the ring's own append space rather than of whatever the
/// appliance happened to have on hand — a frame that started anywhere else would
/// be one a server could not place. And the ring bytes begin with a pcapng
/// Section Header Block, which is what makes them a recording an ingest can open
/// rather than a run of bytes the appliance called one.
fn expect_records(transcript: &[u8]) -> Result<usize, String> {
    let mut at = 0;
    while let Some(found) = transcript
        .get(at..)
        .and_then(|tail| tail.windows(HEADER_LEN).position(is_up_records))
    {
        let start = at + found;
        let Some(header) = transcript.get(start..start + HEADER_LEN) else {
            break;
        };
        let stated = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let body = transcript.get(start + HEADER_LEN..start + HEADER_LEN + stated);
        if let Some(body) = body
            && let Some(position) = body.get(..RING_POSITION_LEN)
            && let Some(ring) = body.get(RING_POSITION_LEN..)
            && position == [0; RING_POSITION_LEN]
            && ring.len() >= SECTION_HEADER_PREFIX_LEN
            && ring.get(..4) == Some(&SECTION_HEADER_BLOCK)
            && ring.get(8..12) == Some(&BYTE_ORDER_MAGIC)
        {
            return Ok(ring.len());
        }
        at = start + 1;
    }
    Err(format!(
        "the appliance never shipped a well-formed UP_RECORDS frame from ring position 0 whose \
         bytes open on a pcapng Section Header Block. The framing puts one on the wire as four \
         bytes of payload length, the type byte {:#04x}, three reserved zeroes, a big-endian ring \
         position and then the ring's own bytes. The server's transcript was:\n{}",
        UP_RECORDS_TYPE,
        String::from_utf8_lossy(transcript)
    ))
}

/// Whether these eight bytes are an `UP_RECORDS` header: the type byte, and the
/// three reserved bytes this protocol holds at zero.
fn is_up_records(window: &[u8]) -> bool {
    window.get(4) == Some(&UP_RECORDS_TYPE) && window.get(5..8) == Some(&[0, 0, 0][..])
}

/// The records the domain that terminates the session wrote.
fn crypto(log: &str) -> Vec<&str> {
    domain_records(log, Domain::Crypto)
}

/// The records the domain that owns the network wrote.
fn management(log: &str) -> Vec<&str> {
    domain_records(log, Domain::Management)
}

fn domain_records(log: &str, domain: Domain) -> Vec<&str> {
    let named = field("domain", domain.name());
    let ready = field("state", DomainState::Ready.name());
    lifecycle_records(log)
        .into_iter()
        .filter(|record| record.contains(&named) && record.contains(&ready))
        .collect()
}

/// Every record the session left, for a verdict a reader can act on.
fn channel_records(log: &str) -> Vec<&str> {
    crypto(log)
        .into_iter()
        .filter(|record| record.contains("channel-"))
        .collect()
}

/// Every record the attempt left, likewise.
fn dial_records(log: &str) -> Vec<&str> {
    management(log)
        .into_iter()
        .filter(|record| record.contains("dial-"))
        .collect()
}

/// A frame header's length, restated here rather than imported, on
/// [`SERVER_GREETING`]'s terms: this harness writes the contract out by hand so
/// that it holds the appliance to the document and not to the appliance's own
/// idea of it.
const HEADER_LEN: usize = 8;

/// The type byte of a frame carrying log-ring bytes.
const UP_RECORDS_TYPE: u8 = 0x02;

/// The ring position an upstream frame carries in front of its ring bytes.
const RING_POSITION_LEN: usize = 8;

/// pcapng's Section Header Block type, and the byte-order magic eight bytes
/// after it. Written out for the same reason the frames are: what is asserted is
/// that a recording arrived, not that this appliance agrees with itself about
/// what one looks like.
const SECTION_HEADER_BLOCK: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
const BYTE_ORDER_MAGIC: [u8; 4] = [0x4D, 0x3C, 0x2B, 0x1A];

/// Bytes of a Section Header Block a reader must see before it can say so: the
/// block type, its total length, and the byte-order magic.
const SECTION_HEADER_PREFIX_LEN: usize = 12;

/// The whole of what the harness sends, restated where both halves are visible:
/// the greeting and the bytes of a frame that never completes.
///
/// The tail is held **below** a header's length, because a fragment that
/// completed a header would be a frame the appliance decides on rather than one
/// it waits for.
const _: () = assert!(SERVER_GREETING.len() == GREETING_LEN + 4);
const _: () = assert!(SERVER_GREETING.len() - GREETING_LEN < HEADER_LEN);
