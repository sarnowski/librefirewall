//! The onboarding port's TLS server, held to what a **real client** made of it
//! on the booted image.
//!
//! [`crate::onboard_contract`] judges what the two domains say a session
//! carried. This judges what the session *was*: an administrator's client
//! reaches the port through a forwarded host port, four times over one boot,
//! and each attempt is a different thing for the appliance to do — one
//! handshake that must complete, and three that must fail differently.
//!
//! # Why a client nothing in this repository wrote
//!
//! Everything above the wire is already held by the host suite, which drives
//! the same server with this appliance's own rustls client. What that cannot
//! settle is whether the thing an administrator actually runs interoperates
//! with it: a first-party client and a first-party server agreeing proves the
//! two agree. So the client here is `openssl s_client`, which shares no code
//! with the appliance, and the fourth attempt is a bare TCP connection, which
//! shares not even a protocol.
//!
//! # The three facts a completed handshake is judged on, and where each comes
//! from
//!
//! The version, the suite and the group are read from **both** ends — the
//! client's transcript and the appliance's own record — and compared. Either
//! read alone is one party's account of itself; together they are two
//! independent statements about one handshake, and a server that reported a
//! group it did not negotiate would pass the first and fail this.
//!
//! The fourth is the certificate's subject, and it is joined further still: the
//! common name the client was shown must be the device identifier the **store**
//! domain printed on the same boot. That is the appliance's own name reaching a
//! peer through a certificate it minted on a medium, and no single surface can
//! state it.
//!
//! # Why a failure is judged by the token and not by the client's complaint
//!
//! What `openssl` prints when a handshake fails is `openssl`'s account, and the
//! whole point of the outcome vocabulary is that the *appliance* says which of
//! the ten causes it was. So each failing attempt is held to its own token on
//! the console, and the client's transcript is kept as evidence rather than
//! parsed for a diagnosis.
//!
//! # No adversary
//!
//! The client is this harness's own and the console is the appliance's own
//! output on a wire only the harness is attached to. What this defends against
//! is a server that answers the appliance's own client and nothing else.

use std::io::Write as _;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lfw_log::{Domain, DomainState, OnboardOutcome};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value};

/// The field every handshake record leads with.
const OUTCOME: &str = "onboard-tls";

/// The three code points a completed handshake carries, and the two tokens a
/// failed one may.
const VERSION: &str = "onboard-tls-version";
const SUITE: &str = "onboard-tls-suite";
const GROUP: &str = "onboard-tls-group";
const INCOMPATIBLE: &str = "onboard-tls-incompatible";
const SUITES: &str = "onboard-tls-suites";

/// The port's own totals, which say how many connections became sessions.
const ACCEPTED: &str = "onboard-accepted";

/// The identifier the store domain prints, which the certificate's subject must
/// be.
const DEVICE: &str = "device";

/// What one attempt runs and what the appliance owes for it.
struct Client {
    /// What this client is, in the words the evidence table uses.
    name: &'static str,
    /// `openssl s_client` arguments after the connect address, or none where
    /// the client is a bare connection that speaks nothing at all.
    arguments: Option<&'static [&'static str]>,
    /// The token the appliance must report for it.
    owed: OnboardOutcome,
}

/// The four attempts, in the order one boot makes them.
///
/// The order is deliberate and is the cheapest half of what it proves: the
/// successful handshake goes **first**, so the three failures after it are
/// three sessions on a port that has already carried one — which is the
/// property a server holding state across sessions would fail, and which no
/// single-session boot can state at all.
const CLIENTS: [Client; 4] = [
    Client {
        name: "a TLS 1.3 client offering this appliance's own group",
        // Both named rather than left to the client's defaults: what is being
        // proved is that the appliance negotiates its one version, its one
        // suite and its one group, and a default list that happened to change
        // between two releases of the client would make the boot prove
        // something else without saying so.
        arguments: Some(&["-tls1_3", "-groups", "X25519MLKEM768", "-brief"]),
        owed: OnboardOutcome::Established,
    },
    Client {
        name: "a client that has only ever spoken TLS 1.2",
        arguments: Some(&["-tls1_2", "-brief"]),
        owed: OnboardOutcome::Incompatible,
    },
    Client {
        name: "a TLS 1.3 client offering a suite this appliance does not have",
        arguments: Some(&[
            "-tls1_3",
            "-ciphersuites",
            "TLS_AES_128_GCM_SHA256",
            "-brief",
        ]),
        owed: OnboardOutcome::NothingInCommon,
    },
    Client {
        name: "a client that connects and says nothing at all",
        arguments: None,
        owed: OnboardOutcome::NoClientHello,
    },
];

/// How many connections one boot's attempts make on the port, which is what its
/// own totals must report.
pub(crate) const ATTEMPTS: u64 = CLIENTS.len() as u64;

/// How long one client is given before the run gives up on it.
///
/// A bound rather than a wait: an emulated boot is slow and an accelerated one
/// is not, so what this has to be is longer than the slower of the two and
/// short enough that a hung client fails the run instead of the runner's own
/// timeout.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// How often the run looks at a client it is waiting on. Short enough that a
/// fast handshake is not paced by it, long enough that waiting costs nothing.
const POLL: Duration = Duration::from_millis(20);

/// What one attempt produced.
#[derive(Debug)]
pub struct Attempt {
    name: &'static str,
    command: String,
    status: String,
    transcript: String,
    owed: OnboardOutcome,
}

/// Wake the appliance once, as cheaply as a wakeup can be had.
///
/// A connection opened and closed on the port's *other* surface, carrying no
/// request: the domain that owns the network has no timer, so what advances the
/// pass that ends a session and writes its account is a frame arriving, and this
/// is the fewest frames that produce one. **Cheapness is the property, not an
/// optimization** — the obvious wakeup is a request, and a request pulls tens of
/// thousands of bytes whose every drain writes a console record of its own, which
/// overruns the bounded log ring and drops exactly the records this boot is
/// waiting for.
pub(crate) fn nudge(host_port: u16) -> Result<(), String> {
    let address: SocketAddr = format!("127.0.0.1:{host_port}")
        .parse()
        .map_err(|error| format!("address the management forward: {error}"))?;
    let stream = TcpStream::connect_timeout(&address, CLIENT_TIMEOUT)
        .map_err(|error| format!("wake the appliance on 127.0.0.1:{host_port}: {error}"))?;
    // Both directions, so the appliance sees the end of the stream rather than
    // holding a connection this run will not come back to.
    let _ = stream.shutdown(Shutdown::Both);
    // A pass per wakeup, and the passes are what is being waited for: without
    // this the loop spends its whole budget faster than the guest can answer one
    // of them.
    std::thread::sleep(SETTLE);
    Ok(())
}

/// How long one wakeup is given to produce its pass.
const SETTLE: Duration = Duration::from_millis(50);

/// Run every client against the forwarded port, nudging the appliance between
/// them.
///
/// `nudge` is called after each attempt because the domain that carries a
/// session holds no timer: every pass that advances the handover runs on a
/// wakeup, and the pass that ends a session and writes its record has no frame
/// of its own once the client's connection is gone. The caller supplies traffic
/// the port answers; this decides when it is needed.
///
/// # Errors
/// A client that could not be run at all, which is the harness's own failure
/// rather than the appliance's.
pub(crate) fn drive(
    onboard_port: u16,
    mut nudge: impl FnMut() -> Result<(), String>,
) -> Result<Vec<Attempt>, String> {
    let mut attempts = Vec::new();
    for client in CLIENTS {
        attempts.push(match client.arguments {
            Some(arguments) => speak_tls(&client, arguments, onboard_port)?,
            None => say_nothing(&client, onboard_port)?,
        });
        // Twice: the first wakeup carries the session's last handover and the
        // second the pass that publishes its account, and a client that opened
        // the next connection before both had run would leave two sessions
        // racing for one slot.
        nudge()?;
        nudge()?;
    }
    Ok(attempts)
}

/// One `openssl s_client` run, whatever it makes of the port.
///
/// The status is recorded and never gated on: a client shown a self-signed
/// certificate reports the verification failure in its exit code, and that is
/// the correct behaviour of a client that has not been onboarded — the
/// administrator compares the fingerprint the console printed instead. What
/// the run is judged by is the transcript and the appliance's own record.
fn speak_tls(client: &Client, arguments: &[&str], port: u16) -> Result<Attempt, String> {
    let connect = format!("127.0.0.1:{port}");
    let command = format!(
        "openssl s_client -connect {connect} {}",
        arguments.join(" ")
    );
    let mut child = Command::new("openssl")
        .arg("s_client")
        .arg("-connect")
        .arg(&connect)
        .args(arguments)
        // Closed, which is what makes the client say goodbye and exit rather
        // than holding the connection open waiting to be typed at.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("run `{command}`: {error}"))?;
    // Bounded, because this client has no timeout of its own and an appliance
    // that answered nothing would otherwise hang the gate rather than fail it —
    // and a gate that hangs reports nothing at all.
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    let mut killed = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                killed = true;
                break;
            }
            Ok(None) => std::thread::sleep(POLL),
            Err(error) => return Err(format!("wait for `{command}`: {error}")),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("collect `{command}`: {error}"))?;
    let mut transcript = String::from_utf8_lossy(&output.stdout).into_owned();
    transcript.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(Attempt {
        name: client.name,
        command,
        status: if killed {
            format!("killed after {}s with no answer", CLIENT_TIMEOUT.as_secs())
        } else {
            format!("{}", output.status)
        },
        transcript: transcript.trim().to_owned(),
        owed: client.owed,
    })
}

/// A connection that carries no byte in either direction.
///
/// No library at all, because the thing under test is what the appliance does
/// with a peer that opens a connection and never sends a client hello — and any
/// TLS client would send one. Closed in both directions rather than dropped, so
/// the appliance sees the end of the stream rather than waiting out an idle
/// timeout the run has no time for.
fn say_nothing(client: &Client, port: u16) -> Result<Attempt, String> {
    let address: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|error| format!("address the onboarding forward: {error}"))?;
    let command = format!("connect 127.0.0.1:{port} and close it");
    let stream = TcpStream::connect_timeout(&address, CLIENT_TIMEOUT)
        .map_err(|error| format!("{command}: {error}"))?;
    // Flushed before the shutdown for the same reason a writer always is, even
    // with nothing written: what is being proved is that the appliance saw a
    // connection and no byte, and a buffer this end forgot would be a byte.
    let mut stream = stream;
    stream
        .flush()
        .map_err(|error| format!("{command}: {error}"))?;
    let closed = stream.shutdown(Shutdown::Both);
    Ok(Attempt {
        name: client.name,
        command,
        status: match closed {
            Ok(()) => String::from("closed"),
            Err(error) => format!("closed with {error}"),
        },
        transcript: String::from("no byte was sent in either direction"),
        owed: client.owed,
    })
}

/// Whether the appliance has finished reporting every attempt.
///
/// The observable a boot that runs these clients waits on, and it is an event
/// rather than a duration: a session's account is written on the pass that ends
/// it, which runs after the client's own connection is already gone, so there is
/// nothing else to wait for. Both surfaces, because both are judged — the
/// terminating domain's account of each handshake, and the port's own totals
/// beside them.
pub(crate) fn reported(serial: &[u8]) -> bool {
    let text = String::from_utf8_lossy(serial);
    handshake_records(&text).len() >= CLIENTS.len()
        && ours(&text, Domain::Management).iter().any(|record| {
            // The port's own count, and not merely that a totals record exists:
            // the two domains report on their own passes, so the network end is
            // routinely a session or two behind the terminating one, and a run
            // that stopped at the first totals record would kill the guest with
            // the last of them still owed.
            value(record, ACCEPTED)
                .and_then(|accepted| accepted.parse::<u64>().ok())
                .is_some_and(|accepted| accepted >= ATTEMPTS)
        })
}

/// Judge one boot's attempts against the records the appliance left.
///
/// # Errors
/// The disagreement, naming the attempt, the token owed and the record that
/// carried something else, and where the whole run log is.
pub(crate) fn judge(attempts: &[Attempt], serial: &[u8], log: &Path) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let handshakes = handshake_records(&text);
    if handshakes.len() != attempts.len() {
        return Err(format!(
            "this boot made {} attempt(s) on the onboarding port and the cryptography domain \
             reported {} handshake(s). One record per attempt is the whole contract: fewer is a \
             session the domain carried and never accounted for — which a reader of a deployed \
             node cannot tell from a port nothing reached — and more is a handshake nobody \
             opened\n  records observed: {handshakes:#?}\n  full run log: {}",
            attempts.len(),
            handshakes.len(),
            log.display()
        ));
    }

    for (attempt, record) in attempts.iter().zip(&handshakes) {
        let reported = read(record, OUTCOME, log)?;
        if reported != attempt.owed.name() {
            return Err(format!(
                "{} drew `{OUTCOME}={reported}` and this attempt owes `{}`: {record:?}. Each of \
                 the ten is a different thing for an administrator to go and change, so a token \
                 that stands for the wrong one is worse than no record at all\n  what the client \
                 said: {}\n  full run log: {}",
                attempt.name,
                attempt.owed.name(),
                attempt.transcript,
                log.display()
            ));
        }
    }

    let established = one_of(&handshakes, OnboardOutcome::Established, log)?;
    let negotiated = judge_established(attempts, established, &text, log)?;
    judge_incompatible(&handshakes, &text, log)?;

    // The port's own totals, which are the second, independent statement that
    // every attempt became a session: the accounts above are the terminating
    // domain's and this is the domain that owns the port.
    let accepted = port_total(&text, log)?;
    if accepted != ATTEMPTS {
        return Err(format!(
            "the onboarding port reports {accepted} connection(s) accepted and this boot opened \
             {ATTEMPTS}. A connection short is one that never reached the port; one over is a \
             connection that became no handshake, and the record that would explain it is not \
             there\n  full run log: {}",
            log.display()
        ));
    }

    Ok(format!(
        "{ATTEMPTS} real clients reached the onboarding port over one boot: {negotiated}, and \
         `{}`, `{}` and `{}` each reported under their own token",
        OnboardOutcome::Incompatible.name(),
        OnboardOutcome::NothingInCommon.name(),
        OnboardOutcome::NoClientHello.name(),
    ))
}

/// The completed handshake, from both ends and joined to the appliance's name.
fn judge_established(
    attempts: &[Attempt],
    record: &str,
    text: &str,
    log: &Path,
) -> Result<String, String> {
    let attempt = attempts
        .iter()
        .find(|attempt| attempt.owed == OnboardOutcome::Established)
        .ok_or_else(|| String::from("no attempt in this boot was meant to establish"))?;

    // The appliance's own three, and the client's own three beside them. The
    // pairs are what makes this a comparison rather than a reading: the code
    // point is what the appliance publishes and the name is what the client
    // prints, and only a run that saw both can hold them together.
    for (key, owed, printed) in [
        (VERSION, "0x0304", "Protocol version: TLSv1.3"),
        (SUITE, "0x1303", "Ciphersuite: TLS_CHACHA20_POLY1305_SHA256"),
        (GROUP, "0x11ec", "Negotiated TLS1.3 group: X25519MLKEM768"),
    ] {
        let reported = read(record, key, log)?;
        if reported != owed {
            return Err(format!(
                "the appliance reports `{key}={reported}` for the handshake that completed and \
                 this image carries {owed}: {record:?}\n  full run log: {}",
                log.display()
            ));
        }
        if !attempt.transcript.contains(printed) {
            return Err(format!(
                "the appliance reports `{key}={reported}` and the client that completed the \
                 handshake did not print {printed:?}. Either the two ends settled on different \
                 things or one of them is reporting something it did not do\n  what the client \
                 said: {}\n  full run log: {}",
                attempt.transcript,
                log.display()
            ));
        }
    }

    // And the certificate's subject against the appliance's own name, which is
    // the one fact neither surface holds alone: the store domain minted this
    // identifier onto a medium and the client was shown it over a wire.
    let device = device_identifier(text, log)?;
    let subject = format!("Peer certificate: CN={device}");
    if !attempt.transcript.contains(&subject) {
        return Err(format!(
            "the store domain reports this appliance is `{device}` and the client was shown a \
             certificate that does not name it — the subject a peer is offered must be the \
             identifier an administrator compares against the console\n  looked for: \
             {subject:?}\n  what the client said: {}\n  full run log: {}",
            attempt.transcript,
            log.display()
        ));
    }
    Ok(format!(
        "TLS 1.3 with TLS_CHACHA20_POLY1305_SHA256 over X25519MLKEM768, under a certificate for \
         `{device}`"
    ))
}

/// The two records that carry the library's own account of an offer it would
/// not accept.
fn judge_incompatible(handshakes: &[&str], text: &str, log: &Path) -> Result<(), String> {
    for (outcome, owed) in [
        (
            OnboardOutcome::Incompatible,
            "supported-versions-extension-required",
        ),
        (
            OnboardOutcome::NothingInCommon,
            "no-cipher-suites-in-common",
        ),
    ] {
        let record = one_of(handshakes, outcome, log)?;
        let reported = read(record, INCOMPATIBLE, log)?;
        if reported != owed {
            return Err(format!(
                "the appliance reports `{INCOMPATIBLE}={reported}` for the `{}` attempt and this \
                 client's offer earns `{owed}`. The token beside the outcome is what separates a \
                 client with no TLS 1.3 from one whose suites this appliance does not have, and \
                 those are different things to go and change: {record:?}\n  full run log: {}",
                outcome.name(),
                log.display()
            ));
        }
    }

    // And the offer itself, which is the whole reason the mismatch carries two
    // more records: an administrator compares what their client listed against
    // what this appliance has.
    let offered = suites_offered(text, log)?;
    if !offered.contains("0x1301") {
        return Err(format!(
            "the appliance reports the client offered `{offered}` and this client was told to \
             offer TLS_AES_128_GCM_SHA256, which is 0x1301. An offer record that does not carry \
             the offer is a record an administrator cannot act on\n  full run log: {}",
            log.display()
        ));
    }
    Ok(())
}

/// The handshake accounts the cryptography domain wrote, in emission order.
fn handshake_records(text: &str) -> Vec<&str> {
    ours(text, Domain::Crypto)
        .into_iter()
        .filter(|record| value(record, OUTCOME).is_some())
        .collect()
}

/// The one record carrying `outcome`, or a verdict naming what was there.
fn one_of<'a>(
    handshakes: &[&'a str],
    outcome: OnboardOutcome,
    log: &Path,
) -> Result<&'a str, String> {
    let found: Vec<&str> = handshakes
        .iter()
        .copied()
        .filter(|record| value(record, OUTCOME) == Some(outcome.name()))
        .collect();
    let [record] = found[..] else {
        return Err(format!(
            "this boot's records carry {} handshake(s) reporting `{}` and exactly one attempt \
             asked for it\n  records observed: {handshakes:#?}\n  full run log: {}",
            found.len(),
            outcome.name(),
            log.display()
        ));
    };
    Ok(record)
}

/// The suites the mismatching client offered, as the record beside the mismatch
/// lists them.
fn suites_offered(text: &str, log: &Path) -> Result<String, String> {
    ours(text, Domain::Crypto)
        .into_iter()
        .find_map(|record| value(record, SUITES))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            format!(
                "no `{SUITES}=` record was written beside the mismatch, so the offer the \
                 appliance refused reached no surface at all\n  full run log: {}",
                log.display()
            )
        })
}

/// The port's own `accepted` total, which the network end alone reports.
fn port_total(text: &str, log: &Path) -> Result<u64, String> {
    let found: Vec<&str> = ours(text, Domain::Management)
        .into_iter()
        .filter(|record| value(record, ACCEPTED).is_some())
        .collect();
    let last = found.last().ok_or_else(|| {
        format!(
            "the console carried no `{}` record stating the onboarding port's own totals, and one \
             goes out beside every session account\n  full run log: {}",
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        )
    })?;
    number(last, ACCEPTED, log)
}

/// The appliance's own identifier, as the store domain printed it.
fn device_identifier<'a>(text: &'a str, log: &Path) -> Result<&'a str, String> {
    ours(text, Domain::Store)
        .into_iter()
        .find_map(|record| value(record, DEVICE))
        .ok_or_else(|| {
            format!(
                "the console carried no `{DEVICE}=` record from the store domain, so there is no \
                 name to hold the certificate's subject to\n  full run log: {}",
                log.display()
            )
        })
}

/// One domain's `ready` lifecycle records.
fn ours(text: &str, domain: Domain) -> Vec<&str> {
    let ready = field("state", DomainState::Ready.name());
    lifecycle_records(text)
        .into_iter()
        .filter(|record| {
            record.contains(&field("domain", domain.name())) && record.contains(&ready)
        })
        .collect()
}

fn read<'a>(record: &'a str, key: &str, log: &Path) -> Result<&'a str, String> {
    value(record, key).ok_or_else(|| {
        format!(
            "{record:?} carries no `{key}=` field, and this record is specified with one\n  full \
             run log: {}",
            log.display()
        )
    })
}

fn number(record: &str, key: &str, log: &Path) -> Result<u64, String> {
    read(record, key, log)?
        .parse()
        .map_err(|error| format!("{record:?}: {key} is no number: {error}"))
}

/// What the run prints and appends to the log: every attempt, what it ran, and
/// what came back.
pub(crate) fn evidence(attempts: &[Attempt]) -> String {
    let mut out = String::from(
        "  the clients this boot ran against the onboarding port, in the order it ran them\n",
    );
    for attempt in attempts {
        out.push_str(&format!(
            "\n  {} — owes `{}`\n    $ {}\n    {}\n{}\n",
            attempt.name,
            attempt.owed.name(),
            attempt.command,
            attempt.status,
            indent(&attempt.transcript),
        ));
    }
    out
}

/// A transcript under the table's own margin, so a reader can tell the client's
/// words from the harness's.
fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("      | {line}\n"))
        .collect()
}
