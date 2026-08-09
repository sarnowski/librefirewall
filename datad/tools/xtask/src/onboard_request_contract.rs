//! The onboarding port's **request surface**, held to what `curl` and
//! `openssl` made of it on the booted image.
//!
//! [`crate::onboard_tls_contract`] judges the handshake; this judges what an
//! administrator does once one has completed. The client is `curl` because that
//! is what an administrator runs and because it shares no code with the
//! appliance, and the request it downloads is read back with `openssl req`,
//! which shares none either.
//!
//! # The fingerprint is the subject, not a detail of the setup
//!
//! Every request here is made with `--pinnedpubkey sha256//…`, and the digest
//! it pins is **the one the store domain printed on this same boot's console**,
//! converted from the hexadecimal the appliance renders to the base64 `curl`
//! spells it in and changed in no other way. That makes each of these a
//! mechanical performance of the administrator's own verification step rather
//! than a check that the port answers: a boot whose page said one thing and
//! whose certificate carried another would return a 200 to a plain `--insecure`
//! fetch and fail every one of these.
//!
//! The same digest then has to appear **inside** the page, because the page is
//! where an administrator reads it. So one boot states it three times — on the
//! console, in the certificate a real client validated against it, and in the
//! body that client read — and this holds all three to each other.
//!
//! # Why a failure is judged by the token and not by the status
//!
//! `curl` prints the status line and that is one party's account. What the
//! appliance owes an operator with no shell is a *token per cause*, so each
//! refusing attempt is held to its own token on the console; the status line is
//! compared beside it because a client and a console disagreeing about what
//! happened is itself a finding.
//!
//! # No adversary
//!
//! The clients are this harness's own and the console is the appliance's own
//! output on a wire only the harness is attached to.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use lfw_log::{Domain, DomainState, OnboardRefusal, OnboardRoute};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value};

/// The records this domain wrote once it was ready, which is where every
/// request's account rides.
fn ours(text: &str) -> Vec<&str> {
    let ready = field("state", DomainState::Ready.name());
    let domain = field("domain", Domain::Crypto.name());
    lifecycle_records(text)
        .into_iter()
        .filter(|record| record.contains(&domain) && record.contains(&ready))
        .collect()
}

/// The field a served request leads with, and the one a refused request does.
const SERVED: &str = "onboard-http";
const REFUSED: &str = "onboard-http-refused";
const STATUS: &str = "onboard-http-status";

/// The identifier and the fingerprint the store domain prints, which are what
/// the page and the certificate must carry.
const DEVICE: &str = "device";
const FINGERPRINT: &str = "fingerprint";

/// How long one client is given before the run gives up on it, on
/// [`crate::onboard_tls_contract`]'s terms.
pub(crate) const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// What one attempt asks for and what the appliance owes for it.
struct Ask {
    /// What this attempt is, in the words the evidence table uses.
    name: &'static str,
    /// The path, and the `curl` arguments that make this attempt what it is.
    target: &'static str,
    arguments: &'static [&'static str],
    owed: Owed,
}

/// What the console must say about one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owed {
    /// The named resource went back.
    Served(OnboardRoute),
    /// The request was refused under this token, and the peer was told this
    /// status.
    Refused(OnboardRefusal, u16),
}

/// The attempts, in the order one boot makes them.
///
/// The two that succeed go **first**, so the three refusals after them are
/// requests on a surface that has already served two — which is the property a
/// surface holding state across connections would fail. And the successes are
/// what an administrator really does, in the order the flow puts them: read the
/// page, then fetch what it links to.
const ASKS: [Ask; 5] = [
    Ask {
        name: "the page an administrator lands on",
        target: "/",
        arguments: &[],
        owed: Owed::Served(OnboardRoute::Page),
    },
    Ask {
        name: "the certificate signing request the page links to",
        target: "/certificate.csr",
        arguments: &[],
        owed: Owed::Served(OnboardRoute::CertificateRequest),
    },
    Ask {
        name: "an address this appliance does not serve",
        target: "/nope",
        arguments: &[],
        owed: Owed::Refused(OnboardRefusal::UnknownRoute, 404),
    },
    Ask {
        // The upload route, asked for with no package behind it. It is served,
        // so this is not the unknown-address refusal: what refuses it is that a
        // `POST` carrying no body is an upload of nothing, and that has a token
        // of its own because nothing was staged and no other domain's record
        // says anything about it. An administrator who forgot the
        // `--data-binary` reaches exactly this.
        name: "the configuration upload with no package behind it",
        target: "/configuration.tar",
        arguments: &["-X", "POST"],
        owed: Owed::Refused(OnboardRefusal::UploadEmpty, 400),
    },
    Ask {
        name: "the page under a method this surface does not serve it with",
        target: "/",
        arguments: &["-X", "POST"],
        owed: Owed::Refused(OnboardRefusal::MethodNotServed, 405),
    },
];

/// How many requests one boot's attempts make on the surface.
pub(crate) const REQUESTS: usize = ASKS.len();

/// What one attempt produced.
#[derive(Debug)]
pub struct Attempt {
    name: &'static str,
    command: String,
    status: String,
    transcript: String,
    owed: Owed,
    /// Where the body landed, for the attempt whose body is read back by
    /// another tool.
    body: Option<PathBuf>,
}

/// The fingerprint as `curl` spells a pin: base64 of the digest the console
/// prints in hexadecimal.
///
/// The one conversion in this file, and it changes no bit: what is pinned is
/// the appliance's own number, in the notation the client happens to take.
///
/// # Errors
/// A rendering that is not 64 hexadecimal characters, which is the store
/// domain's contract and so is a finding rather than something to work around.
pub(crate) fn pinned(fingerprint: &str) -> Result<String, String> {
    let bytes: Vec<u8> = fingerprint
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| {
                    format!(
                        "the fingerprint this boot printed is not hexadecimal: {fingerprint:?}. \
                         It is the one string an administrator compares, so a rendering that \
                         cannot be read back is a defect in what the appliance prints"
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    if bytes.len() != 32 {
        return Err(format!(
            "the fingerprint this boot printed is {} byte(s) and a SHA-256 digest is 32: \
             {fingerprint:?}",
            bytes.len()
        ));
    }
    Ok(base64(&bytes))
}

/// RFC 4648 base64, written out because this build has no such dependency and
/// one integer conversion does not earn one.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let packed = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(
                    ALPHABET[((packed >> (18 - 6 * index)) & 0x3f) as usize],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The device identifier and the fingerprint the store domain printed on this
/// boot.
///
/// # Errors
/// A boot that printed neither, which is a node with no identity and so a
/// finding before any request is made.
pub(crate) fn identity(serial: &[u8]) -> Result<(String, String), String> {
    let text = String::from_utf8_lossy(serial).into_owned();
    let ready = field("state", DomainState::Ready.name());
    let domain = field("domain", Domain::Store.name());
    let records: Vec<&str> = lifecycle_records(&text)
        .into_iter()
        .filter(|record| record.contains(&domain) && record.contains(&ready))
        .collect();
    let find = |key: &str| {
        records
            .iter()
            .find_map(|record| value(record, key))
            .map(str::to_owned)
    };
    match (find(DEVICE), find(FINGERPRINT)) {
        (Some(device), Some(fingerprint)) => Ok((device, fingerprint)),
        _ => Err(String::from(
            "this boot's store domain printed no `device=` and `fingerprint=` pair, so there is \
             no identity to pin a client to and nothing for the page to be compared against",
        )),
    }
}

/// Run every attempt against the forwarded port, nudging the appliance between
/// them.
///
/// [`crate::onboard_tls_contract::settle`] is called after each attempt for its
/// reason: the pass that writes a request's account runs after the client's
/// connection is gone, and nothing is put on the wire to provoke it — the
/// appliance's own periodic wakeup runs it.
///
/// # Errors
/// A client that could not be run at all, which is the harness's own failure
/// rather than the appliance's.
pub(crate) fn drive(
    onboard_port: u16,
    fingerprint: &str,
    into: &Path,
) -> Result<Vec<Attempt>, String> {
    let pin = pinned(fingerprint)?;
    let mut attempts = Vec::new();
    for (index, ask) in ASKS.iter().enumerate() {
        attempts.push(fetch(ask, index, onboard_port, &pin, into)?);
        crate::onboard_tls_contract::settle();
        crate::onboard_tls_contract::settle();
    }
    Ok(attempts)
}

/// How every client on this port reaches it: the arguments, and the pin that
/// authenticates the appliance to them.
///
/// One place rather than one per contract, because it is one statement about
/// what an administrator does — and the whole value of pinning is lost the
/// moment a second contract reaches the same port without it.
///
/// `--insecure` and a pin together is not a contradiction: the appliance has no
/// chain to validate — that is the whole point of the phase — and the pin is
/// what authenticates it. `--http1.1` because that is the only version this
/// surface speaks and a client that negotiated another would be testing a
/// different protocol.
pub(crate) fn client(pin: &str) -> Vec<String> {
    [
        "--silent",
        "--show-error",
        "--include",
        "--http1.1",
        "--insecure",
        "--pinnedpubkey",
    ]
    .iter()
    .map(|argument| (*argument).to_owned())
    .chain([format!("sha256//{pin}")])
    .collect()
}

/// One `curl` run against the port.
fn fetch(ask: &Ask, index: usize, port: u16, pin: &str, into: &Path) -> Result<Attempt, String> {
    let url = format!("https://127.0.0.1:{port}{}", ask.target);
    let body = into.join(format!("onboarding-request-{index}.body"));
    let arguments: Vec<String> = client(pin)
        .into_iter()
        .chain(ask.arguments.iter().map(|argument| (*argument).to_owned()))
        .chain(["--output".to_owned(), body.display().to_string()])
        .chain([url.clone()])
        .collect();
    let command = format!("curl {}", arguments.join(" "));
    let output = Command::new("curl")
        .args(&arguments)
        .arg("--max-time")
        .arg(CLIENT_TIMEOUT.as_secs().to_string())
        .output()
        .map_err(|error| format!("run `{command}`: {error}"))?;
    let mut transcript = fs::read_to_string(&body).unwrap_or_default();
    transcript.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(Attempt {
        name: ask.name,
        command,
        status: format!("{}", output.status),
        transcript: transcript.trim().to_owned(),
        owed: ask.owed,
        body: Some(body),
    })
}

/// Whether the appliance has finished reporting every attempt.
///
/// The observable a boot that runs these clients waits on, on the handshake
/// contract's terms: a request's record is written on the pass that decided it,
/// which runs after the client's own connection is already gone.
pub(crate) fn reported(serial: &[u8]) -> bool {
    let text = String::from_utf8_lossy(serial);
    request_records(&text).len() >= REQUESTS
}

/// Every record a request left, in the order the appliance wrote them.
///
/// A served one and a refused one lead with different keys, and they are read
/// as one sequence because what is being judged is one request per attempt in
/// order.
fn request_records(text: &str) -> Vec<&str> {
    ours(text)
        .into_iter()
        .filter(|record| value(record, SERVED).is_some() || value(record, REFUSED).is_some())
        .collect()
}

/// Judge one boot's attempts against the records the appliance left and the
/// bytes its clients read.
///
/// # Errors
/// The disagreement, naming the attempt, what was owed and what was observed,
/// and where the whole run log is.
pub(crate) fn judge(attempts: &[Attempt], serial: &[u8], log: &Path) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let records = request_records(&text);
    if records.len() != attempts.len() {
        return Err(format!(
            "this boot made {} request(s) on the onboarding surface and the cryptography domain \
             reported {}. One record per request is the whole contract: fewer is a request the \
             appliance answered and never accounted for, and more is one nobody made\n  records \
             observed: {records:#?}\n  full run log: {}",
            attempts.len(),
            records.len(),
            log.display()
        ));
    }

    for (attempt, record) in attempts.iter().zip(&records) {
        match attempt.owed {
            Owed::Served(route) => {
                let reported = read(record, SERVED, log)?;
                if reported != route.name() {
                    return Err(format!(
                        "{} drew `{SERVED}={reported}` and owes `{}`: {record:?}\n  full run \
                         log: {}",
                        attempt.name,
                        route.name(),
                        log.display()
                    ));
                }
            }
            Owed::Refused(refusal, status) => {
                let reported = read(record, REFUSED, log)?;
                if reported != refusal.name() {
                    return Err(format!(
                        "{} drew `{REFUSED}={reported}` and owes `{}`: {record:?}. Each way a \
                         request can be refused is a different thing for an administrator to go \
                         and change, so a token that stands for the wrong one is worse than no \
                         record at all\n  what the client said: {}\n  full run log: {}",
                        attempt.name,
                        refusal.name(),
                        attempt.transcript,
                        log.display()
                    ));
                }
                let told = read(record, STATUS, log)?;
                if told != status.to_string() {
                    return Err(format!(
                        "{} was told status {told} by the console record and owes {status}: \
                         {record:?}\n  full run log: {}",
                        attempt.name,
                        log.display()
                    ));
                }
                if !attempt.transcript.contains(&format!("HTTP/1.1 {status}")) {
                    return Err(format!(
                        "{} drew `{REFUSED}={}` on the console and the client did not read a \
                         {status}. A console and a client disagreeing about what happened is \
                         worse than either being wrong alone\n  what the client read: {}\n  full \
                         run log: {}",
                        attempt.name,
                        refusal.name(),
                        attempt.transcript,
                        log.display()
                    ));
                }
            }
        }
    }

    let (device, fingerprint) = identity(serial)?;
    let page = judge_page(attempts, &device, &fingerprint, log)?;
    let subject = judge_request(attempts, &device, log)?;
    Ok(format!(
        "{REQUESTS} requests reached the onboarding surface over one boot, every one of them \
         pinned to the fingerprint the store domain printed: {page}, {subject}, and \
         `{}`, `{}` each reported under their own token",
        OnboardRefusal::UnknownRoute.name(),
        OnboardRefusal::MethodNotServed.name(),
    ))
}

/// The page, held to the two strings the console printed.
fn judge_page(
    attempts: &[Attempt],
    device: &str,
    fingerprint: &str,
    log: &Path,
) -> Result<String, String> {
    let attempt = attempts
        .iter()
        .find(|attempt| attempt.owed == Owed::Served(OnboardRoute::Page))
        .ok_or_else(|| String::from("no attempt in this boot fetched the page"))?;
    if !attempt.transcript.contains("HTTP/1.1 200 OK") {
        return Err(format!(
            "the page did not answer 200\n  what the client read: {}\n  full run log: {}",
            attempt.transcript,
            log.display()
        ));
    }
    for (what, owed) in [("device identifier", device), ("fingerprint", fingerprint)] {
        if !attempt.transcript.contains(owed) {
            return Err(format!(
                "the page does not carry the {what} the store domain printed on this boot \
                 ({owed}). It is the string an administrator compares against the console, so a \
                 page that renders it differently is a page that will be compared carelessly\n  \
                 what the client read: {}\n  full run log: {}",
                attempt.transcript,
                log.display()
            ));
        }
    }
    Ok(format!(
        "the page carries `{device}` and the same fingerprint the console printed"
    ))
}

/// The request, read back by a tool that shares no code with the appliance.
fn judge_request(attempts: &[Attempt], device: &str, log: &Path) -> Result<String, String> {
    let attempt = attempts
        .iter()
        .find(|attempt| attempt.owed == Owed::Served(OnboardRoute::CertificateRequest))
        .ok_or_else(|| String::from("no attempt in this boot fetched the request"))?;
    let body = attempt
        .body
        .as_ref()
        .ok_or_else(|| String::from("the request attempt kept no body"))?;
    // The headers `--include` prepended have to go: what `openssl` is handed is
    // the encapsulated structure and nothing around it, which is what the
    // profile says travels.
    let downloaded =
        fs::read_to_string(body).map_err(|error| format!("read {}: {error}", body.display()))?;
    let begin = downloaded
        .find("-----BEGIN CERTIFICATE REQUEST-----")
        .ok_or_else(|| {
            format!(
                "the body served at /certificate.csr carries no `CERTIFICATE REQUEST` \
             encapsulation\n  what the client read: {downloaded}\n  full run log: {}",
                log.display()
            )
        })?;
    let pem = downloaded.get(begin..).unwrap_or_default();
    let pem_path = body.with_extension("csr");
    fs::write(&pem_path, pem).map_err(|error| format!("write {}: {error}", pem_path.display()))?;
    let read_back = Command::new("openssl")
        .args(["req", "-in"])
        .arg(&pem_path)
        .args(["-noout", "-subject", "-verify"])
        .output()
        .map_err(|error| format!("run `openssl req`: {error}"))?;
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&read_back.stdout),
        String::from_utf8_lossy(&read_back.stderr)
    );
    if !read_back.status.success() {
        return Err(format!(
            "`openssl req` would not read what /certificate.csr served, so what this appliance \
             emits is not what the management server parses\n  openssl said: {printed}\n  full \
             run log: {}",
            log.display()
        ));
    }
    // The subject as `openssl` renders it, which spaces the equals sign.
    if !printed.contains(&format!("CN = {device}")) && !printed.contains(&format!("CN={device}")) {
        return Err(format!(
            "the request's subject is not the device identifier this boot's store domain printed \
             ({device}). The subject common name is the appliance's whole name in the profile, so \
             a request naming anything else names another appliance\n  openssl said: {printed}\n  \
             full run log: {}",
            log.display()
        ));
    }
    // And the signature over it verifies, which is what says the delegated key
    // really signed the request rather than the encoding merely being
    // well-formed.
    if !printed.contains("verify OK") && !printed.contains("Certificate request self-signature") {
        return Err(format!(
            "`openssl req -verify` did not confirm the request's own signature\n  openssl said: \
             {printed}\n  full run log: {}",
            log.display()
        ));
    }
    Ok(format!(
        "`openssl req` reads the served request as `CN = {device}` with its signature verified"
    ))
}

/// One field of a record, or a finding naming what was missing.
fn read(record: &str, key: &str, log: &Path) -> Result<String, String> {
    value(record, key).map(str::to_owned).ok_or_else(|| {
        format!(
            "a request record carries no `{key}=`: {record:?}. The console is the only surface a \
             deployed node has, so a record missing the field that places it is a record that \
             says nothing\n  full run log: {}",
            log.display()
        )
    })
}

/// The clients this boot ran and what came back, as the evidence table.
pub(crate) fn evidence(attempts: &[Attempt]) -> String {
    let mut out = String::from(
        "  the requests this boot made on the onboarding surface, every one pinned to the \
         fingerprint the console printed:\n",
    );
    for attempt in attempts {
        out.push_str(&format!(
            "\n  {} —\n    $ {}\n",
            attempt.name, attempt.command
        ));
        out.push_str(&format!("    exit: {}\n", attempt.status));
        for line in attempt.transcript.lines() {
            out.push_str(&format!("    {line}\n"));
        }
    }
    // Named so a reader of the table knows which channel the verdict came from.
    out.push_str(&format!(
        "\n  (judged against `{LIFECYCLE_PREFIX}` records)\n"
    ));
    out
}
