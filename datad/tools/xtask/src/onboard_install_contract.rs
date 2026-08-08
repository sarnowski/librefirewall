//! The **management server's** half of onboarding, played by this harness
//! against a booted image.
//!
//! [`crate::onboard_request_contract`] is an administrator reading what the
//! appliance serves. This is what an administrator does next: carry the
//! certificate signing request to the application that issues, and carry a
//! package back. So this module is a certification authority, a package writer
//! and a client — the three things the management server is on this path — and
//! the appliance under it is driven along exactly the sequence a real one is.
//!
//! # The certification authority is this checkout's, and it is not committed
//!
//! Signing needs a key, and a key in a repository is a key that has escaped. So
//! the authority is generated on demand under the build tree, on the payload
//! signing key's own terms ([`crate::signing`]): once per checkout, never
//! committed, removed by `clean`. Nothing about it is a secret worth keeping —
//! it owns one appliance that exists for the length of a gate run — and that is
//! precisely why it must not look like one that is.
//!
//! # Every artifact is composed by something that is not the appliance
//!
//! The request is read back by `openssl req`, the certificate is issued by
//! `openssl x509`, the anchor's fingerprint is taken with `openssl` and
//! `sha256sum`, and the archive is written here. None of that shares code with
//! the reader under test, which is the whole point: a package this harness
//! composed out of the appliance's own writer would prove that the appliance
//! agrees with itself.
//!
//! What is *not* restated here is the contract. The four member names, the
//! block size and the token every refusal is named by come from `lfw_package`,
//! because a second copy of the format in the thing judging the format is the
//! drift every dependency in this crate's manifest exists to close.
//!
//! # Why the refusals go first
//!
//! An accepted package shuts the surface, so a boot's install is its last
//! decision: everything after it is `already-owned` whatever it asked for.
//! Refusals therefore precede the install, and the two after it are what say
//! the close happened — the page an administrator would land on is gone, and so
//! is the route that took the package.
//!
//! # No adversary
//!
//! The clients are this harness's own and the console is the appliance's own
//! output on a wire only the harness is attached to. What the appliance faces
//! here is the management-plane party the onboarding trust model hands it to:
//! whoever reaches the port first becomes the owner, and this run is that party.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use lfw_log::{Domain, DomainState, OnboardRefusal, OnboardRoute};
use lfw_package::{ArchiveError, BLOCK, Member, PackageError};

use crate::artifacts::BUILD_DEV_CA_DIR;
use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value};
use crate::forward_harness::{DIAL_DESTINATION, DIAL_PORT};
use crate::image::CONFIGURATION_DOCUMENT;
use crate::onboard_request_contract::{CLIENT_TIMEOUT, client, pinned};
use crate::store_contract::Identity;
use crate::util::run_command;

/// The authority's private key and certificate, under the build tree.
const CA_KEY: &str = "management-ca.key";
const CA_CERTIFICATE: &str = "management-ca.pem";

/// The name the authority gives itself. The certificate profile leaves it to
/// the server, and this one says what it is so a certificate found anywhere
/// near a production fleet is unmistakable.
const CA_SUBJECT: &str = "/CN=librefirewall development management CA";

/// The validity every certificate here is issued for, as the profile fixes it.
const VALIDITY_DAYS: &str = "3650";

/// The extensions the authority puts in a device certificate.
///
/// Exactly the profile's row and nothing the request asked for: `x509 -req`
/// copies no extension out of a certificate signing request, so what is issued
/// is what is written here.
const DEVICE_EXTENSIONS: &str = "basicConstraints=critical,CA:FALSE\n\
                                 keyUsage=critical,digitalSignature\n\
                                 extendedKeyUsage=clientAuth\n";

/// Where the package that adopted an appliance is left, so the boot that
/// inherits that appliance's medium can offer the very same bytes back.
///
/// One file rather than a name per boot: exactly one scenario writes it and
/// exactly one reads it, and a second name would be a second thing to keep in
/// step with the pair.
const ADOPTION_PACKAGE: &str = "onboarding-adoption-package.tar";

/// The package a **different** appliance's key was certified into, which the
/// management server itself composed and this repository carries as a fixture.
///
/// Uploading it needs nothing composed at all: it is a well-formed package for
/// somebody else, which is the one refusal an administrator is most likely to
/// cause by hand and the only one this harness gets for free.
const OTHER_APPLIANCES_PACKAGE: &str = "crates/package/fixtures/management-server-package.tar";

/// What one attempt asks of the appliance, and what the appliance owes for it.
struct Ask {
    name: &'static str,
    target: &'static str,
    /// The package this attempt uploads, where it uploads one.
    body: Option<PathBuf>,
    owed: Owed,
}

/// What the console must say about one attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Owed {
    /// The named resource went back.
    Served(OnboardRoute),
    /// The package was installed, and this appliance now has an owner.
    Installed,
    /// The request was refused under this token with this status — and, where
    /// the package reached the reader, under the rule of the package contract
    /// that refused it.
    ///
    /// Two tokens rather than one, because they are written by two different
    /// decisions: the surface's says a package was judged and refused, and the
    /// package contract's says which rule did it. An operator reads both, and a
    /// harness that checked only the first would pass on an appliance that
    /// refused every package for the same reason.
    Refused {
        refusal: OnboardRefusal,
        status: u16,
        rule: Option<&'static str>,
    },
}

/// What one attempt produced.
#[derive(Debug)]
pub struct Attempt {
    name: &'static str,
    command: String,
    status: String,
    transcript: String,
    owed: Owed,
}

/// What the management server minted for one appliance, kept so the appliance's
/// own account of the install can be held to it.
#[derive(Debug)]
pub struct Adoption {
    /// The appliance the request named, as `openssl req` read its subject back
    /// — which is what this authority certified and so what it must have been
    /// handed.
    subject: String,
    /// SHA-256 over the DER `SubjectPublicKeyInfo` of the authority's
    /// certificate, in the profile's own rendering — which is the number the
    /// appliance must print once the anchor is durable.
    anchor_fingerprint: String,
    /// The endpoint line the package carries, split as the console prints it.
    destination: String,
    port: u16,
    /// Bytes of archive, which is what the surface's own record states.
    package_len: usize,
}

/// What one boot's management server did, and what it minted while doing it.
#[derive(Debug)]
pub struct Onboarded {
    attempts: Vec<Attempt>,
    /// What was issued, on the boot that onboarded. `None` on the boot that
    /// meets an appliance somebody already owns, which issues nothing because
    /// there is nothing left to ask for.
    adoption: Option<Adoption>,
}

impl Onboarded {
    /// Whether this boot took delivery of a package.
    pub(crate) const fn adopted(&self) -> bool {
        self.adoption.is_some()
    }

    /// Whether the appliance has said everything this boot's clients are owed.
    ///
    /// The observable the run waits on rather than an interval: a request's
    /// record is written on the pass that decided it, which runs after the
    /// client's own connection is already gone, and an install's record is the
    /// installing domain's and arrives behind it.
    pub(crate) fn reported(&self, serial: &[u8]) -> bool {
        let text = String::from_utf8_lossy(serial);
        request_records(&text).len() >= self.attempts.len()
            && (!self.adopted() || adopted(&text).is_some())
    }
}

/// Play the management server against an appliance that has never met one.
///
/// `nudge` is called between attempts on [`crate::onboard_tls_contract`]'s
/// terms: the domain that carries a session holds no timer, and the pass that
/// writes a request's account runs after the client's connection is gone.
///
/// # Errors
/// A tool that would not run, a request the appliance would not serve, or a
/// request whose subject is not the appliance the console named — each of which
/// is the management server refusing to issue, and so a finding before a single
/// package is composed.
pub(crate) fn onboard(
    root: &Path,
    onboard_port: u16,
    fingerprint: &str,
    device: &str,
    into: &Path,
    mut nudge: impl FnMut() -> Result<(), String>,
) -> Result<Onboarded, String> {
    let pin = pinned(fingerprint)?;
    let mut attempts = Vec::new();

    // The one thing an administrator carries away from the appliance.
    let request = Ask {
        name: "the certificate signing request this appliance serves",
        target: "/certificate.csr",
        body: None,
        owed: Owed::Served(OnboardRoute::CertificateRequest),
    };
    let fetched = run(&request, 0, onboard_port, &pin, into)?;
    let subject = issue_to(root, into, &fetched, device)?;
    attempts.push(fetched);
    nudge()?;
    nudge()?;

    let anchor_fingerprint = anchor_fingerprint(root, into)?;
    let (package, package_len) = compose(root, into)?;
    let not_ustar = without_the_ustar_magic(&package, into)?;

    for (index, ask) in [
        Ask {
            // A package the management server really produced, for a device key
            // that is not this one's. Nothing about it is malformed, which is
            // what makes it the sharper of the two refusals: an appliance that
            // installed this would install anybody's identity.
            name: "a well-formed package certified to another appliance's key",
            target: "/configuration.tar",
            body: Some(root.join(OTHER_APPLIANCES_PACKAGE)),
            owed: Owed::Refused {
                refusal: OnboardRefusal::PackageRefused,
                status: 400,
                rule: Some(PackageError::DeviceKeyIsNotThisAppliance.cause()),
            },
        },
        Ask {
            // This appliance's own package with one header's magic replaced, so
            // the only thing wrong with it is that it is not the tar this
            // contract accepts.
            name: "this appliance's package in an archive that is not ustar",
            target: "/configuration.tar",
            body: Some(not_ustar),
            owed: Owed::Refused {
                refusal: OnboardRefusal::PackageRefused,
                status: 400,
                rule: Some(PackageError::Archive(ArchiveError::NotUstar { at: 0 }).cause()),
            },
        },
        Ask {
            name: "the package this management server issued to this appliance",
            target: "/configuration.tar",
            body: Some(package.clone()),
            owed: Owed::Installed,
        },
        Ask {
            // The page is where an administrator lands, so its absence is what
            // an administrator meets first on an appliance that has an owner.
            name: "the page, on a connection opened after the install",
            target: "/",
            body: None,
            owed: Owed::Refused {
                refusal: OnboardRefusal::AlreadyOwned,
                status: 410,
                rule: None,
            },
        },
        Ask {
            name: "the same package again, on an appliance that now has an owner",
            target: "/configuration.tar",
            body: Some(package),
            owed: Owed::Refused {
                refusal: OnboardRefusal::AlreadyOwned,
                status: 410,
                rule: None,
            },
        },
    ]
    .into_iter()
    .enumerate()
    {
        attempts.push(run(&ask, index + 1, onboard_port, &pin, into)?);
        nudge()?;
        nudge()?;
    }

    Ok(Onboarded {
        attempts,
        adoption: Some(Adoption {
            subject,
            anchor_fingerprint,
            destination: destination(),
            port: DIAL_PORT,
            package_len,
        }),
    })
}

/// Come back to an appliance a previous boot of this run took ownership of.
///
/// Every address, including the one that took the package — and including the
/// very package that was accepted, so what is being shown is a route that is
/// gone rather than a package that stopped being good.
///
/// # Errors
/// A client that would not run, or a package the onboarding boot did not leave
/// behind — which means the pair is out of order in the scenario table and the
/// claim would be vacuous.
pub(crate) fn revisit(
    onboard_port: u16,
    fingerprint: &str,
    into: &Path,
    mut nudge: impl FnMut() -> Result<(), String>,
) -> Result<Onboarded, String> {
    let pin = pinned(fingerprint)?;
    let package = into.join(ADOPTION_PACKAGE);
    if !package.is_file() {
        return Err(format!(
            "the package that adopted this appliance is not at {}, so this boot has nothing to \
             offer an owned appliance back. The boot that onboarded it leaves it there, so this \
             means the two are out of order in the scenario table",
            package.display()
        ));
    }
    let mut attempts = Vec::new();
    for (index, ask) in [
        Ask {
            name: "the page, on an appliance that came back owned",
            target: "/",
            body: None,
            owed: Owed::Refused {
                refusal: OnboardRefusal::AlreadyOwned,
                status: 410,
                rule: None,
            },
        },
        Ask {
            name: "the certificate signing request, on the same appliance",
            target: "/certificate.csr",
            body: None,
            owed: Owed::Refused {
                refusal: OnboardRefusal::AlreadyOwned,
                status: 410,
                rule: None,
            },
        },
        Ask {
            name: "the package this appliance itself accepted, offered again",
            target: "/configuration.tar",
            body: Some(package),
            owed: Owed::Refused {
                refusal: OnboardRefusal::AlreadyOwned,
                status: 410,
                rule: None,
            },
        },
    ]
    .into_iter()
    .enumerate()
    {
        attempts.push(run(&ask, index, onboard_port, &pin, into)?);
        nudge()?;
        nudge()?;
    }
    Ok(Onboarded {
        attempts,
        adoption: None,
    })
}

/// One `curl` run against the forwarded onboarding port.
fn run(ask: &Ask, index: usize, port: u16, pin: &str, into: &Path) -> Result<Attempt, String> {
    let url = format!("https://127.0.0.1:{port}{}", ask.target);
    let body = into.join(format!("onboarding-install-{index}.body"));
    let upload = match &ask.body {
        // `Expect:` is emptied deliberately: `curl` offers a hundred-continue
        // for a body this size, this surface answers one request per connection
        // and never that, and the client would then spend a second of its own
        // waiting for a reply nobody owes it.
        Some(package) => vec![
            "-X".to_owned(),
            "POST".to_owned(),
            "-H".to_owned(),
            "Expect:".to_owned(),
            "--data-binary".to_owned(),
            format!("@{}", package.display()),
        ],
        None => Vec::new(),
    };
    let arguments: Vec<String> = client(pin)
        .into_iter()
        .chain(upload)
        .chain(["--output".to_owned(), body.display().to_string()])
        .chain([url])
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
        owed: ask.owed.clone(),
    })
}

/// Read the served request back, hold its subject to the appliance the console
/// named, and issue a certificate over it.
///
/// The two happen in one step because the second must not happen without the
/// first: a certification authority that signed whatever it was handed would be
/// certifying a name it never read.
fn issue_to(root: &Path, into: &Path, fetched: &Attempt, device: &str) -> Result<String, String> {
    let begin = fetched
        .transcript
        .find("-----BEGIN CERTIFICATE REQUEST-----")
        .ok_or_else(|| {
            format!(
                "the appliance served no `CERTIFICATE REQUEST` encapsulation, so this management \
                 server has nothing to issue over\n  what the client read: {}",
                fetched.transcript
            )
        })?;
    let request = into.join("appliance.csr");
    let pem = fetched.transcript.get(begin..).unwrap_or_default();
    fs::write(&request, pem).map_err(|error| format!("write {}: {error}", request.display()))?;

    let read_back = capture(
        Command::new("openssl")
            .args(["req", "-in"])
            .arg(&request)
            .args(["-noout", "-subject", "-verify"]),
        "read the served certificate signing request",
    )?;
    // The subject as `openssl` renders it, which spaces the equals sign.
    if !read_back.contains(&format!("CN = {device}"))
        && !read_back.contains(&format!("CN={device}"))
    {
        return Err(format!(
            "the request's subject is not the device identifier this boot's store domain printed \
             ({device}), so a management server issuing over it would be certifying another \
             appliance's name\n  openssl said: {read_back}"
        ));
    }
    if !read_back.contains("verify OK") && !read_back.contains("Certificate request self-signature")
    {
        return Err(format!(
            "`openssl req -verify` did not confirm the request's own signature, so nothing proves \
             the appliance holds the key it asked to have certified\n  openssl said: {read_back}"
        ));
    }

    let (key, certificate) = authority(root)?;
    let extensions = into.join("device-certificate.ext");
    fs::write(&extensions, DEVICE_EXTENSIONS)
        .map_err(|error| format!("write {}: {error}", extensions.display()))?;
    let issued = into.join("device-certificate.pem");
    run_command(
        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(&request)
            .arg("-CA")
            .arg(&certificate)
            .arg("-CAkey")
            .arg(&key)
            .args(["-set_serial", &serial()?])
            .args(["-days", VALIDITY_DAYS, "-sha256", "-extfile"])
            .arg(&extensions)
            .arg("-out")
            .arg(&issued),
        "issue the device certificate",
    )
    .map_err(|error| error.to_string())?;
    Ok(device.to_owned())
}

/// The authority's key and certificate, generated once per checkout.
///
/// Generated on demand rather than by a build step, because only a run that
/// issues needs one: a checkout that never boots a scenario never mints a
/// certification authority at all.
fn authority(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    let home = root.join(BUILD_DEV_CA_DIR);
    let key = home.join(CA_KEY);
    let certificate = home.join(CA_CERTIFICATE);
    if certificate.is_file() && key.is_file() {
        return Ok((key, certificate));
    }
    fs::create_dir_all(&home).map_err(|error| format!("create {}: {error}", home.display()))?;
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
        "generate the development authority's key",
    )
    .map_err(|error| error.to_string())?;
    run_command(
        Command::new("openssl")
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key)
            .args(["-sha256", "-days", VALIDITY_DAYS, "-subj", CA_SUBJECT])
            .args(["-set_serial", &serial()?])
            .args([
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign",
            ])
            .arg("-out")
            .arg(&certificate),
        "generate the development authority's certificate",
    )
    .map_err(|error| error.to_string())?;
    Ok((key, certificate))
}

/// A random 128-bit positive serial number, as `openssl` takes one.
///
/// The profile asks the issuer's own generator for it, and the host's is what
/// this issuer has. The leading byte is bounded on both sides deliberately: a
/// high bit set would make a DER encoder widen the integer to seventeen octets
/// to keep it positive, and a leading zero byte would narrow it to fewer than
/// the hundred and twenty-eight bits asked for.
///
/// # Errors
/// A generator that would not answer, which is a machine this harness cannot
/// issue on.
fn serial() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| format!("draw a serial number: {error}"))?;
    bytes[0] = (bytes[0] & 0x3f) | 0x40;
    let mut out = String::from("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// The fingerprint the appliance must print once the anchor is durable.
///
/// Computed from the authority's certificate by the profile's own definition —
/// SHA-256 over the DER `SubjectPublicKeyInfo`, 64 lowercase hexadecimal
/// characters — with `openssl` and `sha256sum`, neither of which shares code
/// with the appliance. It is the one number in this contract that the harness
/// knows before the appliance says it.
fn anchor_fingerprint(root: &Path, into: &Path) -> Result<String, String> {
    let (_, certificate) = authority(root)?;
    let armoured = into.join("management-ca-spki.pem");
    let der = into.join("management-ca-spki.der");
    run_command(
        Command::new("openssl")
            .args(["x509", "-in"])
            .arg(&certificate)
            .args(["-noout", "-pubkey", "-out"])
            .arg(&armoured),
        "export the authority's public key",
    )
    .map_err(|error| error.to_string())?;
    run_command(
        Command::new("openssl")
            .args(["pkey", "-pubin", "-in"])
            .arg(&armoured)
            .args(["-outform", "DER", "-out"])
            .arg(&der),
        "encode the authority's public key",
    )
    .map_err(|error| error.to_string())?;
    let digest = capture(
        Command::new("sha256sum").arg(&der),
        "digest the authority's public key",
    )?;
    let rendered = digest.split_whitespace().next().unwrap_or_default();
    if rendered.len() != 64 {
        return Err(format!(
            "the authority's key digested to {} character(s) and a SHA-256 digest renders as 64: \
             {digest:?}",
            rendered.len()
        ));
    }
    Ok(rendered.to_owned())
}

/// Compose the package, and leave it where the boot that inherits this
/// appliance's medium can find it. Answers its length beside it, which is what
/// the appliance's own record of the upload states.
fn compose(root: &Path, into: &Path) -> Result<(PathBuf, usize), String> {
    let (_, certificate) = authority(root)?;
    let archive = package(
        &read(&into.join("device-certificate.pem"))?,
        &read(&certificate)?,
        format!("{}:{DIAL_PORT}\n", destination()).as_bytes(),
        // The document the image under test was built from, which is one this
        // appliance accepts by construction: the fast gate puts it through the
        // same reader the configuration domain runs at boot, so a package
        // refused for its document would be a finding about the reader rather
        // than about anything this composed.
        &read(&root.join(CONFIGURATION_DOCUMENT))?,
    );
    let path = into.join(ADOPTION_PACKAGE);
    fs::write(&path, &archive).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok((path, archive.len()))
}

/// The four members in a plain uncompressed ustar archive, written to the
/// package contract.
///
/// The names, the block size and the member set come from the reader's own
/// crate; what is written here is the framing around them, which is the part a
/// writer can get wrong.
fn package(
    device_certificate: &[u8],
    trust_anchor: &[u8],
    endpoint: &[u8],
    configuration: &[u8],
) -> Vec<u8> {
    let mut archive = Vec::new();
    for (member, content) in [
        (Member::DeviceCertificate, device_certificate),
        (Member::TrustAnchor, trust_anchor),
        (Member::ManagementEndpoint, endpoint),
        (Member::Configuration, configuration),
    ] {
        write_member(&mut archive, member, content);
    }
    // The two closing blocks the format ends with.
    archive.resize(archive.len() + 2 * BLOCK, 0);
    archive
}

/// One member: a ustar header, the content, and the padding to a whole block.
fn write_member(archive: &mut Vec<u8>, member: Member, content: &[u8]) {
    let mut header = [0_u8; BLOCK];
    let name = member.name();
    header[..name.len()].copy_from_slice(name);
    header[100..107].copy_from_slice(b"0000644");
    header[108..115].copy_from_slice(b"0000000");
    header[116..123].copy_from_slice(b"0000000");
    header[124..135].copy_from_slice(format!("{:011o}", content.len()).as_bytes());
    header[136..147].copy_from_slice(b"15234352100");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    checksum(&mut header);
    archive.extend_from_slice(&header);
    archive.extend_from_slice(content);
    let remainder = content.len() % BLOCK;
    if remainder != 0 {
        archive.resize(archive.len() + BLOCK - remainder, 0);
    }
}

/// A header's checksum, over the header with its own checksum field blanked —
/// which is the one rule of a tar header that is not a field but an arithmetic.
fn checksum(header: &mut [u8; BLOCK]) {
    header[148..156].copy_from_slice(b"        ");
    let sum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
}

/// The same archive with the first header's magic replaced and its checksum
/// recomputed, so exactly one rule of the format refuses it.
///
/// Recomputed rather than left stale on purpose: an archive with two faults in
/// it would be refused by whichever the reader reaches first, and a contract
/// asserting a token it did not isolate is asserting the reader's order.
fn not_ustar(archive: &[u8]) -> Result<Vec<u8>, String> {
    let mut broken = archive.to_vec();
    let Some(header) = broken.get_mut(..BLOCK) else {
        return Err(String::from(
            "the package this run composed is shorter than one tar block, which is a defect in \
             this harness's own writer rather than anything the appliance did",
        ));
    };
    let mut block: [u8; BLOCK] = header.try_into().unwrap_or([0; BLOCK]);
    block[257..263].copy_from_slice(b"gnutar");
    checksum(&mut block);
    header.copy_from_slice(&block);
    Ok(broken)
}

/// The archive above, written where a client can upload it.
fn without_the_ustar_magic(package: &Path, into: &Path) -> Result<PathBuf, String> {
    let broken = not_ustar(&read(package)?)?;
    let path = into.join("onboarding-not-ustar.tar");
    fs::write(&path, &broken).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(path)
}

/// The endpoint the package names: the address this appliance already dials,
/// so the ownership it is given points where the run's own station answers.
fn destination() -> String {
    let [a, b, c, d] = DIAL_DESTINATION;
    format!("{a}.{b}.{c}.{d}")
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

/// Run a command for what it printed, on **both** streams.
///
/// Both because `openssl` splits one answer across them: `req` prints the
/// subject on one and its verdict on the signature on the other, and a reader
/// that took only the first would judge a request nothing verified.
fn capture(command: &mut Command, what: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("{what}: {error}"))?;
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(printed)
    } else {
        Err(format!("{what}: {printed}"))
    }
}

/// The field a served, an installed and a refused request lead with.
const SERVED: &str = "onboard-http";
const INSTALLED: &str = "onboard-http-installed";
const REFUSED: &str = "onboard-http-refused";
const STATUS: &str = "onboard-http-status";

/// The three fields the installing domain writes once ownership is durable.
const ANCHOR: &str = "anchor-fingerprint";
const ENDPOINT: &str = "adopted-endpoint";
const PORT: &str = "adopted-port";
const GENERATION: &str = "adopted-generation";

/// The records the domain that terminated these requests wrote once it was
/// ready, which is where every request's account rides.
fn ours(text: &str) -> Vec<&str> {
    domains(text, Domain::Crypto)
}

/// The records the domain that holds the device key wrote, which is where an
/// install's own account rides.
fn theirs(text: &str) -> Vec<&str> {
    domains(text, Domain::Store)
}

fn domains(text: &str, domain: Domain) -> Vec<&str> {
    let ready = field("state", DomainState::Ready.name());
    let named = field("domain", domain.name());
    lifecycle_records(text)
        .into_iter()
        .filter(|record| record.contains(&named) && record.contains(&ready))
        .collect()
}

/// Every record a request left, in the order the appliance wrote them.
fn request_records(text: &str) -> Vec<&str> {
    ours(text)
        .into_iter()
        .filter(|record| {
            value(record, SERVED).is_some()
                || value(record, INSTALLED).is_some()
                || value(record, REFUSED).is_some()
        })
        .collect()
}

/// The record naming where an adopted appliance answers to, or nothing on a
/// boot that adopted nobody.
fn adopted(text: &str) -> Option<&str> {
    theirs(text)
        .into_iter()
        .find(|record| value(record, ENDPOINT).is_some())
}

/// Judge one boot's management server against the records the appliance left.
///
/// `identity` is the store domain's own account of itself on this boot, taken
/// rather than re-read: what an install changes is that record, so the contract
/// is between the two and a second parse of one of them would be this harness
/// agreeing with itself.
///
/// # Errors
/// The disagreement, naming the attempt, what was owed and what was observed,
/// and where the whole run log is.
pub(crate) fn judge(
    onboarded: &Onboarded,
    identity: &Identity,
    serial: &[u8],
    log: &Path,
) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let records = ours(&text);
    let requests: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| {
            value(record, SERVED).is_some()
                || value(record, INSTALLED).is_some()
                || value(record, REFUSED).is_some()
        })
        .map(|(at, _)| at)
        .collect();
    if requests.len() != onboarded.attempts.len() {
        return Err(format!(
            "this boot made {} request(s) on the onboarding surface and the cryptography domain \
             reported {}. One record per request is the whole contract: fewer is a request the \
             appliance answered and never accounted for, and more is one nobody made\n  records \
             observed: {records:#?}\n  full run log: {}",
            onboarded.attempts.len(),
            requests.len(),
            log.display()
        ));
    }

    for (position, (attempt, at)) in onboarded.attempts.iter().zip(&requests).enumerate() {
        let record = records.get(*at).copied().unwrap_or_default();
        // Where the rule that refused a package is written: after the surface's
        // own record and before the next request's, which is the window one
        // decision owns.
        let until = requests.get(position + 1).copied().unwrap_or(records.len());
        let following = records.get(at.saturating_add(1)..until).unwrap_or_default();
        judge_attempt(attempt, record, following, onboarded, log)?;
    }

    match &onboarded.adoption {
        Some(adoption) => {
            let install = judge_install(adoption, identity, &text, log)?;
            Ok(format!(
                "this harness played the management server against an unowned appliance: it read \
                 the request it serves as `{}`, issued against a development authority of this \
                 checkout's own, and had the package refused twice by name before it was taken — \
                 `{}` and `{}` — then {install}, after which the page and the upload route were \
                 both `{}`",
                adoption.subject,
                PackageError::DeviceKeyIsNotThisAppliance.cause(),
                PackageError::Archive(ArchiveError::NotUstar { at: 0 }).cause(),
                OnboardRefusal::AlreadyOwned.name(),
            ))
        }
        None => {
            if let Some(record) = adopted(&text) {
                return Err(format!(
                    "this boot installed a package and its whole subject is an appliance that \
                     already has an owner: {record:?}. An appliance that can be onboarded twice \
                     has no owner at all\n  full run log: {}",
                    log.display()
                ));
            }
            if !identity.onboarded {
                return Err(format!(
                    "this boot reloaded the medium a package was installed on and reports itself \
                     unowned: {}. The ownership is read off the medium on every boot, so an \
                     unowned reading means the close was a flag a restart cleared\n  full run \
                     log: {}",
                    identity.summary(),
                    log.display()
                ));
            }
            Ok(format!(
                "the appliance came back owned and served nothing at all: {} address(es) asked \
                 for on an owned appliance, every one of them `{}`, the package it accepted \
                 included",
                onboarded.attempts.len(),
                OnboardRefusal::AlreadyOwned.name(),
            ))
        }
    }
}

/// One attempt against the record it drew and whatever the same decision wrote
/// after it.
fn judge_attempt(
    attempt: &Attempt,
    record: &str,
    following: &[&str],
    onboarded: &Onboarded,
    log: &Path,
) -> Result<(), String> {
    match &attempt.owed {
        Owed::Served(route) => {
            let reported = read_field(record, SERVED, log)?;
            if reported != route.name() {
                return Err(format!(
                    "{} drew `{SERVED}={reported}` and owes `{}`: {record:?}\n  full run log: {}",
                    attempt.name,
                    route.name(),
                    log.display()
                ));
            }
            expect_status(attempt, 200, log)
        }
        Owed::Installed => {
            let reported = read_field(record, INSTALLED, log)?;
            let owed = onboarded
                .adoption
                .as_ref()
                .map_or(0, |adoption| adoption.package_len);
            if reported != owed.to_string() {
                return Err(format!(
                    "the appliance installed {reported} byte(s) and this management server \
                     uploaded {owed}: {record:?}. The two are the same archive or the surface \
                     counted something other than what it took\n  full run log: {}",
                    log.display()
                ));
            }
            expect_status(attempt, 200, log)
        }
        Owed::Refused {
            refusal,
            status,
            rule,
        } => {
            let reported = read_field(record, REFUSED, log)?;
            if reported != refusal.name() {
                return Err(format!(
                    "{} drew `{REFUSED}={reported}` and owes `{}`: {record:?}. Each way a request \
                     can be refused is a different thing for an administrator to go and change, \
                     so a token that stands for the wrong one is worse than no record at all\n  \
                     what the client said: {}\n  full run log: {}",
                    attempt.name,
                    refusal.name(),
                    attempt.transcript,
                    log.display()
                ));
            }
            let told = read_field(record, STATUS, log)?;
            if told != status.to_string() {
                return Err(format!(
                    "{} was told status {told} by the console record and owes {status}: \
                     {record:?}\n  full run log: {}",
                    attempt.name,
                    log.display()
                ));
            }
            expect_status(attempt, *status, log)?;
            let Some(rule) = rule else {
                return Ok(());
            };
            let rule = *rule;
            let named = following
                .iter()
                .filter_map(|record| value(record, "cause"))
                .any(|cause| cause == rule);
            if !named {
                return Err(format!(
                    "{} was refused under `{}` and the package contract's own rule was never \
                     named beside it. `{}` says a package was judged and refused; which rule did \
                     it is what an administrator opens a file about, so a refusal without it is a \
                     refusal that told them nothing\n  what the domain wrote after it: \
                     {following:#?}\n  full run log: {}",
                    attempt.name,
                    refusal.name(),
                    refusal.name(),
                    log.display()
                ));
            }
            Ok(())
        }
    }
}

/// What the client read, held to the status the console says it was told.
///
/// Beside the record rather than instead of it: a client and a console
/// disagreeing about what happened is worse than either being wrong alone.
fn expect_status(attempt: &Attempt, status: u16, log: &Path) -> Result<(), String> {
    if attempt.transcript.contains(&format!("HTTP/1.1 {status}")) {
        return Ok(());
    }
    Err(format!(
        "{} did not read a {status} from the appliance\n  what the client read: {}\n  full run \
         log: {}",
        attempt.name,
        attempt.transcript,
        log.display()
    ))
}

/// The installing domain's own account of the ownership it made durable.
fn judge_install(
    adoption: &Adoption,
    identity: &Identity,
    text: &str,
    log: &Path,
) -> Result<String, String> {
    if identity.onboarded {
        return Err(format!(
            "the store domain reported itself already owned before this boot's management server \
             uploaded anything: {}. The whole of what this scenario proves is an appliance \
             changing hands, and one that began owned changed nothing\n  full run log: {}",
            identity.summary(),
            log.display()
        ));
    }
    let records = theirs(text);
    let anchors: Vec<&str> = records
        .iter()
        .filter_map(|record| value(record, ANCHOR))
        .collect();
    let [printed] = anchors[..] else {
        return Err(format!(
            "the console carried {} `{ANCHOR}=` record(s) and an install writes exactly one. It \
             is the number an administrator compares against what the management server showed \
             them, so an appliance that printed none has accepted an authority nobody can check\n \
             store records observed: {records:#?}\n  full run log: {}",
            anchors.len(),
            log.display()
        ));
    };
    if printed != adoption.anchor_fingerprint {
        return Err(format!(
            "the appliance printed anchor fingerprint {printed} and this management server's \
             authority digests to {}. The two are the same key or the appliance installed an \
             anchor other than the one in the package it took\n  full run log: {}",
            adoption.anchor_fingerprint,
            log.display()
        ));
    }
    let Some(record) = adopted(text) else {
        return Err(format!(
            "the appliance took a package and never said where it will answer to. The endpoint is \
             what the ownership is *for*, and a node that installed one silently leaves an \
             operator with nothing to check it against\n  store records observed: {records:#?}\n  \
             full run log: {}",
            log.display()
        ));
    };
    let endpoint = read_field(record, ENDPOINT, log)?;
    let port = read_field(record, PORT, log)?;
    if endpoint != adoption.destination || port != adoption.port.to_string() {
        return Err(format!(
            "the appliance reports it will answer to {endpoint}:{port} and the package named \
             {}:{}. An endpoint is the one fact a pushed configuration can never change, so an \
             appliance that installed a different one is answering to somebody else\n  full run \
             log: {}",
            adoption.destination,
            adoption.port,
            log.display()
        ));
    }
    let generation: u64 = read_field(record, GENERATION, log)?
        .parse()
        .map_err(|error| format!("{record:?}: {GENERATION} is no number: {error}"))?;
    if generation <= identity.generation {
        return Err(format!(
            "the appliance reports ownership at generation {generation} and came up on {}. An \
             install writes a new record under the next generation, so one that did not advance \
             is an ownership that was not committed\n  full run log: {}",
            identity.generation,
            log.display()
        ));
    }
    Ok(format!(
        "the appliance printed the authority's own fingerprint {printed} and the endpoint \
         {endpoint}:{port} it will answer to, at generation {generation}"
    ))
}

/// One field of a record, or a finding naming what was missing.
fn read_field(record: &str, key: &str, log: &Path) -> Result<String, String> {
    value(record, key).map(str::to_owned).ok_or_else(|| {
        format!(
            "a request record carries no `{key}=`: {record:?}. The console is the only surface a \
             deployed node has, so a record missing the field that places it is a record that \
             says nothing\n  full run log: {}",
            log.display()
        )
    })
}

/// What this boot's management server did, as the evidence table.
pub(crate) fn evidence(onboarded: &Onboarded) -> String {
    let mut out = String::from(
        "  what this run's management server did to the appliance, every request pinned to the \
         fingerprint the console printed:\n",
    );
    if let Some(adoption) = &onboarded.adoption {
        out.push_str(&format!(
            "\n  it issued to `{}` against a development authority whose key digests to {}, and \
             composed a {}-byte package naming {}:{}\n",
            adoption.subject,
            adoption.anchor_fingerprint,
            adoption.package_len,
            adoption.destination,
            adoption.port,
        ));
    }
    for attempt in &onboarded.attempts {
        out.push_str(&format!(
            "\n  {} —\n    $ {}\n",
            attempt.name, attempt.command
        ));
        out.push_str(&format!("    exit: {}\n", attempt.status));
        for line in attempt.transcript.lines() {
            out.push_str(&format!("    {line}\n"));
        }
    }
    out.push_str(&format!(
        "\n  (judged against `{LIFECYCLE_PREFIX}` records)\n"
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lfw_package::{ChainRejected, ChainVerifier};
    use lfw_x509::SPKI_LEN;

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    const DEVICE: &str = "0123456789abcdef0123456789abcdef";
    const ANCHOR: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// A verifier that accepts, which is never reached by anything here: every
    /// archive below is refused before a chain is weighed.
    struct Accept;

    impl ChainVerifier for Accept {
        fn verify(&self, _end_entity: &[u8], _anchor: &[u8]) -> Result<(), ChainRejected> {
            Ok(())
        }
    }

    /// The writer, held to the reader it writes for.
    ///
    /// The bodies are not certificates, so the read stops at the first member's
    /// content — and that is exactly the assertion: everything the *archive*
    /// layer decides was decided in this writer's favour, which is the half a
    /// harness composing its own tar can get wrong. A gate that only ever
    /// uploaded this to a booted appliance would learn the same thing three
    /// minutes later and one boot at a time.
    #[test]
    fn the_composed_archive_is_one_the_appliances_own_reader_walks_whole() {
        let archive = package(
            b"not a certificate",
            b"nor this",
            b"10.0.2.2:4433\n",
            b"<n/>",
        );
        let refusal = lfw_package::read(&archive, &[0; SPKI_LEN], &Accept)
            .err()
            .expect("bodies that are not certificates");
        assert!(
            matches!(refusal, PackageError::DeviceCertificate(_)),
            "the reader refused the framing rather than the content: {refusal:?}"
        );
    }

    /// And the broken one is refused by exactly the rule it breaks, rather than
    /// by a checksum it also happened to invalidate.
    #[test]
    fn the_broken_archive_names_the_one_rule_it_breaks() {
        let archive = package(
            b"not a certificate",
            b"nor this",
            b"10.0.2.2:4433\n",
            b"<n/>",
        );
        let broken = not_ustar(&archive).expect("an archive of at least one block");
        let refusal = lfw_package::read(&broken, &[0; SPKI_LEN], &Accept)
            .err()
            .expect("an archive that is not ustar");
        assert_eq!(
            refusal.cause(),
            PackageError::Archive(ArchiveError::NotUstar { at: 0 }).cause(),
            "{refusal:?}"
        );
    }

    /// The one number this harness draws for itself, held to the profile's
    /// shape: a positive integer of a hundred and twenty-eight bits, in the
    /// notation `openssl` takes.
    #[test]
    fn a_serial_number_is_a_positive_128_bit_integer() {
        for _ in 0..16 {
            let drawn = serial().expect("a generator");
            let digits = drawn.strip_prefix("0x").expect("{drawn}");
            assert_eq!(digits.len(), 32, "{drawn}");
            assert!(
                digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{drawn}"
            );
            let leading = u8::from_str_radix(&digits[..2], 16).expect("{drawn}");
            assert!((0x40..0x80).contains(&leading), "{drawn}");
        }
    }

    fn identity(onboarded: bool, generation: u64) -> Identity {
        Identity {
            device: DEVICE.to_owned(),
            fingerprint: ANCHOR.to_owned(),
            generation,
            onboarded,
            reset: None,
        }
    }

    fn attempt(name: &'static str, status: u16, owed: Owed) -> Attempt {
        Attempt {
            name,
            command: format!("curl --output /dev/null https://127.0.0.1/{name}"),
            status: String::from("exit status: 0"),
            transcript: format!("HTTP/1.1 {status} something"),
            owed,
        }
    }

    /// The attempts one adopting boot makes, in the order it makes them.
    fn adopting(package_len: usize) -> Onboarded {
        Onboarded {
            attempts: vec![
                attempt(
                    "the request",
                    200,
                    Owed::Served(OnboardRoute::CertificateRequest),
                ),
                attempt(
                    "another appliance's package",
                    400,
                    Owed::Refused {
                        refusal: OnboardRefusal::PackageRefused,
                        status: 400,
                        rule: Some(PackageError::DeviceKeyIsNotThisAppliance.cause()),
                    },
                ),
                attempt("the package", 200, Owed::Installed),
            ],
            adoption: Some(Adoption {
                subject: DEVICE.to_owned(),
                anchor_fingerprint: ANCHOR.to_owned(),
                destination: String::from("10.0.2.2"),
                port: 4433,
                package_len,
            }),
        }
    }

    fn crypto(fields: &str) -> String {
        format!("LFW-PD time=unsynchronized domain=crypto state=ready {fields}")
    }

    fn store(fields: &str) -> String {
        format!("LFW-PD time=unsynchronized domain=store state=ready {fields}")
    }

    fn capture(records: &[String]) -> String {
        let mut text = String::from("LFW-BOOT slot=A state=confirmed\r\n");
        for record in records {
            text.push_str(record);
            text.push_str("\r\n");
        }
        text
    }

    /// The capture an adopting boot leaves when everything went as it must.
    fn adopted_capture(bytes: usize, fingerprint: &str) -> String {
        capture(&[
            crypto("onboard-http=certificate-request onboard-http-bytes=800"),
            crypto(
                "onboard-http-refused=package-refused onboard-http-status=400 onboard-http-held=180",
            ),
            crypto("cause=install-device-key-is-not-this-appliance signalled=false"),
            crypto(&format!("onboard-http-installed={bytes}")),
            store(&format!("anchor-fingerprint={fingerprint}")),
            store("adopted-endpoint=10.0.2.2 adopted-port=4433 adopted-generation=2"),
        ])
    }

    #[test]
    fn an_appliance_that_changed_hands_is_accepted_and_reported() {
        let onboarded = adopting(12_800);
        let proved = judge(
            &onboarded,
            &identity(false, 1),
            adopted_capture(12_800, ANCHOR).as_bytes(),
            log(),
        )
        .expect("a boot that installed what it was handed");
        assert!(proved.contains(DEVICE), "{proved}");
        assert!(proved.contains("10.0.2.2:4433"), "{proved}");
    }

    /// The anchor is the whole of what an install *gives away*, so a
    /// fingerprint that is not this authority's is the finding, whatever the
    /// status line said.
    #[test]
    fn an_anchor_that_is_not_the_one_uploaded_is_refused() {
        let other = ANCHOR.replace('0', "1");
        let verdict = judge(
            &adopting(12_800),
            &identity(false, 1),
            adopted_capture(12_800, &other).as_bytes(),
            log(),
        )
        .expect_err("an anchor nobody delivered");
        assert!(
            verdict.contains("other than the one in the package"),
            "{verdict}"
        );
    }

    /// A record that counted something other than the archive uploaded is a
    /// surface accounting for bytes it did not take.
    #[test]
    fn an_install_that_counted_other_bytes_is_refused() {
        let verdict = judge(
            &adopting(12_800),
            &identity(false, 1),
            adopted_capture(11_776, ANCHOR).as_bytes(),
            log(),
        )
        .expect_err("a length nobody uploaded");
        assert!(verdict.contains("uploaded 12800"), "{verdict}");
    }

    /// The surface says a package was refused; the package contract says which
    /// rule did it. A refusal missing the second told an administrator nothing.
    #[test]
    fn a_package_refusal_that_named_no_rule_is_refused() {
        let text = capture(&[
            crypto("onboard-http=certificate-request onboard-http-bytes=800"),
            crypto(
                "onboard-http-refused=package-refused onboard-http-status=400 \
                 onboard-http-held=180",
            ),
            crypto("onboard-http-installed=12800"),
            store(&format!("anchor-fingerprint={ANCHOR}")),
            store("adopted-endpoint=10.0.2.2 adopted-port=4433 adopted-generation=2"),
        ]);
        let verdict = judge(
            &adopting(12_800),
            &identity(false, 1),
            text.as_bytes(),
            log(),
        )
        .expect_err("a refusal with no rule beside it");
        assert!(verdict.contains("rule was never"), "{verdict}");
    }

    /// A generation that did not advance is an ownership that was never
    /// committed, whatever the console said about it.
    #[test]
    fn an_ownership_at_the_generation_the_boot_came_up_on_is_refused() {
        let text =
            adopted_capture(12_800, ANCHOR).replace("adopted-generation=2", "adopted-generation=1");
        let verdict = judge(
            &adopting(12_800),
            &identity(false, 1),
            text.as_bytes(),
            log(),
        )
        .expect_err("a generation that did not advance");
        assert!(verdict.contains("did not advance"), "{verdict}");
    }

    /// An appliance that was already owned when this boot's management server
    /// arrived proves nothing about changing hands.
    #[test]
    fn a_boot_that_began_owned_proves_no_transfer() {
        let verdict = judge(
            &adopting(12_800),
            &identity(true, 1),
            adopted_capture(12_800, ANCHOR).as_bytes(),
            log(),
        )
        .expect_err("an appliance that began owned");
        assert!(verdict.contains("changed nothing"), "{verdict}");
    }

    /// The attempts the returning boot makes, and the capture it must leave.
    fn returning() -> Onboarded {
        Onboarded {
            attempts: vec![
                attempt(
                    "the page",
                    410,
                    Owed::Refused {
                        refusal: OnboardRefusal::AlreadyOwned,
                        status: 410,
                        rule: None,
                    },
                ),
                attempt(
                    "the package it accepted",
                    410,
                    Owed::Refused {
                        refusal: OnboardRefusal::AlreadyOwned,
                        status: 410,
                        rule: None,
                    },
                ),
            ],
            adoption: None,
        }
    }

    fn gone() -> String {
        let refused = crypto(
            "onboard-http-refused=already-owned onboard-http-status=410 onboard-http-held=90",
        );
        capture(&[refused.clone(), refused])
    }

    #[test]
    fn an_owned_appliance_that_served_nothing_is_accepted() {
        let proved = judge(&returning(), &identity(true, 2), gone().as_bytes(), log())
            .expect("an appliance that came back owned");
        assert!(proved.contains("served nothing at all"), "{proved}");
    }

    /// The close is durable or it is not a close: an appliance that came back
    /// unowned has lost the only thing the previous boot gave it.
    #[test]
    fn an_appliance_that_came_back_unowned_is_refused() {
        let verdict = judge(&returning(), &identity(false, 2), gone().as_bytes(), log())
            .expect_err("an owner a restart cleared");
        assert!(verdict.contains("a flag a restart cleared"), "{verdict}");
    }

    /// And one that wrote a second owner has no owner at all — whatever it
    /// told the client. The two halves of an install are two domains, so a
    /// surface that refused while the medium was written is precisely the
    /// divergence worth catching.
    #[test]
    fn an_owned_appliance_that_adopted_again_is_refused() {
        let refused = crypto(
            "onboard-http-refused=already-owned onboard-http-status=410 onboard-http-held=90",
        );
        let text = capture(&[
            refused.clone(),
            refused,
            store("adopted-endpoint=10.0.2.2 adopted-port=4433 adopted-generation=3"),
        ]);
        let verdict = judge(&returning(), &identity(true, 2), text.as_bytes(), log())
            .expect_err("an appliance adopted twice");
        assert!(verdict.contains("no owner at all"), "{verdict}");
    }

    /// One record per request, and a boot that answered a request it never
    /// accounted for fails before any of the rest is read.
    #[test]
    fn a_request_the_appliance_never_accounted_for_is_refused() {
        let verdict = judge(
            &adopting(12_800),
            &identity(false, 1),
            capture(&[crypto(
                "onboard-http=certificate-request onboard-http-bytes=800",
            )])
            .as_bytes(),
            log(),
        )
        .expect_err("two requests unaccounted for");
        assert!(verdict.contains("One record per request"), "{verdict}");
    }

    /// The wait the run spends on the appliance is bounded by what the
    /// appliance has said, and an install is not reported until the domain that
    /// made it durable has spoken.
    #[test]
    fn a_boot_is_finished_only_once_both_domains_have_spoken() {
        let onboarded = adopting(12_800);
        assert!(!onboarded.reported(capture(&[]).as_bytes()));
        let requests = capture(&[
            crypto("onboard-http=certificate-request onboard-http-bytes=800"),
            crypto(
                "onboard-http-refused=package-refused onboard-http-status=400 \
                 onboard-http-held=180",
            ),
            crypto("onboard-http-installed=12800"),
        ]);
        assert!(!onboarded.reported(requests.as_bytes()));
        assert!(onboarded.reported(adopted_capture(12_800, ANCHOR).as_bytes()));
        // The returning boot owes no install, so its own three records are all
        // there is to wait for.
        assert!(returning().reported(gone().as_bytes()));
    }
}
