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
//! # The boot ends on the record, not beside it
//!
//! A session's outcome is written by the domain that terminates it, on the pass
//! that decided the session — which is a different domain and a later pass than
//! anything the routed contract waits for. A boot that stopped when its traffic
//! and its recordings were done would therefore kill the guest with the channel's
//! own record still unwritten, and read an appliance that was about to speak as
//! one that never did.
//!
//! So [`ChannelContract::satisfied`] states what the capture must already carry
//! and the run loop waits on it, under the same total budget every other boot
//! takes: an appliance that genuinely never reports fails on that budget rather
//! than hanging the gate. The wait asks whether the record has *appeared*, never
//! how many times the appliance re-dialled — that is the appliance's decision,
//! and a harness that counted connections would be asserting its own schedule.
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
use lfw_recorder::deck::SEGMENT_BYTES;

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
    /// [`Self::Established`]'s server, which then **pushes a configuration and
    /// commits it**: a stage frame carrying the document the reconfiguration
    /// scenario submits over HTTP, and a commit frame naming the generation that
    /// document becomes.
    ///
    /// That document and not the addressing one, deliberately: this boot is
    /// user-networked, so the run reaches its management port from the host, and
    /// a document that moved the appliance's addresses would take the port with
    /// it. What has to differ from the running configuration is the policy, which
    /// is what makes the commit a new generation rather than an `unchanged`.
    ///
    /// What it is for is the medium and not the session. The appliance must put
    /// the committed version into its configuration slot array and say so, which
    /// is the only way a version survives a reboot — so what this contract reads
    /// is the store domain's own record of a slot it wrote, beside the session
    /// records that say the document got there.
    ///
    /// It owes no shipment and no frame tally: what those prove is proved by
    /// [`Self::Established`], and a commit **ends the session** — commit-confirm
    /// admits a confirmation only over a connection opened after it — so this
    /// boot's connection closes where that one's stays up.
    CommitsAConfiguration,
    /// [`Self::Established`]'s server, which reconfigures a node that is
    /// **already carrying traffic**: it stands by until the appliance has
    /// greeted, and only then pushes the transaction the boot's subject is —
    /// two documents this appliance refuses, the document the scenario is
    /// about, and the commit that puts it in force.
    ///
    /// Its own variant beside [`Self::CommitsAConfiguration`] because the two
    /// differ in *when*, which is the whole of what these boots are for. That
    /// one writes its frames before QEMU starts and is judged on the slot they
    /// produced; this one has a dataplane whose verdicts under the old policy
    /// are half the evidence, so the push cannot happen until those verdicts
    /// have been reached — and the harness holds the pipe until the appliance
    /// itself says a session is up.
    ///
    /// It owes no shipment and no frame tally, on [`Self::CommitsAConfiguration`]'s
    /// terms exactly: a commit ends the session, so this boot's connection
    /// closes where an established one's stays up.
    ReconfiguresARunningNode,
    /// **Nothing is listening**, on [`Self::NoServer`]'s terms, and the boot's
    /// subject is what the appliance came back *running* rather than what it
    /// dials.
    ///
    /// The other half of [`Self::CommitsAConfiguration`], on the medium that one
    /// wrote. What it holds the appliance to is a configuration slot read back
    /// off that medium at start-up and held to the digest the record names it by
    /// — which is the whole claim that a committed version is durable, and one no
    /// single boot can make.
    ///
    /// No server, deliberately: a version restored off a disk is a fact about the
    /// disk, and a boot that had to reach a management plane to demonstrate it
    /// would be proving something else.
    RestoresACommittedConfiguration,
    /// A boot that **restored** a version and is then reconfigured again, over a
    /// transaction driven step by step out of the pipe it holds open.
    ///
    /// This is the boot the gate did not have, and its absence is why a defect
    /// reached a demonstration. A restored appliance runs the document its own
    /// image carries, so its running generation is one while its medium holds two —
    /// and the next commit has to be numbered past both. Numbered from the running
    /// counter alone it was two, which the holder of the medium refuses as a version
    /// that does not advance, so the commit never became durable and the appliance
    /// could not be reconfigured again for the rest of its life.
    ///
    /// It is held to the store domain's own records, both of them: the version it
    /// read back off the medium, and the **new** slot it wrote afterwards.
    RecommitsAfterAReload,
}

impl ChannelContract {
    /// Whether a server is started for this boot.
    const fn serves(self) -> bool {
        matches!(
            self,
            Self::Established
                | Self::AnchorRejectsTheServer
                | Self::RejectsTheAppliance
                | Self::CommitsAConfiguration
                | Self::ReconfiguresARunningNode
                | Self::RecommitsAfterAReload
        )
    }

    /// Whether the whole configuration transaction is driven mid-boot, out of the
    /// pipe the boot holds open, rather than written into the stream before QEMU
    /// starts.
    ///
    /// It has to be for this one: the boot is judged on the generation its commit
    /// is *answered* with, which means reading each result line before the next
    /// frame goes out rather than writing the whole exchange up front.
    pub(crate) const fn drives_a_transaction(self) -> bool {
        matches!(self, Self::RecommitsAfterAReload)
    }

    /// Whether the boot reads the appliance's own record of the channel.
    pub(crate) const fn judged(self) -> bool {
        !matches!(self, Self::Untouched)
    }

    /// Whether this boot's own contract holds the store medium it inherited to
    /// what the boot before it wrote there.
    ///
    /// A carried medium is otherwise proved by the pair of store identities, which
    /// is the only claim a boot whose subject is the identity can make. This one's
    /// subject is the **configuration** on that medium, so it states the same kind
    /// of thing about the same file — one version written by one boot and read
    /// back by the next — and says so here rather than leaving the run to conclude
    /// the pair proves nothing.
    pub(crate) const fn states_the_carried_medium(self) -> bool {
        matches!(
            self,
            Self::RestoresACommittedConfiguration | Self::RecommitsAfterAReload
        )
    }

    /// Whether the capture already carries every console record this contract is
    /// judged on, which is what lets the boot that owes one **wait** for it
    /// rather than race it.
    ///
    /// Deliberately only the *positive* half, on
    /// [`crate::config_transcript::RefusedContract::satisfied`]'s terms: a record
    /// that has not arrived yet and one that never will look alike while a guest
    /// is still running, so the absences this contract also states are judged
    /// once the capture is complete.
    ///
    /// **Nothing here counts attempts.** The appliance decides how often it
    /// re-dials, and every one of these records is written per session, so what
    /// is asked is whether the record has appeared at all — a boot bounded by a
    /// number of connections would be one this harness had decided the shape of.
    pub(crate) fn satisfied(self, serial: &[u8]) -> bool {
        let records = self.owed_records();
        // Before the capture is decoded at all, because this is asked on every
        // pass of the run loop and every boot whose subject is something else
        // takes the variant that owes nothing.
        if records.is_empty() {
            return true;
        }
        let log = &String::from_utf8_lossy(serial);
        records.iter().all(|owed| owed.carried(log))
            && (!self.owes_frames_beyond_the_greeting()
                || (expect_frames_beyond_the_greeting(log).is_ok()
                    && expect_shipping_after_catching_up(log).is_ok()))
    }

    /// One clause naming what this boot is still owed on the channel it dials and
    /// what the capture has to show for it, for the verdict a run that spent its
    /// whole budget leaves behind — and **empty where nothing is outstanding**,
    /// so a boot whose subject is something else adds no clause at all.
    pub(crate) fn outstanding(self, serial: &[u8]) -> String {
        if self.satisfied(serial) {
            return String::new();
        }
        let mut owed: Vec<String> = self
            .owed_records()
            .iter()
            .map(|record| format!("`{}`", record.owed))
            .collect();
        if self.owes_frames_beyond_the_greeting() {
            owed.push(String::from(
                "a `channel-agreed=true` record whose `channel-frames-sent` is past the greeting",
            ));
            owed.push(String::from(
                "a `channel-…-shipped=` record past the one that reported both recordings \
                 caught up, which is this appliance shipping records made after it had drained \
                 the rings",
            ));
        }
        let log = &String::from_utf8_lossy(serial);
        format!(
            "; the console is also silent on the channel this boot dials, which owes {}. What it \
             did write about the attempt:\n  {}\nand about the session:\n  {}",
            owed.join(", "),
            or_nothing(dial_records(log)),
            or_nothing(channel_records(log)),
        )
    }

    /// Whether this boot owes the appliance a further burst of traffic now: it
    /// holds the appliance to shipping records made after it drained the rings,
    /// and it has said it drained them.
    ///
    /// Asked of the console rather than of a clock, because the ordering is the
    /// assertion: traffic injected before the appliance has caught up is traffic
    /// the first shipments would have carried anyway.
    pub(crate) fn owes_shipping_after_catching_up(self, serial: &[u8]) -> bool {
        if !self.owes_frames_beyond_the_greeting() {
            return false;
        }
        let log = &String::from_utf8_lossy(serial);
        shipping_places(log)
            .iter()
            .any(|[_, log_pending, _, capture_pending]| *log_pending == 0 && *capture_pending == 0)
    }

    /// Whether this boot also holds the appliance to having shipped a frame
    /// beyond its own greeting, which is a tally rather than a token and so is
    /// not stated as a record substring.
    const fn owes_frames_beyond_the_greeting(self) -> bool {
        matches!(self, Self::Established)
    }

    /// The console records this boot is judged on, each named exactly as
    /// [`judge`] asks for it: one place says what is owed, so the wait and the
    /// verdict cannot come apart.
    fn owed_records(self) -> Vec<OwedRecord> {
        match self {
            Self::Untouched => Vec::new(),
            Self::NoServer => vec![OwedRecord::dial("reset-by-peer")],
            Self::Established => vec![
                OwedRecord::dial("established"),
                OwedRecord::channel(&established_session()),
            ],
            Self::AnchorRejectsTheServer => {
                vec![OwedRecord::channel(&anchor_refused_the_server())]
            }
            Self::RejectsTheAppliance => vec![OwedRecord::channel(&appliance_refused())],
            // The session, and then the slot it produced. The store record is
            // what this boot is really for, and it is owed *beside* the session
            // records rather than instead of them: a slot written without a
            // session behind it would be a claim about a medium nothing pushed to.
            Self::CommitsAConfiguration => {
                let [placed, restored] = configured(PUSHED_GENERATION, PUSHED_SLOT, false);
                vec![
                    OwedRecord::dial("established"),
                    OwedRecord::channel(&established_session()),
                    OwedRecord::store(&placed),
                    OwedRecord::store(&restored),
                ]
            }
            // The session and nothing beyond it. What the transaction itself
            // produced is judged as it happens — every step of it is answered
            // by a result frame this harness reads before it sends the next —
            // so the console owes only the session those frames crossed on.
            Self::ReconfiguresARunningNode => vec![
                OwedRecord::dial("established"),
                OwedRecord::channel(&established_session()),
            ],
            // The version the medium gave back, and nothing else: what this
            // boot is about is the disk, and holding it to a dial outcome would
            // make a restored version depend on where the appliance was pointed.
            Self::RestoresACommittedConfiguration => {
                let [placed, restored] = configured(PUSHED_GENERATION, PUSHED_SLOT, true);
                vec![OwedRecord::store(&placed), OwedRecord::store(&restored)]
            }
            // Both slots, and the pair is the whole claim: the version this boot
            // read back off its medium, and the one it wrote afterwards. A boot
            // that produced only the first is one whose commit was refused as a
            // version that does not advance.
            Self::RecommitsAfterAReload => {
                let [reloaded, was_restored] = configured(PUSHED_GENERATION, PUSHED_SLOT, true);
                let [placed, restored] =
                    configured(RECOMMITTED_GENERATION, RECOMMITTED_SLOT, false);
                vec![
                    OwedRecord::dial("established"),
                    OwedRecord::channel(&established_session()),
                    OwedRecord::store(&reloaded),
                    OwedRecord::store(&was_restored),
                    OwedRecord::store(&placed),
                    OwedRecord::store(&restored),
                ]
            }
        }
    }
}

/// The generation the pushed document becomes.
///
/// Two, and it is arithmetic rather than a choice: the document compiled into the
/// image is committed as generation one on every boot, and the staged one is the
/// next thing the datastore admits. Stated here once so the frame that names it
/// and the record that must report it cannot come apart.
pub(crate) const PUSHED_GENERATION: u64 = 2;

/// The generation a boot that **restored** a version numbers its next commit at,
/// and the slot that one takes.
///
/// Three, and it is arithmetic over two counters rather than a choice: the medium
/// carries generation two, the boot document is committed as the running one, and
/// the next version has to be past everything either of them holds. A commit
/// numbered anywhere below three is the defect this pair exists for — the holder of
/// the medium refuses a version that does not advance, so the commit never becomes
/// durable at all. The slot is one because slot zero already holds the version this
/// boot restored.
pub(crate) const RECOMMITTED_GENERATION: u64 = 3;
const RECOMMITTED_SLOT: u64 = 1;

/// The slot the pushed document takes.
///
/// Zero: the array fills empty slots in index order, and an appliance onboarded
/// but never configured over its channel has an empty array. A boot that found
/// something already there would be a boot on a medium this pair did not write.
const PUSHED_SLOT: u64 = 0;

/// The record a version reaches the console as, up to the size between the slot
/// and the flag.
///
/// The size is left out on purpose: it is the document's own length, and a
/// contract that named it would be a boot asserting how many bytes the gate's
/// second document happens to be. What the pair of boots is about is the
/// generation, the slot and where the answer came from.
fn configured(generation: u64, slot: u64, restored: bool) -> [String; 2] {
    [
        format!(
            "{}{}",
            field("configured-generation", &generation.to_string()),
            field("configured-slot", &slot.to_string()),
        ),
        field(
            "configured-restored",
            if restored { "true" } else { "false" },
        ),
    ]
}

/// Records as a verdict lists them, and the word for having written none.
fn or_nothing(records: Vec<&str>) -> String {
    if records.is_empty() {
        return String::from("(nothing)");
    }
    records.join("\n  ")
}

/// One console record a boot owes, and which of the appliance's two domains
/// writes it.
struct OwedRecord {
    /// The substring the record must carry, verbatim as [`judge`] asks for it.
    owed: String,
    /// Which of the appliance's domains writes it.
    from: Domain,
}

impl OwedRecord {
    fn dial(outcome: &str) -> Self {
        Self {
            owed: field("dial-outcome", outcome),
            from: Domain::Management,
        }
    }

    fn channel(owed: &str) -> Self {
        Self {
            owed: owed.to_owned(),
            from: Domain::Crypto,
        }
    }

    /// A record of the domain that owns the medium, which is where a version
    /// becoming durable is decided and therefore where it is said.
    fn store(owed: &str) -> Self {
        Self {
            owed: owed.to_owned(),
            from: Domain::Store,
        }
    }

    /// Whether the capture carries this record, read off the domain that writes
    /// it — the same sets [`judge`] reads.
    fn carried(&self, log: &str) -> bool {
        domain_records(log, self.from)
            .iter()
            .any(|record| record.contains(&self.owed))
    }
}

/// The record an established session leaves, composed once so the wait and the
/// verdict ask for the same bytes.
fn established_session() -> String {
    format!(
        "channel-tls={} channel-tls-version=0x0304 channel-tls-suite=0x1303 \
         channel-tls-group=0x11ec",
        ChannelOutcome::Established
    )
}

/// The record the delivered anchor leaves when it refuses the server.
fn anchor_refused_the_server() -> String {
    format!(
        "channel-tls={} channel-tls-certificate={}",
        ChannelOutcome::ServerCertificateRejected,
        TlsCertificateRefusal::UnknownIssuer
    )
}

/// The record a server that will not have this appliance leaves: the fatal
/// alert, as a number an operator can look up.
fn appliance_refused() -> String {
    format!(
        "channel-tls={} channel-tls-alert=0x0030",
        ChannelOutcome::AlertReceived
    )
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

/// The stream a server that pushes a configuration writes: the greeting, then a
/// stage frame carrying `document`, then a commit frame naming
/// [`PUSHED_GENERATION`].
///
/// Composed here as bytes rather than through the appliance's own encoder, on
/// [`SERVER_GREETING`]'s terms exactly: frames this harness built out of the code
/// under test would prove that the appliance agrees with itself. The layout is
/// the framing contract's — four bytes of payload length, one type byte, three
/// reserved zeroes, then the payload — and the type bytes are the protocol's own
/// numbering written out.
///
/// It is written whole and up front because `openssl s_server` sends what it
/// reads on standard input. The appliance reads the three frames in order: it
/// answers the stage with a result frame, and the commit ends the session, so
/// nothing follows.
fn configuration_push(document: &[u8]) -> Result<Vec<u8>, String> {
    // The greeting **proper** and not the whole array: its four trailing bytes are
    // a deliberate partial second frame, and a real frame written after them would
    // be read as the continuation of that fragment rather than as itself. The
    // fragment is a boot of its own's subject; this boot's is what the server says
    // next, so it says it on a frame boundary.
    let mut stream = Vec::from(&SERVER_GREETING[..GREETING_LEN]);
    stream.extend_from_slice(&stage_frame(document)?);
    stream.extend_from_slice(&commit_frame(PUSHED_GENERATION));
    Ok(stream)
}

/// One stage frame: 0x05, and `document` as its whole payload.
///
/// # Errors
/// A document longer than a frame's length prefix can name.
pub(crate) fn stage_frame(document: &[u8]) -> Result<Vec<u8>, String> {
    let len = u32::try_from(document.len())
        .map_err(|_| format!("a document of {} bytes is past a frame", document.len()))?;
    let mut frame = Vec::with_capacity(HEADER_LEN.saturating_add(document.len()));
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&[0x05, 0, 0, 0]);
    frame.extend_from_slice(document);
    Ok(frame)
}

/// The commit frame: 0x07, a generation and the seconds a confirmation has. Ten
/// bytes of payload, which is what the encoder puts there.
pub(crate) fn commit_frame(generation: u64) -> Vec<u8> {
    /// The longest this appliance will hold an unconfirmed commit for. The number
    /// is clamped by the appliance to its own bound whatever is asked, so what it
    /// decides is only how long a boot has before the revert. It is an order of
    /// magnitude past the budget any boot in this gate takes, so the configuration
    /// a commit puts in force is still in force when the guest stops, and every
    /// boot is bounded by the records and the result frames it waits for rather
    /// than by this.
    const CONFIRM_SECONDS: u16 = 600;

    let mut frame = Vec::with_capacity(18);
    frame.extend_from_slice(&10_u32.to_be_bytes());
    frame.extend_from_slice(&[0x07, 0, 0, 0]);
    frame.extend_from_slice(&generation.to_be_bytes());
    frame.extend_from_slice(&CONFIRM_SECONDS.to_be_bytes());
    frame
}

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
    let stream = match contract {
        ChannelContract::CommitsAConfiguration => {
            let document = fs::read(root.join(crate::image::SUBMITTED_DOCUMENT))
                .map_err(|error| format!("read {}: {error}", crate::image::SUBMITTED_DOCUMENT))?;
            configuration_push(&document)?
        }
        // The greeting **proper** and nothing after it: every boot that writes its
        // own frames mid-run needs them to land on a frame boundary, and the
        // four-byte fragment the greeting array carries after it — a deliberate
        // partial second frame, and another boot's whole subject — would be read
        // as the beginning of the first of them.
        ChannelContract::ReconfiguresARunningNode | ChannelContract::RecommitsAfterAReload => {
            Vec::from(&SERVER_GREETING[..GREETING_LEN])
        }
        _ => Vec::from(SERVER_GREETING),
    };
    fs::write(&greeting, &stream)
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
        pipe.write_all(&stream)
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
    resumed: bool,
    medium: &[crate::data_disk::Extent],
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
            expect_channel(log, &established_session())?;
            expect_certificate(&verification, device)?;
            expect_greeting(&transcript)?;
            let (records, from) = expect_records(&transcript, resumed)?;
            let shipped = expect_shipments_at_advancing_positions(&transcript)?;
            // The frame tally is read after the frames themselves, so a boot
            // that shipped nothing fails on the missing frame rather than on a
            // number.
            expect_frames_beyond_the_greeting(log)?;
            expect_shipping_after_catching_up(log)?;
            // And the half no reading of this transcript alone could establish:
            // that the bytes the appliance handed a management server are the
            // bytes on its own medium, at the positions it said they were at.
            let corroborated = expect_the_medium_behind_the_shipments(&transcript, medium)?;
            Ok(format!(
                "  answered   channel               appliance->server  {}:{DIAL_PORT}  \
                 TLS 1.3, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768; the server validated \
                 CN={device} against the authority this run issued, both greetings crossed at \
                 version 1, and the appliance shipped {records} bytes of its log ring from \
                 position {from} as UP_RECORDS — where that recording begins on the medium this \
                 boot attached — then went on shipping across {shipped} frames at advancing \
                 positions with traffic injected between them\n{corroborated}",
                ipv4(DIAL_DESTINATION)
            ))
        }
        ChannelContract::CommitsAConfiguration => {
            let Some(server) = server else {
                return Err(String::from(
                    "this boot's contract pushes a configuration and no management server was \
                     started for it",
                ));
            };
            let (transcript, verification) = server.finish()?;
            expect_dial(log, "established")?;
            expect_channel(log, &established_session())?;
            expect_certificate(&verification, device)?;
            expect_greeting(&transcript)?;
            // The appliance's own account of the slot it wrote, which is what
            // this boot is for. It is read off the domain that owns the medium:
            // the session records above say the document arrived, and only this
            // one says it became durable.
            for owed in configured(PUSHED_GENERATION, PUSHED_SLOT, false) {
                expect_store(log, &owed)?;
            }
            Ok(format!(
                "  answered   channel               appliance->server  {}:{DIAL_PORT}  the \
                 server pushed a second configuration document and committed it at generation \
                 {PUSHED_GENERATION}, and the appliance wrote it into configuration slot \
                 {PUSHED_SLOT} of its own medium behind a flush and reported the version it now \
                 holds",
                ipv4(DIAL_DESTINATION)
            ))
        }
        ChannelContract::ReconfiguresARunningNode => {
            let Some(server) = server else {
                return Err(String::from(
                    "this boot's contract reconfigures a running node over its channel and no \
                     management server was started for it",
                ));
            };
            let (transcript, verification) = server.finish()?;
            expect_dial(log, "established")?;
            expect_channel(log, &established_session())?;
            expect_certificate(&verification, device)?;
            expect_greeting(&transcript)?;
            // What the transaction itself produced is not read here: every step
            // of it was answered by a result frame the run loop held to its
            // contract before it sent the next, and a second reading of the
            // same transcript afterwards would state one fact twice. What this
            // states is the session those frames crossed on — mutually
            // authenticated, and agreed at both ends.
            Ok(format!(
                "  answered   channel               appliance->server  {}:{DIAL_PORT}  the \
                 server validated CN={device} against the authority this run issued, both \
                 greetings crossed at version 1, and it then reconfigured a node that was \
                 already carrying traffic",
                ipv4(DIAL_DESTINATION)
            ))
        }
        ChannelContract::RestoresACommittedConfiguration => {
            // Nothing was started: what this boot proves is about the disk the
            // boot before it wrote, and reaching a management plane to show it
            // would be proving something else.
            let _ = server.map(Server::finish).transpose()?;
            for owed in configured(PUSHED_GENERATION, PUSHED_SLOT, true) {
                expect_store(log, &owed)?;
            }
            Ok(format!(
                "  answered   configuration         medium->appliance  slot {PUSHED_SLOT}  the \
                 appliance came back on generation {PUSHED_GENERATION} read off the medium the \
                 boot before it committed to, held to the digest its own record names that slot by"
            ))
        }
        ChannelContract::RecommitsAfterAReload => {
            let Some(server) = server else {
                return Err(String::from(
                    "this boot's contract reconfigures an appliance that restored a version and \
                     no management server was started for it",
                ));
            };
            let (transcript, verification) = server.finish()?;
            expect_dial(log, "established")?;
            expect_channel(log, &established_session())?;
            expect_certificate(&verification, device)?;
            expect_greeting(&transcript)?;
            for owed in configured(PUSHED_GENERATION, PUSHED_SLOT, true) {
                expect_store(log, &owed)?;
            }
            for owed in configured(RECOMMITTED_GENERATION, RECOMMITTED_SLOT, false) {
                expect_store(log, &owed)?;
            }
            Ok(format!(
                "  answered   configuration         medium->appliance  slot {PUSHED_SLOT}  the \
                 appliance came back on generation {PUSHED_GENERATION} read off the medium the \
                 boot before it confirmed, and then took a further commit at generation \
                 {RECOMMITTED_GENERATION} into slot {RECOMMITTED_SLOT} — which is only numbered \
                 there because the version its medium already held is what the numbering starts \
                 above"
            ))
        }
        ChannelContract::AnchorRejectsTheServer => {
            let _ = server.map(Server::finish).transpose()?;
            expect_channel(log, &anchor_refused_the_server())?;
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
            expect_channel(log, &appliance_refused())?;
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
    /// Write `frames` down the pipe the boot is holding open, so the server
    /// says something the appliance was not told at spawn.
    ///
    /// `openssl s_server` sends what it reads on standard input and this pipe
    /// is never closed, which is what makes a mid-boot push possible at all:
    /// the bytes reach the session the appliance is holding rather than a
    /// redirect that hung up when the greeting had gone.
    ///
    /// # Errors
    /// A server that has no pipe, and a write that failed.
    pub(crate) fn push(&mut self, frames: &[u8]) -> Result<(), String> {
        let Some(pipe) = self.child.stdin.as_mut() else {
            return Err(String::from(
                "the management server has no standard input to push a frame down, so nothing \
                 this run says after the greeting can reach the appliance",
            ));
        };
        pipe.write_all(frames)
            .and_then(|()| pipe.flush())
            .map_err(|error| format!("push a frame to the management server: {error}"))
    }

    /// What the server has written down so far, mid-boot.
    ///
    /// # Errors
    /// A transcript that could not be read.
    fn seen(&self) -> Result<Vec<u8>, String> {
        fs::read(&self.transcript)
            .map_err(|error| format!("read {}: {error}", self.transcript.display()))
    }

    /// How many times the **appliance's** greeting has reached this server,
    /// which is one per session it has agreed.
    ///
    /// The server's own account and never the appliance's: what a push needs to
    /// know is that there is a session at this end to write into, and a console
    /// record is the far end saying so about a session that may since have
    /// gone.
    ///
    /// # Errors
    /// A transcript that could not be read.
    pub(crate) fn sessions_greeted(&self) -> Result<usize, String> {
        let seen = self.seen()?;
        Ok(seen
            .windows(APPLIANCE_GREETING.len())
            .filter(|window| *window == APPLIANCE_GREETING)
            .count())
    }

    /// Every result line the appliance has answered a staged document with, in
    /// arrival order.
    ///
    /// The frames are found in the transcript rather than at an offset, on
    /// [`expect_greeting`]'s terms: `openssl s_server` writes the application
    /// data it received into the same stream as its own diagnostics. A payload
    /// that is not one of this appliance's result lines is passed over rather
    /// than reported, because a diagnostic that happened to carry the type byte
    /// is not a frame — what makes one is the grammar the line is composed in.
    ///
    /// # Errors
    /// A transcript that could not be read.
    pub(crate) fn validate_results(&self) -> Result<Vec<String>, String> {
        let seen = self.seen()?;
        let mut lines = Vec::new();
        let mut at = 0usize;
        while let Some(found) = seen
            .get(at..)
            .and_then(|tail| tail.windows(HEADER_LEN).position(is_validate_result))
        {
            let start = at.saturating_add(found);
            at = start.saturating_add(1);
            let Some(header) = seen.get(start..start.saturating_add(HEADER_LEN)) else {
                break;
            };
            let stated = match header
                .get(..4)
                .and_then(|four| <[u8; 4]>::try_from(four).ok())
            {
                Some(octets) => u32::from_be_bytes(octets) as usize,
                None => continue,
            };
            let body = seen.get(
                start.saturating_add(HEADER_LEN)
                    ..start.saturating_add(HEADER_LEN).saturating_add(stated),
            );
            if let Some(body) = body
                && let Ok(line) = core::str::from_utf8(body)
                && line.starts_with(RESULT_LINE_OPENS_WITH)
            {
                lines.push(line.to_owned());
            }
        }
        Ok(lines)
    }

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

/// One record of the domain that owns the medium, verbatim.
///
/// Its own reader rather than [`expect_channel`] with a domain parameter, because
/// what it says on failure is different: the session's records are what a reader
/// of a channel failure goes to, and a slot that was not written sends one to the
/// store's instead.
fn expect_store(log: &str, owed: &str) -> Result<(), String> {
    let written = domain_records(log, Domain::Store);
    if written.iter().any(|record| record.contains(owed)) {
        return Ok(());
    }
    Err(format!(
        "the appliance never wrote a record carrying `{owed}`. What the domain that owns the \
         medium did write:\n  {}",
        or_nothing(written)
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

/// Where the appliance said its channel had got to, one entry per record it
/// wrote, in emission order.
///
/// Each is the two ring positions and the two backlogs behind them. A record
/// missing any of the four is skipped rather than guessed at: what this contract
/// is about is the numbers moving, and a record it could not read is a record it
/// cannot say that of.
fn shipping_places(log: &str) -> Vec<[u64; 4]> {
    management(log)
        .into_iter()
        .filter_map(|record| {
            let mut place = [0_u64; 4];
            for (slot, key) in place.iter_mut().zip([
                "channel-log-shipped",
                "channel-log-pending",
                "channel-capture-shipped",
                "channel-capture-pending",
            ]) {
                *slot = value(record, key)?.parse().ok()?;
            }
            Some(place)
        })
        .collect()
}

/// The appliance shipped a recording it made **after** it had drained both
/// rings, on the session it was already holding.
///
/// The order is the whole assertion and it is why the caught-up record has to
/// come first: a channel that merely walks a backlog it had at the start reports
/// advancing positions too, and would satisfy a check that only compared two
/// numbers. A record stating both backlogs at zero is this appliance saying it
/// has shipped everything the medium had taken; a higher position after it is a
/// record that did not exist when it said so.
fn expect_shipping_after_catching_up(log: &str) -> Result<(), String> {
    let places = shipping_places(log);
    let caught_up = places
        .iter()
        .position(|[_, log_pending, _, capture_pending]| {
            *log_pending == 0 && *capture_pending == 0
        });
    let Some(caught_up) = caught_up else {
        return Err(format!(
            "the appliance never reported both recordings caught up, so nothing it shipped \
             afterwards can be a record made after it had drained them. Where it said its channel \
             had got to:\n  {}",
            or_nothing(shipping_records(log))
        ));
    };
    let [drained_log, _, drained_capture, _] = places[caught_up];
    let advanced = places.get(caught_up + 1..).unwrap_or_default().iter().any(
        |[log_position, _, capture_position, _]| {
            *log_position > drained_log || *capture_position > drained_capture
        },
    );
    if advanced {
        return Ok(());
    }
    Err(format!(
        "the appliance drained both recordings at log {drained_log} / capture {drained_capture} \
         and never shipped past either of them again, so nothing recorded after that reached the \
         server on the session it was holding. Where it said its channel had got to:\n  {}",
        or_nothing(shipping_records(log))
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
/// Two things are held, and both matter. The position is **where that recording
/// begins**, rather than wherever the appliance happened to have bytes on hand —
/// a frame that started anywhere else would be one a server could not place.
/// That is zero on a fresh medium and the segment this boot opened on one a
/// previous boot wrote, which is a segment boundary either way: the previous
/// boot left its last segment unsealed, so it is not this one's to hand over.
/// And the ring bytes begin with a pcapng Section Header Block, which is what
/// makes them a recording an ingest can open rather than a run of bytes the
/// appliance called one.
fn expect_records(transcript: &[u8], resumed: bool) -> Result<(usize, u64), String> {
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
            && let Ok(octets) = <[u8; RING_POSITION_LEN]>::try_from(position)
            && begins_a_recording(u64::from_be_bytes(octets), resumed)
            && ring.len() >= SECTION_HEADER_PREFIX_LEN
            && ring.get(..4) == Some(&SECTION_HEADER_BLOCK)
            && ring.get(8..12) == Some(&BYTE_ORDER_MAGIC)
        {
            return Ok((ring.len(), u64::from_be_bytes(octets)));
        }
        at = start + 1;
    }
    Err(format!(
        "the appliance never shipped a well-formed UP_RECORDS frame from {} whose bytes open on a \
         pcapng Section Header Block. The framing puts one on the wire as four bytes of payload \
         length, the type byte {UP_RECORDS_TYPE:#04x}, three reserved zeroes, a big-endian ring \
         position and then the ring's own bytes. The server's transcript was:\n{}",
        if resumed {
            "where the recording begins on the medium a previous boot wrote, which is position 0 \
             until the ring has wrapped"
        } else {
            "ring position 0"
        },
        String::from_utf8_lossy(transcript)
    ))
}

/// Whether `position` is where a recording begins on the medium this boot
/// attached.
///
/// Zero on a fresh one, and a segment boundary on either — which on a medium a
/// previous boot wrote is **zero as well** until the ring has wrapped, because a
/// boot resumes inside the segment it read rather than in the one after it, so
/// nothing an earlier boot put on the medium stops being this one's to ship. A
/// wrap is the only thing that moves it, and the segment is the unit it moves
/// by; how many the medium this run assembled has seen is not something this
/// harness knows or has to.
fn begins_a_recording(position: u64, resumed: bool) -> bool {
    if !resumed {
        return position == 0;
    }
    position.is_multiple_of(SEGMENT_BYTES as u64)
}

/// The appliance kept shipping: more than one upstream frame reached the server,
/// and each ring's frames name strictly advancing positions.
///
/// **This is the server's own statement**, beside the appliance's on its console,
/// and it is the half no reading of that console could establish: a node that
/// reported shipping and put nothing on the wire looks identical there. The
/// positions must advance because a position is what places a frame's bytes in
/// the ring — two frames at one position are one shipment sent twice, which is
/// exactly what a cursor that never moves produces.
///
/// # Errors
/// A boot that shipped once and stopped, and one whose positions stood still.
fn expect_shipments_at_advancing_positions(transcript: &[u8]) -> Result<usize, String> {
    let frames = crate::shipment_contract::walk(transcript).positions();
    if frames.len() < 2 {
        return Err(format!(
            "the appliance put {} upstream frame(s) on the session it was holding, and this boot \
             injects traffic after the first one arrives: a node that ships once and then goes \
             quiet leaves its recordings on the appliance until the server's read timeout closes \
             the connection. The frames that did arrive were {frames:?}",
            frames.len()
        ));
    }
    for ring in [UP_RECORDS_TYPE, UP_CAPTURE_TYPE] {
        let positions: Vec<u64> = frames
            .iter()
            .filter(|(kind, ..)| *kind == ring)
            .map(|(_, position, _)| *position)
            .collect();
        if positions.windows(2).any(|pair| pair[1] <= pair[0]) {
            return Err(format!(
                "the appliance shipped ring {ring:#04x} at positions {positions:?}, which do not \
                 advance. A position places a frame's bytes in the ring, so a repeat is one \
                 shipment sent twice rather than the next one"
            ));
        }
    }
    Ok(frames.len())
}

/// Whether these eight bytes are an `UP_RECORDS` header: the type byte, and the
/// three reserved bytes this protocol holds at zero.
fn is_up_records(window: &[u8]) -> bool {
    window.get(4) == Some(&UP_RECORDS_TYPE) && window.get(5..8) == Some(&[0, 0, 0][..])
}

/// The same, for the frame a staged document is answered with.
fn is_validate_result(window: &[u8]) -> bool {
    window.get(4) == Some(&UP_CONFIG_VALIDATE_RESULT_TYPE)
        && window.get(5..8) == Some(&[0, 0, 0][..])
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

/// Every record the reader that ships the recordings left.
fn shipping_records(log: &str) -> Vec<&str> {
    management(log)
        .into_iter()
        .filter(|record| record.contains("channel-log-shipped="))
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

/// The type bytes of a frame carrying log-ring and capture-ring bytes.
const UP_RECORDS_TYPE: u8 = 0x02;
const UP_CAPTURE_TYPE: u8 = 0x03;

/// And of the frame a staged document is answered with, whose payload is one
/// line of the console's own field vocabulary.
const UP_CONFIG_VALIDATE_RESULT_TYPE: u8 = 0x06;

/// What every one of those lines opens with, which is what tells a result frame
/// from a diagnostic that happened to carry the type byte.
const RESULT_LINE_OPENS_WITH: &str = "generation=";

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
/// Hold the ring bytes the appliance shipped to the extents on its own disk.
///
/// **This is the pair that makes either reading evidence.** The transcript is
/// the appliance's account of its recordings, composed by the domain whose
/// conduct is in question; the extents are the same recordings read on the host
/// side of the emulation by a process the guest cannot reach. A recorder that
/// shipped a plausible stream and wrote nothing satisfies every management
/// server, and a recorder that wrote a fine extent and shipped something else
/// leaves one holding a fiction — neither surface notices alone, and the
/// comparison is total rather than statistical because the framing contract
/// makes the ring bytes the wire bytes.
///
/// # Errors
/// A boot whose medium was not read back, and every disagreement
/// [`crate::shipment_contract::judge`] states.
fn expect_the_medium_behind_the_shipments(
    transcript: &[u8],
    medium: &[crate::data_disk::Extent],
) -> Result<String, String> {
    use crate::shipment_contract::{Extent, Ring, judge, walk};
    // `Deck::extents`' order, which is the connection history and then the
    // capture — the order the recorder declares them in and the order every
    // other contract over the pair reads them in.
    let [log, capture] = medium else {
        return Err(format!(
            "this boot shipped its recordings up a channel and {} recording extent(s) were read \
             off its disk image, so there is nothing to hold the shipments to. The contract is \
             stated over the two the recorder declares",
            medium.len()
        ));
    };
    let held = [(Ring::Log, log), (Ring::Capture, capture)].map(|(ring, extent)| Extent {
        ring,
        payload: &extent.payload,
        durable: extent.durable,
    });
    // A floor rather than a count: how much of each ring reaches the wire before
    // the boot ends is the appliance's own scheduling, and asserting a number
    // would be this harness deciding it. What it refuses is the vacuous pass —
    // an agreement reached because nothing was compared. A pcapng Section Header
    // Block alone is 28 bytes, so a ring that shipped fewer shipped no recording.
    Ok(judge(&walk(transcript), &held, 28)?.evidence())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lifecycle record on the channel the domain `domain` writes, as the
    /// appliance renders one: the marker, the domain, its state, and the detail.
    fn record(domain: Domain, detail: &str) -> String {
        format!(
            "LFW-PD time=1 domain={} state={}{detail}\r\n",
            domain.name(),
            DomainState::Ready.name()
        )
    }

    /// The console of a boot whose server refused the appliance, as many times
    /// over as it re-dialled.
    fn refused_console(attempts: usize) -> Vec<u8> {
        let mut capture = String::new();
        for attempt in 1..=attempts {
            capture.push_str(&record(
                Domain::Management,
                &format!(" dial-attempts={attempt} dial-outcome=established"),
            ));
            capture.push_str(&record(
                Domain::Crypto,
                &format!(" {}", appliance_refused()),
            ));
        }
        capture.into_bytes()
    }

    #[test]
    fn a_boot_that_owes_no_record_is_satisfied_by_an_empty_capture() {
        assert!(ChannelContract::Untouched.satisfied(b""));
        assert!(ChannelContract::Untouched.outstanding(b"").is_empty());
    }

    #[test]
    fn a_boot_that_owes_a_record_is_unsatisfied_until_that_very_record_arrives() {
        let contract = ChannelContract::RejectsTheAppliance;
        // The transport got there and the session has not spoken, which is the
        // capture the run used to stop on and judge as a failure.
        let attempt = record(
            Domain::Management,
            " dial-attempts=1 dial-outcome=established",
        );
        assert!(!contract.satisfied(attempt.as_bytes()));
        // Another session's outcome is not this one's: an appliance that refused
        // the server's certificate has not reported an alert.
        let other = format!(
            "{attempt}{}",
            record(Domain::Crypto, &format!(" {}", anchor_refused_the_server()))
        );
        assert!(!contract.satisfied(other.as_bytes()));
        assert!(contract.satisfied(&refused_console(1)));
    }

    #[test]
    fn how_often_the_appliance_re_dialled_decides_nothing() {
        // The appliance chooses how many times it dials and each attempt writes
        // the same record, so one and many are the same answer. A wait that
        // counted connections would be waiting for a schedule this harness
        // invented.
        let contract = ChannelContract::RejectsTheAppliance;
        for attempts in [1, 2, 7] {
            assert!(
                contract.satisfied(&refused_console(attempts)),
                "{attempts} attempt(s) must satisfy the contract"
            );
        }
    }

    #[test]
    fn the_record_is_read_off_the_domain_that_writes_it() {
        // The session's outcome belongs to the domain that terminates the
        // session; the same text under the domain that owns the network is a
        // record no reader of this contract would have believed.
        let misfiled = record(Domain::Management, &format!(" {}", appliance_refused()));
        assert!(!ChannelContract::RejectsTheAppliance.satisfied(misfiled.as_bytes()));
    }

    /// A line saying where the channel has got to, as the appliance writes one.
    fn shipping(log_position: u64, log_pending: u64, capture: u64, capture_pending: u64) -> String {
        record(
            Domain::Management,
            &format!(
                " channel-log-shipped={log_position} channel-log-pending={log_pending} \
                 channel-capture-shipped={capture} channel-capture-pending={capture_pending}"
            ),
        )
    }

    #[test]
    fn an_established_channel_waits_for_the_frame_past_its_own_greeting() {
        let contract = ChannelContract::Established;
        let mut capture = record(
            Domain::Management,
            " dial-attempts=1 dial-outcome=established",
        );
        capture.push_str(&record(
            Domain::Crypto,
            &format!(" {}", established_session()),
        ));
        // The session is up and nothing has been shipped over it yet, which is
        // the second half of what this boot judges.
        assert!(!contract.satisfied(capture.as_bytes()));
        capture.push_str(&record(
            Domain::Crypto,
            " channel-agreed=true channel-version=1 channel-frames-sent=1 channel-frames-received=1",
        ));
        assert!(!contract.satisfied(capture.as_bytes()));
        capture.push_str(&record(
            Domain::Crypto,
            " channel-agreed=true channel-version=1 channel-frames-sent=2 channel-frames-received=1",
        ));
        // And still not: a frame past the greeting is one shipment, and this
        // boot is about an appliance that goes on shipping.
        assert!(!contract.satisfied(capture.as_bytes()));
        capture.push_str(&shipping(512, 1_024, 0, 4_096));
        capture.push_str(&shipping(1_536, 0, 4_096, 0));
        assert!(
            !contract.satisfied(capture.as_bytes()),
            "catching up is not the same as shipping what came afterwards"
        );
        assert!(contract.owes_shipping_after_catching_up(capture.as_bytes()));
        capture.push_str(&shipping(1_536, 0, 8_192, 512));
        assert!(contract.satisfied(capture.as_bytes()));
    }

    #[test]
    fn a_channel_that_only_walks_the_backlog_it_started_with_is_not_shipping() {
        // Positions advancing is not the property: a reader draining a ring it
        // was already behind on reports exactly that, and would satisfy a check
        // that compared two numbers. What is asserted is a position past the one
        // the appliance itself said it had drained to.
        let contract = ChannelContract::Established;
        let mut capture = record(
            Domain::Management,
            " dial-attempts=1 dial-outcome=established",
        );
        capture.push_str(&record(
            Domain::Crypto,
            &format!(" {}", established_session()),
        ));
        capture.push_str(&record(
            Domain::Crypto,
            " channel-agreed=true channel-version=1 channel-frames-sent=2 channel-frames-received=1",
        ));
        for step in 1..=4 {
            capture.push_str(&shipping(512 * step, 4_096, 0, 0));
        }
        assert!(!contract.satisfied(capture.as_bytes()));
        assert!(!contract.owes_shipping_after_catching_up(capture.as_bytes()));
        assert!(
            contract
                .outstanding(capture.as_bytes())
                .contains("caught up"),
            "the verdict must name what the boot was still owed"
        );
    }

    #[test]
    fn the_servers_own_frames_must_be_more_than_one_and_advance() {
        // The appliance's console and the server's transcript are two halves of
        // one claim, and this is the half no reading of the console could make.
        let framed = |kind: u8, position: u64, bytes: usize| {
            let mut frame = Vec::new();
            let len = (RING_POSITION_LEN + bytes) as u32;
            frame.extend_from_slice(&len.to_be_bytes());
            frame.push(kind);
            frame.extend_from_slice(&[0, 0, 0]);
            frame.extend_from_slice(&position.to_be_bytes());
            frame.extend(core::iter::repeat_n(0xA5, bytes));
            frame
        };
        let one = framed(UP_RECORDS_TYPE, 0, 512);
        assert!(expect_shipments_at_advancing_positions(&one).is_err());

        let mut stalled = one.clone();
        stalled.extend(framed(UP_RECORDS_TYPE, 0, 512));
        assert!(
            expect_shipments_at_advancing_positions(&stalled).is_err(),
            "one shipment sent twice is not two shipments"
        );

        let mut shipping = one;
        shipping.extend(framed(UP_CAPTURE_TYPE, 0, 4_058));
        shipping.extend(framed(UP_RECORDS_TYPE, 512, 512));
        assert_eq!(
            expect_shipments_at_advancing_positions(&shipping),
            Ok(3),
            "each ring's own positions advance"
        );
    }

    #[test]
    fn a_boot_with_nothing_listening_waits_for_the_transports_own_account() {
        let contract = ChannelContract::NoServer;
        let established = record(
            Domain::Management,
            " dial-attempts=1 dial-outcome=established",
        );
        assert!(!contract.satisfied(established.as_bytes()));
        let reset = record(
            Domain::Management,
            " dial-attempts=1 dial-outcome=reset-by-peer",
        );
        assert!(contract.satisfied(reset.as_bytes()));
    }

    #[test]
    fn the_verdict_of_a_boot_that_ran_out_of_budget_names_what_was_owed() {
        let verdict = ChannelContract::RejectsTheAppliance.outstanding(
            record(
                Domain::Management,
                " dial-attempts=1 dial-outcome=established",
            )
            .as_bytes(),
        );
        assert!(verdict.contains("channel-tls-alert=0x0030"), "{verdict}");
        assert!(verdict.contains("dial-outcome=established"), "{verdict}");
        assert!(verdict.contains("(nothing)"), "{verdict}");
    }
}
