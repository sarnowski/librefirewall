//! Booting the deployable disk in QEMU.
//!
//! Every QEMU invocation boots through the same firmware → boot-manager → seL4
//! chain the hardware appliance uses: OVMF (UEFI) loads the signed GRUB image
//! from the disk's ESP, which verifies and boots the selected slot. The disk is
//! attached as an explicit `ide-hd,bootindex=0` device so OVMF starts at GRUB
//! rather than at the firmware's own network-boot options for the virtio NICs.
//!
//! Three properties keep a run's result independent of the machine it ran on.
//! The guest CPU model is [`GUEST_CPU`] whether or not KVM is available, so the
//! asserted contract never varies with the runner's host CPU; the
//! [`Acceleration`] actually chosen — with the reason KVM was rejected, or the
//! reason emulation was asked for — is printed and written into the run log, so
//! an unnoticed degradation to emulation cannot pass for an accelerated run; and
//! one scenario is forced onto the emulator by its [`Accelerator`] whatever the
//! machine offers, because an image proved only on the accelerator every runner
//! happens to have is an image whose verdict is a fact about the runners.
//!
//! [`test_system`] is the black-box system gate. It boots one [`Scenario`] per
//! contract the appliance owes, almost every one asserting the machine-observable
//! routed contract — a datagram sent from the host endpoint on each NIC port
//! reaches the endpoint on the other rewritten for its next hop, and the packets
//! the appliance must refuse reach nobody — driven by
//! [`crate::forward_harness`]. Some additionally judge the `LFW-CFG` console
//! channel through [`crate::config_transcript`], and every one whose management
//! port a real client can reach ([`ManagementRole::Client`]) pulls every surface
//! the endpoint serves and holds the three of them to each other
//! ([`crate::surface_contract`]). The exception is the forced-emulation boot,
//! whose subject is the accelerator rather than a contract, and which therefore
//! judges the cryptography domain alone ([`Console::JudgedOnCryptographyAlone`]).
//!
//! Every scenario boots the RELEASE kernel configuration, because that is the
//! image a release publishes. A scenario that fails there is re-run
//! once against the debug kernel by [`crate::diagnose`], whose verdict reports
//! the divergence; that re-run is evidence and never changes the outcome.
//!
//! Every address in all of that comes from the configuration document the image
//! under test was built from, read by [`crate::topology`]. Nothing in this
//! module names an address, and the MAC it hands each guest NIC is the MAC an
//! interface in that document claims.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use lfw_log::{DialOutcome, OnboardEnd, Ownership};

use crate::{
    artifacts::DIST_DISK,
    clock_contract,
    config_transcript::ConfigContract,
    crypto_contract,
    data_disk::{DataDisk, StoreDisk},
    diagnose::{self, GUEST_OUTPUT_MARKER, Run},
    dial_contract::{self, Count, DialAccount, DialVerdict},
    forward_harness::{
        self, BootContract, BootTest, Booted, DialMisbehaviour, ManagementBacking,
        OnboardBehaviour, Traffic,
    },
    image, management_contract, metrics_contract,
    onboard_contract::{self, OnboardVerdict},
    onboard_install_contract, onboard_request_contract, onboard_tls_contract, ownership_contract,
    probe_contract,
    recording_contract::{self, Download},
    stamp_contract, store_contract, surface_contract,
    topology::{PORTS, Topology},
    util::{copy_file, locate, require_file, run_command},
};

/// The two documents a scenario may build its own image from, named through
/// [`crate::image`] so the fast gate's list of documents to validate and the
/// scenarios' own choice of one cannot drift apart.
use image::{ALTERNATE_DOCUMENT, LIFECYCLE_DOCUMENT};

// UEFI firmware for the OVMF boot path; the first existing candidate is used.
const OVMF_CODE_CANDIDATES: &[&str] = &[
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
];
const OVMF_VARS_CANDIDATES: &[&str] = &[
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
];

const KVM_DEVICE: &str = "/dev/kvm";

/// The guest CPU, pinned to one feature set for BOTH accelerators. seL4's
/// x86_64 kernel needs the first four features present; naming them explicitly
/// (rather than passing `host` under KVM) is what makes the boot the system test
/// asserts on identical on every runner, accelerated or not. Every feature here
/// has been baseline on x86-64 since well before the hardware this project
/// targets, so pinning them costs no KVM host compatibility.
///
/// `rdrand` is the appliance's requirement rather than the kernel's, and it is a
/// *hard* one: the management domain derives its transport's initial sequence
/// numbers from a per-boot secret it draws with `RDRAND` (RFC 6528), and refuses
/// to start at all when `CPUID.01H:ECX[30]` is clear rather than answering a
/// connection with a predictable number. QEMU's `qemu64` model does not expose it
/// — which this gate discovered by the domain refusing on its first boot, exactly
/// as it would on a part that lacked it — so the bench must, and any deployment
/// target must too. It has been present on Intel parts since Ivy Bridge (2012)
/// and on AMD since Excavator, so it costs no host compatibility either.
///
/// The six features after it are the appliance's compile-time CPU baseline on
/// `rdrand`'s precedent: the hardware-probe domain is compiled with SSSE3
/// through SSE4.2, AES-NI, PCLMULQDQ and ADX enabled, so on bare `qemu64`
/// — which exposes none of them — every boot would refuse the probe exactly as
/// a below-baseline part would. TCG implements all six, and every deployment
/// target carries them (universal since roughly 2013 on Intel and AMD parts),
/// so pinning them costs no host compatibility either.
///
/// Two features are deliberately absent. `popcnt`, because the target
/// specification does not enable it, so the compiler cannot emit it. And
/// `bmi2`, for the same reason and a sharper one: the model advertising a
/// feature is a claim about the part, and a CPUID bit no domain gates on and no
/// instruction uses is a claim nothing keeps. It was advertised while the target
/// enabled BMI2 — and TCG then refused the VEX-encoded instructions that
/// produced, because it will not execute that encoding while the guest's
/// `CR4.OSXSAVE` and `XCR0` leave the vector state disabled, which the pinned
/// kernel's XSAVE feature set never enables. The target, this model and both
/// domains' CPUID gates agree on that removal; disagreement between them is how
/// an image comes to be provable on one accelerator only.
const GUEST_CPU: &str = "qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave,+rdrand,+ssse3,+sse4.1,+sse4.2,+aes,+pclmulqdq,+adx";

/// Which accelerator a boot may use, decided by the scenario rather than by the
/// machine.
///
/// A property of the boot and not a switch on the run, because the two states
/// are not two ways of running the same gate: all but one scenario asks for
/// whatever is fastest, and exactly one asks for the slow one on purpose. Making
/// it a field is what lets the scenario table say which is which, and what keeps
/// a reader from having to find out by running it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accelerator {
    /// Whatever the machine offers: hardware where this process can use KVM,
    /// emulation where it cannot.
    WhateverTheMachineOffers,
    /// Emulation, whatever the machine offers.
    ///
    /// The image is one artifact and it has to execute under both, because a
    /// defect that only appears under emulation is otherwise invisible on every
    /// machine that has acceleration — and the machines that run this gate do.
    Emulated,
}

/// How QEMU will execute the guest and, when hardware acceleration was not
/// taken, why. Carrying the reason (rather than a bare flag) is the point: a
/// gate run that silently fell back to emulation must not be indistinguishable
/// from an accelerated one in its log — nor from one that emulated on purpose,
/// which is why a deliberate choice and a rejection are two variants and not one
/// string.
enum Acceleration {
    Kvm,
    Tcg {
        kvm_rejected_because: String,
    },
    /// Emulation because the boot asked for it, whatever the machine offers.
    TcgByRequest,
}

impl Acceleration {
    /// Whether the guest runs on the host's own processor. The one judge that
    /// asks is the cryptography domain's: a cycles-per-byte figure taken while
    /// every instruction is being emulated is a figure about the emulator.
    const fn is_hardware(&self) -> bool {
        matches!(self, Self::Kvm)
    }

    /// What `accelerator` asks for, against what this machine can give.
    ///
    /// A request for emulation is honoured without probing the device at all: a
    /// boot that exists to run the image on the emulator must not become an
    /// accelerated one because the machine happened to offer KVM.
    fn choose(accelerator: Accelerator) -> Self {
        match accelerator {
            Accelerator::Emulated => Self::TcgByRequest,
            Accelerator::WhateverTheMachineOffers => Self::detect(),
        }
    }

    /// Prefer hardware acceleration, but only when this process can actually
    /// open the KVM device read/write — the access QEMU itself needs.
    /// Existence alone is not enough: a container can expose the device node
    /// without granting the permission to use it.
    fn detect() -> Self {
        // `OpenOptions` opens with `O_CLOEXEC` on Linux and the handle is
        // dropped here, so the probe cannot leak a descriptor into QEMU.
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(KVM_DEVICE)
        {
            Ok(_probe) => Self::Kvm,
            Err(error) => Self::Tcg {
                kvm_rejected_because: format!("cannot open {KVM_DEVICE} read-write: {error}"),
            },
        }
    }

    fn qemu_accel(&self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Tcg { .. } | Self::TcgByRequest => "tcg",
        }
    }

    /// One line recording how the guest ran, for the operator's terminal and
    /// for the run log.
    fn describe(&self) -> String {
        match self {
            Self::Kvm => format!("accel=kvm cpu={GUEST_CPU}"),
            Self::Tcg {
                kvm_rejected_because,
            } => format!("accel=tcg cpu={GUEST_CPU} kvm-rejected: {kvm_rejected_because}"),
            Self::TcgByRequest => format!(
                "accel=tcg cpu={GUEST_CPU} emulation-requested: this boot proves the shipped \
                 image on the emulator whatever the machine offers"
            ),
        }
    }
}

/// How one boot is set up around the contract it must meet: which accelerator
/// executes it, how its management port is attached, and which probe set goes
/// out on the dataplane ports.
///
/// One struct rather than three parameters because they are one decision per
/// boot and are always chosen together — and because the accelerator only became
/// a choice at all once a boot existed whose subject was the accelerator, which
/// is exactly the kind of addition an argument list absorbs silently.
struct Bench {
    accelerator: Accelerator,
    management: ManagementBacking,
    traffic: Traffic,
    /// Whether this boot holds the appliance to the channel it dials out.
    dial: DialContract,
    /// Whether this boot opens a session on the appliance's onboarding port, and
    /// how the station on this end of it behaves.
    onboard: OnboardContract,
    /// Which store medium this boot attaches: a fresh one, the one an earlier
    /// boot of the same run minted an identity on — reset or not — or a copy of
    /// one an earlier boot was onboarded on.
    store: StoreMedium,
    /// Whether the appliance on that medium **has an owner**, which the scenario
    /// table derives and the boot cannot: a node without one forwards nothing,
    /// so this decides what the boot's own recordings can hold as well as what
    /// its console must say.
    owner: Ownership,
}

/// What a routed boot puts on its wires, as one value rather than four
/// adjacent arguments: how the management port is attached, which probes go out,
/// whether the appliance's own dial is judged, and which store medium it
/// attaches. A [`Bench`] without the accelerator, which a routed boot does not
/// choose — the routed contract is a statement about the image, so every boot of
/// it takes whatever the machine offers.
pub(crate) struct ForwardBench {
    pub(crate) management: ManagementBacking,
    pub(crate) traffic: Traffic,
    pub(crate) dial: DialContract,
    pub(crate) onboard: OnboardContract,
    pub(crate) store: StoreMedium,
    pub(crate) owner: Ownership,
}

/// Whether a boot judges the connection the appliance *originates* out of its
/// management port.
///
/// Its own field rather than a property of the management role, because the two
/// answer different questions and only one of them is decidable from the wire:
/// a socket-backed boot always answers the dial — a station on a link answers
/// for its own address whoever asks — and whether the exchange must *complete*
/// depends on the document the image under test was built from. The appliance
/// dials a first-party constant, so an image whose management prefix does not
/// contain it reaches the station and is right to refuse what it says back, its
/// own addressing rules putting that address off-link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialContract {
    /// The dial is answered and nothing is required of it. Every scenario whose
    /// subject is something else takes this.
    Answered,
    /// The dial must complete: the station sees the resolution, the handshake,
    /// the probe and the close, and the appliance reports the channel on its
    /// console as `answered` on its first attempt. One scenario carries it, for
    /// the reason every other pairing in this table has one — the claim is about
    /// the appliance and not about the document, so proving it twice would state
    /// the same fact twice.
    Judged,
    /// The station misbehaves in the named way, and the appliance must report the
    /// channel as the one outcome that misbehaviour can produce — while the node
    /// itself goes on forwarding and its management port goes on counting to the
    /// byte.
    ///
    /// A variant per misbehaviour rather than phases inside one boot: a station
    /// that changed its mind mid-run would leave a reader working out which half
    /// of a capture a frame belonged to, and each of the four is a different
    /// thing for an operator to go and look at.
    Misbehaves(DialMisbehaviour),
}

impl DialContract {
    /// How the station on the far end of this boot's dial behaves.
    pub(crate) const fn misbehaviour(self) -> DialMisbehaviour {
        match self {
            Self::Answered | Self::Judged => DialMisbehaviour::Answers,
            Self::Misbehaves(misbehaviour) => misbehaviour,
        }
    }

    /// Whether this boot spends frames keeping the port awake while its dial is
    /// outstanding. Only a boot that judges the channel needs to: everywhere else
    /// the dial is answered and left unasserted, so a channel that stalls costs
    /// the run nothing.
    pub(crate) const fn nudges(self) -> bool {
        !matches!(self, Self::Answered)
    }

    /// Whether this boot's station leaves the appliance's `SYN` unanswered, and
    /// so whether the run must watch the transport spend its whole
    /// retransmission budget on every session of the channel.
    ///
    /// The two modes that do are the silent one and the one whose bogus
    /// handshake is refused without ending the dial. A reset ends a session at
    /// once, and a resolution nobody answers never reaches a connection.
    pub(crate) const fn leaves_the_dial_unanswered(self) -> bool {
        matches!(
            self,
            Self::Misbehaves(
                DialMisbehaviour::SilentToTheDial | DialMisbehaviour::AcknowledgesTheWrongSequence
            )
        )
    }

    /// What the appliance's own record of the channel must say, where this boot
    /// reads it.
    ///
    /// The one place the four misbehaviours are turned into outcomes, and every
    /// answer here follows from the appliance's own code rather than from what
    /// would be convenient. **Each of the four is now its own token**, which is
    /// the point of asserting them: three of them once shared one, and an
    /// operator reading it could not tell a dead server from one refusing the
    /// port from one that is not speaking TCP correctly. The counts beside each
    /// token are what keep the three apart even if the tokens ever drifted back
    /// together, and each scenario states the subset that distinguishes it.
    ///
    /// Every station on this wire is on this port's own prefix, so the route
    /// decision hands each of them the destination itself and never the gateway
    /// — stated in all four, because a channel that went somewhere else would
    /// make every other count a fact about the wrong station.
    pub(crate) const fn verdict(self) -> Option<DialVerdict> {
        let (outcome, attempts, account) = match self {
            // Nothing is read: the boot does not judge the channel.
            Self::Answered => return None,
            // A station that answers is not a misbehaviour, so this pairing
            // names no outcome. A `None` rather than a panic: the caller refuses
            // it by name, which turns a table entry that cannot mean anything
            // into a verdict a reader can act on rather than a crash.
            Self::Misbehaves(DialMisbehaviour::Answers) => return None,
            // One session, answered — and no counts at all, a channel that came
            // up having no fault to place.
            Self::Judged => (DialOutcome::Answered, 1, None),
            // Three sessions, each carried to the end of the transport's own
            // retransmission budget with nothing at the far end answering. What
            // says so is `answered=false` beside a handshake count that spans
            // every attempt: the station took all of them and returned
            // nothing.
            Self::Misbehaves(DialMisbehaviour::SilentToTheDial) => (
                DialOutcome::Unanswered,
                3,
                Some(DialAccount {
                    next_hop: (forward_harness::DIAL_DESTINATION, "prefix"),
                    // The resolution worked: the station answers for the address
                    // it holds and only the connection is ignored. A floor
                    // rather than an exact count, because a cache entry that
                    // expires between sessions is asked about again.
                    requests: Count::AtLeast(1),
                    learned: Count::AtLeast(1),
                    unlearned: [Count::Exactly(0); 4],
                    // At least one per session and every re-send of it. A floor,
                    // the number of re-sends inside a boot being the backoff's.
                    syns: Count::AtLeast(3),
                    resets_received: Count::Exactly(0),
                    resets_sent: Count::Exactly(0),
                    answered: false,
                    acknowledged: false,
                }),
            ),
            // Three sessions, each refused by a reset the moment it opened. The
            // reset count is what separates this from the silence above, and the
            // absence of one *sent* is the protocol's own rule: a reset is never
            // answered with another.
            Self::Misbehaves(DialMisbehaviour::ResetsTheDial) => (
                DialOutcome::ResetByPeer,
                3,
                Some(DialAccount {
                    next_hop: (forward_harness::DIAL_DESTINATION, "prefix"),
                    requests: Count::AtLeast(1),
                    learned: Count::AtLeast(1),
                    unlearned: [Count::Exactly(0); 4],
                    syns: Count::AtLeast(3),
                    resets_received: Count::AtLeast(1),
                    resets_sent: Count::Exactly(0),
                    answered: true,
                    acknowledged: false,
                }),
            ),
            // Three sessions again, and for a reason worth stating: the bogus
            // handshake does NOT end one. It draws a reset and leaves the dial
            // where it was, so each session runs out the same retransmission
            // budget the silent station's does — and what tells the two apart on
            // the console is `answered=true`, a reset count that moved *outward*
            // rather than inward, and the two numbers the station claimed.
            Self::Misbehaves(DialMisbehaviour::AcknowledgesTheWrongSequence) => (
                DialOutcome::UnacceptableAcknowledgement,
                3,
                Some(DialAccount {
                    next_hop: (forward_harness::DIAL_DESTINATION, "prefix"),
                    requests: Count::AtLeast(1),
                    learned: Count::AtLeast(1),
                    unlearned: [Count::Exactly(0); 4],
                    syns: Count::AtLeast(3),
                    resets_received: Count::Exactly(0),
                    // One per bogus handshake refused, which is at least one per
                    // session. A floor for the handshake count's reason.
                    resets_sent: Count::AtLeast(3),
                    answered: true,
                    // The pair itself is the station's arithmetic and is
                    // supplied by the run: this scenario states that one is
                    // owed, and the numbers the appliance prints are compared
                    // against what the station read off the wire.
                    acknowledged: true,
                }),
            ),
            // Three sessions, none of which reached a connection: the neighbour
            // cache asked, was answered by somebody else, gave up, and no `SYN`
            // ever crossed the wire — which is the claim, and the station is
            // what holds it.
            //
            // Every one of the three ends on the link rather than on this node,
            // and the last is what the record names. Each session leaves behind
            // the connection its `SYN` was composed on — that segment was
            // dropped for want of an address, so the transport holds it in
            // `SynSent` and nothing at the far end will ever answer it — and
            // ending the session gives that connection back, so the dial after
            // it opens a new one rather than meeting this node's own table.
            // That is what keeps the token a fact about the link: an operator
            // reading it goes and looks at what claims the next hop.
            Self::Misbehaves(DialMisbehaviour::AnswersForAnotherAddress) => (
                DialOutcome::NextHopUnreachable,
                3,
                Some(DialAccount {
                    next_hop: (forward_harness::DIAL_DESTINATION, "prefix"),
                    // The whole request budget, three times over, and nothing
                    // learned from any of them: the pair is the entire meaning
                    // of the token.
                    requests: Count::AtLeast(3),
                    learned: Count::Exactly(0),
                    // And this is what says the link is not silent: somebody is
                    // answering, and every answer is for an address nobody asked
                    // about. It is the count that separates a station holding
                    // the wrong address from a link with nothing on it at all.
                    unlearned: [
                        Count::AtLeast(3),
                        Count::Exactly(0),
                        Count::Exactly(0),
                        Count::Exactly(0),
                    ],
                    // At least one per session, composed and dropped for want
                    // of an address — and re-sent by the transport's own
                    // backoff while the resolution runs, which is why this is a
                    // floor and not the three sessions. **None of them reached
                    // the wire**, which is the claim this scenario rests on and
                    // the station holds it separately by seeing no `SYN` at all.
                    syns: Count::AtLeast(3),
                    resets_received: Count::Exactly(0),
                    resets_sent: Count::Exactly(0),
                    answered: false,
                    acknowledged: false,
                }),
            ),
        };
        Some(DialVerdict {
            outcome,
            attempts,
            account,
        })
    }
}

/// Whether a boot opens a session on the **second** port the appliance's
/// management endpoint listens on, and what it must be answered with.
///
/// [`DialContract`]'s shape on the other port and the other direction: there the
/// appliance connects and the harness answers, here the harness connects and the
/// appliance answers. The station's behaviour is chosen once and held for the
/// whole boot, so a reader never has to work out which half of a capture a frame
/// belongs to.
///
/// **Only three boots open one, and that is structural rather than thrifty.**
/// The port holds one connection at a time, so a session opened on every boot
/// would sit beside every other contract this harness states — and a scenario
/// whose subject was something else would be the one to fail when the port did.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnboardContract {
    /// Nothing is opened. Every scenario whose subject is something else takes
    /// this.
    Untouched,
    /// The station behaves in the named way and the appliance must report the
    /// one set of records that behaviour produces — while the node itself goes
    /// on forwarding and its management port goes on counting to the byte.
    Session(OnboardBehaviour),
    /// **Real clients**, one after another through a forwarded host port, and
    /// no station at all. What is judged is the handshake each of them drew: one
    /// that must complete and three that must fail, each under its own token.
    ///
    /// Mutually exclusive with [`Self::Session`] by construction, on
    /// [`ManagementRole`]'s terms: a boot either plays the station on that wire
    /// or lets a client onto it, and a boot that did both would be two things on
    /// one wire.
    Handshakes,
    /// **Real clients again**, and the surface above the handshake: the page,
    /// the request it links to, and three requests that must be refused, each
    /// under its own token.
    ///
    /// Its own variant rather than more clients on [`Self::Handshakes`] because
    /// the two prove different things and each boot's contract is exact: that
    /// one owes one handshake record per attempt, and this one owes one request
    /// record per attempt. A boot doing both would owe a count neither contract
    /// states.
    Requests,
    /// **The management server**, played by this harness against an appliance
    /// that has never met one ([`crate::onboard_install_contract`]): it reads
    /// the request the appliance serves, issues a device certificate against a
    /// certification authority of this checkout's own, composes a package to
    /// the package contract, has two packages refused by name, uploads the one
    /// this appliance can take, and then finds the surface shut behind it.
    ///
    /// Its own variant for the reason [`Self::Requests`] is one: this boot's
    /// contract is that an appliance *changed hands*, which is a claim the two
    /// read-only ones cannot make and which the appliance can satisfy exactly
    /// once.
    Onboards,
    /// The same clients against the appliance a **previous boot of this run**
    /// took ownership of, over the medium it left behind.
    ///
    /// What is judged here is an absence, and it is the half the boot above
    /// cannot prove: a close that a restart undid would satisfy every assertion
    /// that boot makes.
    Owned,
}

impl OnboardContract {
    /// How the station this harness plays on that port behaves.
    pub(crate) const fn behaviour(self) -> OnboardBehaviour {
        match self {
            // A boot that lets real clients in plays no station, so the station
            // this harness would otherwise put on the wire does nothing.
            Self::Untouched | Self::Handshakes | Self::Requests | Self::Onboards | Self::Owned => {
                OnboardBehaviour::Untouched
            }
            Self::Session(behaviour) => behaviour,
        }
    }

    /// Whether this boot runs real clients against the port.
    pub(crate) const fn handshakes(self) -> bool {
        matches!(self, Self::Handshakes)
    }

    /// Whether this boot runs real clients against the surface above it.
    pub(crate) const fn requests(self) -> bool {
        matches!(self, Self::Requests)
    }

    /// Whether this boot plays the management server and gives the appliance an
    /// owner.
    pub(crate) const fn onboards(self) -> bool {
        matches!(self, Self::Onboards)
    }

    /// Whether this boot returns to an appliance a previous one adopted.
    pub(crate) const fn revisits(self) -> bool {
        matches!(self, Self::Owned)
    }

    /// What the appliance must say about the session, given how the station
    /// ended it.
    ///
    /// The one place the three behaviours are turned into records, and every
    /// answer here follows from the appliance's own code rather than from what
    /// would be convenient. What is *not* here is every count the machine
    /// decides: the items a session's handover spends are a floor stated where
    /// the contract judges them, and the bytes are what the run's own station
    /// put on the wire.
    pub(crate) const fn verdict(self) -> Option<OnboardVerdict> {
        let (ended, forgotten) = match self {
            // Nothing is read: the boot opens no session, or it opens several
            // and they are judged as handshakes, as requests, or as what one
            // management server did, rather than as one session.
            Self::Untouched | Self::Handshakes | Self::Requests | Self::Onboards | Self::Owned => {
                return None;
            }
            // A station that opens nothing is not a session, so this pairing
            // names no records. A `None` rather than a panic: the caller refuses
            // it by name, which turns a table entry that cannot mean anything
            // into a verdict a reader can act on.
            Self::Session(OnboardBehaviour::Untouched) => return None,
            // The peer closed its half and the appliance closed after it, so the
            // connection was given up by agreement and the transport lost
            // nothing.
            Self::Session(OnboardBehaviour::Completes) => (OnboardEnd::Peer, Count::Exactly(0)),
            // A reset with neither end having said the session was over, so the
            // connection stopped existing under a session that was still
            // running. `forgotten` is the port's own count of exactly that, and
            // it is what separates this from the close above on a surface where
            // the two once shared one token.
            Self::Session(OnboardBehaviour::Abandons) => (OnboardEnd::Forgotten, Count::Exactly(1)),
            // The crowding station ends its own session exactly as the first
            // does; what it adds is an absence on the wire and a port that
            // accepted one connection rather than two, both of which the
            // contract states of every session it judges.
            Self::Session(OnboardBehaviour::Crowds) => (OnboardEnd::Peer, Count::Exactly(0)),
        };
        Some(OnboardVerdict { ended, forgotten })
    }
}

/// Which store medium a boot attaches at 00:06.0 — the appliance's own.
///
/// A property of the scenario rather than of the run, on [`Accelerator`]'s terms.
/// It decides two things at once and they are worth separating. The first is
/// whether the boot's *identity* is its own or an earlier boot's, which is what
/// the store scenarios are about. The second is whether the appliance the boot
/// brings up **has an owner** — and that one is not a subject at all for most of
/// this table, it is a precondition: an unowned node forwards nothing, so a
/// scenario about routing, filtering, tracking or the management channel has to
/// boot a node somebody already onboarded, exactly as a deployed one would be.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreMedium {
    /// A fresh, zero-filled medium, so the boot mints an identity **and comes up
    /// unowned**. Taken by every scenario whose subject is an appliance nobody has
    /// taken yet — the onboarding surface, the identity a mint produces, and the
    /// node that refused its own document — and by no other, a medium carried
    /// between two unrelated boots letting one pass on an identity another minted.
    Fresh,
    /// The medium the named scenario's *shipping* boot left behind — the file
    /// itself, not a copy of it.
    ///
    /// The source's shipping label rather than this run's, so a diagnostic re-run
    /// of the reloading scenario reads the same medium the shipping run judged.
    /// A reload writes nothing, so reading it twice is not a second commit.
    ///
    /// For the two boots whose claim *is* the medium, and for no others: sharing
    /// one file is what makes "the identity survived" sayable and what would let
    /// any third boot pass on state to a fourth.
    CarriedFrom(&'static str),
    /// This boot's **own copy** of the medium the named scenario's shipping boot
    /// left behind.
    ///
    /// What a deployed appliance is: onboarded once, long before, and running ever
    /// since. Every scenario whose contract needs frames to cross takes this, and
    /// the alternative — onboarding during its own boot — is not available, because
    /// an install shuts the onboarding surface for good and so has to be the last
    /// thing a boot does. A copy costs nothing and reorders nothing.
    ///
    /// A copy rather than [`Self::CarriedFrom`]'s shared file, because these boots
    /// make no claim about the medium and several of them write to it. Nineteen
    /// boots sharing one file would let one scenario's writes decide another's
    /// verdict, which is precisely the coupling the recorder's fresh-per-boot disk
    /// exists to prevent.
    CopiedFrom(&'static str),
    /// The same medium, with a **factory-reset request** written onto one sector
    /// of it before the boot — which is the whole of how a reset is asked for,
    /// there being no channel operation, no configuration document and no console
    /// input that can invoke one.
    ///
    /// A separate variant rather than a flag on the one above, because the two
    /// scenarios owe opposite things of the same medium: one must come back the
    /// same appliance and the other must not come back that appliance at all.
    ResetRequestedOn(&'static str),
}

/// What a boot owes the raw device at 00:05.0, which follows from its contract
/// and from nothing the run observed.
enum DataDiskVerdict {
    /// The appliance ran, so the recorder's witness pattern must be on the
    /// medium: its absence is a domain that never started.
    WitnessWritten,
    /// No slot was bootable, so the sector must be exactly as it was made: a
    /// witness here would be the host having written it.
    SectorUntouched,
    /// Neither, because the boot ends before the two are ordered against each
    /// other. The only such boot is the one whose subject is the accelerator.
    NotThisBootsSubject,
}

/// A prepared QEMU invocation together with the record of how it will execute.
struct Invocation {
    command: Command,
    acceleration: Acceleration,
    /// The data device this run created and attached, kept so the caller can
    /// read it back once QEMU has exited. Every invocation gets one — including
    /// the interactive `run`, whose guest would otherwise find no device at
    /// 00:05.0 and park the recorder on a refusal, which is a boot no shipped
    /// image would ever perform.
    data: DataDisk,
    /// The store device this run attached — created fresh, or the one an earlier
    /// boot left, with or without a factory-reset request written onto it. Every
    /// invocation gets one for the reason every one gets a data device: a domain
    /// staring at an absent device is a different boot from the one the image was
    /// assembled for.
    store: StoreDisk,
}

/// Which disk a scenario boots on a [`Run::Shipping`] run.
///
/// It does not decide a [`Run::Diagnostic`] re-run, which always assembles its
/// own disk into the build tree — see [`scenario_disk`].
pub(crate) enum ImageUnderTest {
    /// The disk `dist/` already holds — what `image` published and what an
    /// operator would deploy. `dist/` is left exactly as it is.
    Published,
    /// A disk assembled here from the scenario's own configuration document,
    /// into the build tree. Nothing published changes.
    BuiltForTheScenario,
}

/// What a scenario does with the management port.
///
/// The two are mutually exclusive by construction, which is the point: a
/// harness that plays a station on the wire sees every frame and composes every
/// reply, and a harness that lets a real client in sees none of them. Asserting
/// both in one boot would mean two things on one wire.
pub(crate) enum ManagementRole {
    /// The harness is the station: it injects opaque frames, an ARP request, an
    /// ICMP echo request and a whole TCP exchange, and judges every answer field
    /// by field.
    Station,
    /// The harness is a client. QEMU's user-mode stack carries the port and
    /// `curl` pulls **every surface the endpoint serves** through a host port
    /// forward — `GET /metrics`, `GET /logs.pcapng` and `GET /capture.pcapng` —
    /// and all three are judged, together.
    ///
    /// All three, on every scenario that reaches the endpoint, because judging
    /// one of them is the gap: a recording that silently drops, a metric that
    /// double-counts and a tap that loses a record are each invisible in the
    /// surface they occur in and each a disagreement between two of them
    /// ([`crate::surface_contract`]). Nothing at frame level is asserted on this
    /// wire; what is asserted is the HTTP responses, one metric value against
    /// traffic the harness observed on the *dataplane* ports in the same boot,
    /// every label of the interface info family against the configuration
    /// document this image was built from, the two recordings against each
    /// other and against the bytes the harness injected, and the same two
    /// extents read straight off the disk image after the run — one artifact
    /// reached two ways, neither of them the appliance's own account of itself.
    Client,
}

impl ManagementRole {
    /// Whether QEMU's user-mode stack carries the port, which is what a real
    /// client needs and what a frame-level station forbids.
    const fn user_network(&self) -> bool {
        matches!(self, Self::Client)
    }
}

impl Scenario {
    /// Whether a real client can reach this boot's management port, and so whether
    /// it pulls every surface the endpoint serves and holds the three to each other.
    ///
    /// Exposed because the status pages state how many scenarios do, and a count
    /// restated in prose beside a list nothing compares it to goes stale
    /// ([`crate::reference_contract`]).
    pub(crate) const fn reaches_the_management_port(&self) -> bool {
        self.management.user_network()
    }
}

/// Whether a scenario reads the console beside the traffic.
///
/// One flag for every channel rather than one each, because it is one decision:
/// a scenario either judges what the appliance said or is left to report a
/// forwarding failure as a forwarding failure and nothing else. What
/// [`Console::Judged`] covers is the `LFW-CFG` transcript
/// ([`crate::config_transcript`]) and three records on the `LFW-PD` channel —
/// the clock domain's ([`crate::clock_contract`]), the hardware probe's
/// ([`crate::probe_contract`]), the cryptography domain's
/// ([`crate::crypto_contract`]) and the management port's count
/// ([`crate::management_contract`]).
pub(crate) enum Console {
    Ignored,
    Judged,
    /// The node **refused the document its own image carries**, so it committed no
    /// generation, has no address, and the console is the only surface it has.
    ///
    /// Judged as part of the boot contract ([`BootContract::FailedClosed`]) rather
    /// than after it, and for a reason the other two do not have: the records are
    /// also what tell the run the node has finished refusing, so there is nothing
    /// to wait for otherwise — such a node runs indefinitely, forwarding nothing.
    ///
    /// It reaches none of the three contracts [`Self::Judged`] runs. Two of them
    /// have nothing to state: there is no committed configuration to compare a
    /// transcript against, and no management frame is injected, so the port's own
    /// count has no number to equal. The third — the clock record — is a domain that
    /// does come up, and holding it here would make a clock failure read as a
    /// fail-closed failure.
    JudgedOnARefusal,
    /// **The cryptography domain's records, and nothing else at all** — neither
    /// the four other channels [`Self::Judged`] reads nor the traffic.
    ///
    /// The narrow half of a deliberately narrow boot. Every other statement the
    /// gate makes here is a statement about the *image*, and the boots that
    /// carry it have already made them; what this one asks is whether the same
    /// bytes execute on the other accelerator, which is a question only this
    /// domain has ever answered no to. So the vectors and the session are
    /// judged, the measured costs are reported without a verdict — a cycle count
    /// taken while every instruction is a host function call is a figure about
    /// the emulator, which [`crate::crypto_contract::judge`] already declines
    /// rather than something this boot special-cases — and nothing else is
    /// re-proved.
    JudgedOnCryptographyAlone,
    /// **The store domain's records, and nothing else at all.**
    ///
    /// [`Self::JudgedOnCryptographyAlone`]'s shape and its reasoning, for the two
    /// other questions a single boot cannot answer. Every other statement this
    /// gate makes here is about the *image*, and the boots that carry it have
    /// already made them; what only these boots and their partners can settle is
    /// whether the identity on one medium survives a reboot, and whether a factory
    /// reset takes it away. So the identity records are judged, each boot is held
    /// to the one whose medium it inherited after the run, and nothing else is
    /// re-proved.
    JudgedOnTheStoredIdentityAlone,
    /// **The channel the appliance dialled, and the port's own count beside it.**
    ///
    /// The narrow shape again, for the four boots whose subject is a management
    /// station that misbehaves. The transcript, the clock, the hardware probe and
    /// the cryptography domain are facts about the image that other boots state,
    /// and re-stating them on four more would pay four whole boots for a second
    /// reading of the same fact.
    ///
    /// The port's count is not a fifth such fact and is here on purpose: it is
    /// the evidence that the node stayed healthy while its channel failed. The
    /// appliance must report every frame the harness put on that wire, to the
    /// frame and to the byte — and on the two boots whose station leaves a `SYN`
    /// unanswered that is hundreds of frames, spent carrying a channel that never
    /// comes up, so a domain that faulted, stalled or lost its place under one
    /// cannot satisfy it. Beside it the boot's own routed contract says the
    /// dataplane went on forwarding throughout.
    JudgedOnTheDialledChannelAndThePortsCount,
    /// **The session the appliance carried on its onboarding port, and the port's
    /// own count beside it.**
    ///
    /// [`Self::JudgedOnTheDialledChannelAndThePortsCount`]'s shape on the other
    /// of the two ports that endpoint listens on, and it is here for the same
    /// two reasons. The transcript, the clock, the hardware probe and the
    /// cryptography domain are facts about the image that other boots state, and
    /// re-stating them on three more would pay three whole boots for a second
    /// reading of one fact.
    ///
    /// And the port's count is not a fifth such fact: it is the evidence that
    /// the node stayed healthy while a second protection domain was driven over
    /// a relay by an unauthenticated peer's bytes. The appliance must report
    /// every frame the harness put on that wire, to the frame and to the byte,
    /// over a boot in which many of them are spent waking a domain that has no
    /// timer of its own — so a domain that faulted, stalled or lost its place
    /// carrying a session cannot satisfy it. Beside it the boot's own routed
    /// contract says the dataplane went on forwarding throughout.
    JudgedOnTheOnboardingSessionAndThePortsCount,
    /// **The handshakes real clients drew out of the onboarding port, and
    /// nothing else on the console.**
    ///
    /// The narrow shape once more, on the boot that lets clients onto that wire
    /// instead of playing a station on it. The transcript, the clock, the
    /// hardware probe and the cryptography domain's bring-up are facts about the
    /// image that other boots state; what only this boot can settle is whether
    /// the server behind that port interoperates with a client this project did
    /// not write, and says how each attempt ended in a vocabulary an
    /// administrator can act on.
    ///
    /// The port's own frame count is deliberately **not** here, unlike on the
    /// two narrow shapes above it. There is no station on this wire, so the
    /// harness sees no frame and has no number to hold the console to; what
    /// stands in its place is the request surface, pulled and judged in the same
    /// boot, which is the same statement — the node stayed healthy while an
    /// unauthenticated peer drove a second protection domain four times over.
    JudgedOnTheOnboardingHandshakes,
    /// **The requests real clients made on the surface above those
    /// handshakes**, on [`Self::JudgedOnTheOnboardingHandshakes`]'s terms: what
    /// the page carried, what `openssl` made of the request it links to, and
    /// the token each refused request reached the console under.
    JudgedOnTheOnboardingRequests,
    /// **What a management server did to an appliance that had never met one**,
    /// and the store domain's own account of having changed hands.
    ///
    /// The narrow shape once more, and the widest claim any single boot in this
    /// table makes: the three boots above read what an unprovisioned appliance
    /// *serves*, and this one drives it all the way through the one transition
    /// it has. So both domains are read — the one that answered the requests,
    /// for the token each of them drew, and the one that made the ownership
    /// durable, for the anchor's fingerprint and the endpoint it will answer to
    /// — and held to what this run's own certification authority issued.
    JudgedOnTheOnboardingInstall,
    /// **An appliance that came back owned, and serves nothing.**
    ///
    /// The other half of the claim above, and the half no single boot can make:
    /// a surface a restart reopened would satisfy every assertion the boot that
    /// installed makes. So the store domain's record is read for the identity
    /// that returned — the same appliance, now with an owner — and every
    /// address the surface once had is asked for and found gone.
    JudgedOnTheOwnedApplianceServingNothing,
}

/// One system scenario: which disk, which configuration document the appliance
/// in it was built from, which accelerator it runs on, and what the boot must
/// prove.
pub(crate) struct Scenario {
    name: &'static str,
    /// The document, relative to the workspace root. It is what the endpoints
    /// are derived from *and* what the appliance was compiled around, which is
    /// the whole point: neither side of the contract can hold a stale address
    /// the other does not.
    document: &'static str,
    image: ImageUnderTest,
    console: Console,
    management: ManagementRole,
    /// Which probe set this boot injects into the two dataplane ports.
    traffic: Traffic,
    /// Whether this boot holds the appliance to the channel it dials out of its
    /// management port.
    dial: DialContract,
    /// Whether this boot opens a session on the appliance's onboarding port, and
    /// how the station on this end of it behaves.
    onboard: OnboardContract,
    /// Which accelerator QEMU must use. All but one scenario take whatever the
    /// machine offers; the one that does not is what proves the shipped image
    /// runs on the emulator as well as on a processor.
    accelerator: Accelerator,
    /// Which store medium this boot attaches, which decides both the identity it
    /// comes up under and **whether it has an owner at all** — an appliance nobody
    /// has onboarded forwards nothing, so this is a precondition of most of this
    /// table rather than a subject of it. [`ownership_at_boot`] derives the second
    /// answer from this field, so a scenario cannot state one and boot the other.
    store: StoreMedium,
}

/// Boot the deployable disk through OVMF/GRUB and prove the complete system
/// behaviour, in the kernel configuration a release ships. Returns what the run
/// proved.
///
/// What each boot is for is on [`SCENARIOS`], beside the entries themselves.
pub(crate) fn test_system(root: &Path) -> Result<String, String> {
    run_scenarios(root, SCENARIOS)
}

/// The scenario whose boot leaves behind a medium an appliance has been
/// onboarded on.
///
/// Named rather than left as a literal because two things need the same answer:
/// the boot a suite runs to *get* an owned medium, and the source a
/// [`StoreMedium::CopiedFrom`] names to take a copy of one. A caller outside this
/// module states the name once and gets both.
pub(crate) const OWNED_MEDIUM_SOURCE: &str = "onboarding-adopted";

/// Boot the scenario that gives an appliance an owner, for a run that needs an
/// owned medium of its own.
///
/// The A/B run is the caller, and it needs one for the reason nineteen scenarios
/// in the table above do: a node no management plane has taken refuses every
/// frame before it looks at it, so a suite whose subject is that **slot selection
/// yields a working appliance** cannot state that against an unowned one. A
/// firewall that came up carrying nothing is not a working firewall, and a
/// dataplane broken by whatever the machinery selected would satisfy a contract
/// that only asked whether the stack started.
///
/// Its scenarios cannot each onboard during their own boot, for the reason the
/// table's cannot: an accepted package shuts the onboarding surface for good, so
/// the management server has to be the last client a boot runs, and a boot that
/// onboarded itself first would inject its traffic afterwards — a different loop
/// from the one every scenario runs.
///
/// **This boot rather than a second definition of one.** There is one way an
/// appliance changes hands, and a suite that restated it would be proving its own
/// restatement rather than the appliance; running the scenario that already
/// states it also means the medium is judged on the way out — the install held to
/// the package contract, the store domain's own account of the identity it now
/// carries — instead of being a file some boot happened to leave. What it costs
/// the caller is one boot.
///
/// # Errors
/// The scenario not being declared in [`SCENARIOS`], and anything the boot
/// itself fails — with the diagnostic re-run every shipping failure gets.
pub(crate) fn boot_the_owned_medium_source(root: &Path) -> Result<(), String> {
    let scenario = SCENARIOS
        .iter()
        .find(|scenario| scenario.name == OWNED_MEDIUM_SOURCE)
        .ok_or_else(|| {
            format!(
                "{OWNED_MEDIUM_SOURCE} is the boot that leaves a medium an appliance has been \
                 onboarded on, and the scenario table declares none by that name, so a run asking \
                 for an owned medium has nothing to boot"
            )
        })?;
    // Derived from the medium it attaches like every other boot's, rather than
    // stated here: this one starts from a fresh medium and so comes up unowned,
    // and it is the install it runs that leaves an owner behind.
    let owner = ownership_at_boot(SCENARIOS, scenario)?;
    if let Err(verdict) = run_scenario(root, scenario, Run::Shipping, owner) {
        return Err(diagnose::after_shipping_failure(
            &format!("system scenario {}", scenario.name),
            verdict,
            &scenario_log(root, scenario, Run::Shipping),
            &scenario_log(root, scenario, Run::Diagnostic),
            || run_scenario(root, scenario, Run::Diagnostic, owner).map(|_| ()),
        ));
    }
    Ok(())
}

/// Every system scenario the gate boots, in the order it boots them.
///
/// A module constant rather than a local, so the two counts the status pages
/// state about this gate — how many scenarios there are, and how many of them
/// reach the management port — are readable as data by
/// [`crate::reference_contract`] and held to those pages. A count restated in
/// prose beside a list nothing compares it to is a number that goes stale with
/// every stage green, which is the defect that check exists for.
///
/// # The order, which is a dependency and not a preference
///
/// **onboarding-adopted comes first**, and everything about the order follows from
/// that. It is the boot that gives an appliance an owner, and a node without one
/// forwards nothing at all — so nineteen of the boots below copy the medium it
/// leaves rather than booting an appliance that would refuse every frame they
/// inject. The pair that reads one medium twice comes after the boot that writes
/// it, for the same shape of reason. Both dependencies are checked before a single
/// boot runs ([`check_media_order`]), so a table edit that reordered a pair is a
/// verdict rather than an hour of boots ending in a puzzle.
///
/// The list below numbers the first nine; the ones after them carry their reasons
/// beside the entries themselves, where a reader meets them.
///
/// 1. **onboarding-adopted** — an appliance nobody owns is given an owner by this
///    run's management server, over the surface it serves for exactly that. Its
///    own contract is the install; what it additionally provides is the owned
///    medium the nineteen scenarios that need frames to cross take copies of, and
///    the *unowned* half of the ownership contract, its six probes being refused
///    because at the moment they are injected nothing has taken this node.
/// 2. **routed-forwarding** — the published disk, judged by the routed contract
///    alone. It is the regression guard: exactly the contract that existed
///    before configuration management, now stated between endpoints read out of
///    the document rather than written beside it, so a forwarding failure is
///    reported as a forwarding failure and nothing else.
/// 3. **generation-swap** — the same disk, judged additionally by what it said:
///    the node comes up fail-closed on generation 0 and switches to generation
///    1, whose change records are the document's own diff, and its clock domain
///    establishes a time and reports the frequency it measured. A separate boot,
///    because a transcript that could only be read off a run whose traffic had
///    already passed would be silent in exactly the case it exists for — a node
///    that committed nothing and forwarded nothing.
/// 4. **alternate-configuration** — a disk assembled from a second document
///    that shares no address and no MAC with the first, judged by both. This is
///    what proves the dataplane reads its table from the document: a compiled-in
///    table would satisfy scenarios 2 and 3 and fail every probe here.
/// 5. **metrics-endpoint**, 6. **metrics-endpoint-alternate** and
///    7. **recording-download** — `curl` pulls every surface the endpoint serves
///    through QEMU's own user-mode stack: `GET /metrics`, `GET /logs.pcapng` and
///    `GET /capture.pcapng`. Scenarios 5 and 7 run against the published disk and
///    6 against a disk built from the second document, and each is judged
///    against *its own* document — which is what makes the interface info family
///    a checked statement about the running configuration, the two documents
///    sharing no identity, so a label the build carried rather than read would
///    pass one and fail the other. The same holds the probes the recordings are
///    compared against: the two benches inject different bytes.
///
///    All three surfaces are judged on all three scenarios, and then against
///    each other ([`crate::surface_contract`]). A scenario that booted a
///    reachable endpoint and judged one of them is the gap that closes: a
///    recording that silently drops, a metric that double-counts and a tap that
///    loses a record are each invisible in the surface they occur in.
///
/// 8. **policy-filter** and 9. **policy-filter-alternate** — the filter's own
///    two, and the only two that inject a different probe set: one packet per
///    outcome the filter can reach, differing from each other in the UDP
///    destination port and in nothing else. One is forwarded because a rule
///    permits it, one is dropped by a rule though it is routable in every other
///    respect, and one falls past the last rule to the default deny. All three
///    are held apart three ways — the wire (one delivery, two absences), the drop
///    reason, and the per-rule hit counter — and each scenario is judged against
///    its own document, whose policy names different ports under different rule
///    ids. Two rather than one for scenario 6's reason: a counter labelled with a
///    name the build carried, rather than one it read, would satisfy one and fail
///    the other.
///
/// Every scenario but `cryptography-under-emulation` additionally injects frames
/// into the dedicated management port and holds that port to carrying nothing
/// back, whatever else it judges; the two that read the console also hold the
/// management domain's own count to the frames and bytes injected. That one
/// injects none, its subject being the accelerator rather than any contract the
/// appliance owes.
///
/// And every one of them, whatever else it proves, is held to the ownership its
/// medium carried ([`crate::ownership_contract`]) — the premise the forwarding
/// half of each contract above rests on, stated by the appliance on the one
/// surface a deployed node always has.
pub(crate) const SCENARIOS: &[Scenario] = &[
    // FIRST, and the position is load-bearing rather than a preference.
    //
    // This is the boot that gives an appliance an owner, and an owned appliance
    // is what nineteen of the boots below need: a node no management plane has
    // taken forwards nothing at all, so a routing, filtering, tracking or channel
    // contract stated against an unowned one would be stated against a node that
    // refuses every frame before it looks at it. They take copies of the medium
    // this boot leaves, which costs the run no extra boot and puts each of them
    // in the position a deployed appliance is actually in — onboarded once, long
    // ago, and running ever since.
    //
    // They cannot each onboard during their own boot instead, and that is the
    // reason this one is a source rather than a step every scenario repeats: an
    // install shuts the onboarding surface for good, so the management server has
    // to be the last client a boot runs. A boot that onboarded itself first would
    // have to inject its dataplane traffic afterwards, which is a different loop
    // from the one every other scenario runs.
    Scenario {
        name: "onboarding-adopted",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheOnboardingInstall,
        management: ManagementRole::Client,
        // The shipped six, every one of them owed a refusal: at the moment they
        // are injected this appliance has no owner, the management server being
        // the last thing this boot runs. That is not a weaker version of the
        // routed contract — it is the other half of it, the same six frames the
        // boots below watch cross an owned node.
        traffic: Traffic::Unowned,
        dial: DialContract::Answered,
        onboard: OnboardContract::Onboards,
        accelerator: Accelerator::WhateverTheMachineOffers,
        // Fresh, necessarily: the whole subject is an appliance that has never
        // had an owner being given one.
        store: StoreMedium::Fresh,
    },
    Scenario {
        name: "routed-forwarding",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "generation-swap",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Judged,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Judged,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "alternate-configuration",
        document: ALTERNATE_DOCUMENT,
        image: ImageUnderTest::BuiltForTheScenario,
        console: Console::Judged,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "metrics-endpoint",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        // The console is not judged here and it is not an omission: this
        // scenario injects no management frame, so the `frames=`/`bytes=`
        // equality the other two hold the console to has nothing to be
        // stated against. What it judges instead is the endpoint's answer.
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The same scrape against a disk built from the second document, and the
    // one thing the scenario above cannot show: that the identity the
    // interface info series carry comes from the document rather than from
    // the build. Both scrapes are judged against the document their own image
    // was assembled from, and the two documents share no id, no address and
    // no MAC — so a label compiled in would satisfy one of the two and fail
    // the other.
    //
    // Its management addressing differs too, which is why this works at all:
    // QEMU's user-mode stack is told the network, the station and the
    // endpoint out of the document (`forward_harness::user_netdev`), so the
    // forward reaches whatever address the document names.
    Scenario {
        name: "metrics-endpoint-alternate",
        document: ALTERNATE_DOCUMENT,
        image: ImageUnderTest::BuiltForTheScenario,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The recording milestone's own scenario. It is no longer the only one
    // that pulls the recordings — every [`ManagementRole::Client`] scenario
    // does, which is the point of there being one role — and it remains
    // because it is the pairing of the published disk with the recording
    // surfaces, where the two above pair the same surfaces with the two
    // documents. The download proves the whole chain from tap to HTTP; the
    // disk read after it proves what is on the medium independently, so a
    // recorder that composed a plausible body out of nothing would pass one
    // and fail the other.
    Scenario {
        name: "recording-download",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The filter's own two scenarios, and the reason there are two of them
    // rather than one: the three outcomes have to be shown to follow from the
    // *document* rather than from the build, exactly as the routed contract
    // does. Each boots a disk assembled around its own policy, and the two
    // policies name different ports under different rule ids — so a per-rule
    // counter labelled with a name the build carried, or a port a rule no
    // longer covers, satisfies one and fails the other.
    //
    // Both are `Client` scenarios, because the metric is half the evidence: a
    // drop reason says which of the two refusals happened and the per-rule
    // counter says which rule reached it, and neither is visible on the wire
    // — where all a refused probe leaves is its absence.
    Scenario {
        name: "policy-filter",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Policy,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "policy-filter-alternate",
        document: ALTERNATE_DOCUMENT,
        image: ImageUnderTest::BuiltForTheScenario,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Policy,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The one contract a stateless filter cannot meet, on both documents.
    //
    // A request goes out, its reply comes back — and the reply is addressed to
    // a port neither document says anything about, so nothing in the policy
    // permits it. What carries it is the flow the request opened, and the
    // scrape says so: `librefirewall_flow_packets_total{outcome="established"}`
    // rises while the accepting rule's hit counter counts only the openings.
    //
    // Beside it, the two refusals that keep that from being a hole: the same
    // packet with no request in front of it, and a TCP segment from the middle
    // of a conversation the appliance never saw begin. Both are refused, and
    // the two are told apart by reason — one falls to the default deny, the
    // other is refused as mid-stream before the filter is consulted at all.
    //
    // `Client` scenarios, because every one of those statements is a metric:
    // on the wire a refused probe leaves only its absence, and the reply's
    // arrival alone would not say which mechanism let it through.
    Scenario {
        name: "stateful-tracking",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Stateful,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "stateful-tracking-alternate",
        document: ALTERNATE_DOCUMENT,
        image: ImageUnderTest::BuiltForTheScenario,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Stateful,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The one thing a connection history needs that no other scenario can
    // produce: a conversation that **opens and closes**.
    //
    // It boots its own document because a close needs TCP and both other
    // documents' rules name `protocol="udp"`, so a TCP segment matches
    // neither and falls to the default deny — correct behaviour that leaves a
    // lifecycle unreachable. This one's rules are the shipped document's with
    // the protocol criterion widened, and nothing else changed.
    //
    // That widening is also what makes this the only scenario in the gate
    // where a **rule** refuses a TCP segment. It injects an opening segment to
    // the port the dropping rule names, and the rule drops it — where on every
    // other bench the same segment is refused for its protocol by the default
    // deny, so no rule about a port ever decides one. Protocol-specific
    // matching is therefore stated in both directions on a booted image: a
    // segment a rule admits crosses, and a segment a rule denies is dropped
    // with the reason and the hit counter that name that rule.
    //
    // A `Client` scenario, because the whole of what it proves is on the two
    // recordings and in the exposition: on the wire an opening and a close are
    // two frames that were forwarded, nothing about either says a conversation
    // began or ended, and all a denied segment leaves is its absence.
    // The one scenario that CHANGES what the appliance is doing, and the only
    // evidence there is that this node is configurable at all.
    //
    // It boots the published disk, so the policy in force is the shipped
    // document's, and injects the two probes that document decides: the
    // accepted port is forwarded and the denied one is dropped by a rule. It
    // then hands the node, over HTTP and with `curl`, a document that is the
    // shipped one with those two rules' ACTIONS SWAPPED and nothing else
    // changed — reads the running document back, holds the answer to naming the
    // generation it assigned, submits a malformed document and holds *that* to
    // being refused with a reason and moving nothing, waits for the forwarding
    // domain to report the committed generation, and only then injects the same
    // two ports again. Both verdicts must have reversed.
    //
    // Both directions, and that is the point: a document that only tightened
    // the policy would leave "the new rules are in force" and "the dataplane
    // has stopped" looking alike. Here the traffic the shipped policy dropped
    // is FORWARDED after the commit, so the dataplane is demonstrably still
    // deciding — and the forwarded totals it publishes rise across the swap
    // rather than resetting, which is what says no domain restarted under it.
    //
    // A `Client` scenario necessarily: the document is submitted with a real
    // client through QEMU's own user-mode stack, and the generation the
    // dataplane switched to is a metric.
    Scenario {
        name: "configuration-submission",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Reconfiguration,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The landing that closed the model's one real hole, and the only scenario
    // that states what a policy commit did to the conversations the appliance
    // was ALREADY CARRYING. Every other scenario that submits a document opens
    // its second wave's conversations afresh, because before this there was no
    // way for a commit to reach one that was already running.
    //
    // It boots the published disk and opens two conversations under the shipped
    // policy that differ in their source port and in nothing else, answering
    // both so each is a flow the tracker has seen in both directions. It then
    // submits a document that is the shipped one with its accept rule narrowed
    // by ONE ATTRIBUTE — a `source-port` — waits for the forwarding domain to
    // report the generation, and works the pass that commit armed off to
    // completion. Only then does it inject each conversation's next packet, on
    // the five-tuple it has been using all along.
    //
    // FOUR THINGS THEN HAVE TO HOLD TOGETHER, and no three of them are enough.
    // The occupancy gauge must fall and the revocation must be counted, so a
    // conversation really was ended. The doomed conversation's next packet must
    // NOT cross — which under the previous behaviour it would have, a tracked
    // flow being forwarded before the filter is consulted at all. The surviving
    // conversation's next packet MUST cross, and no rule of either document is
    // about the direction it travels in, so only its flow can be carrying
    // it — which is what separates re-deciding the table from flushing it, a
    // flush satisfying every other clause here. And that crossing is also the
    // dataplane demonstrably still forwarding across the commit.
    //
    // A `Client` scenario necessarily: the document goes over HTTP with a real
    // client, and three of the four statements are metrics.
    Scenario {
        name: "policy-revocation",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Revocation,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The scenario that proves an ICMP error the tracker RELATES to a live
    // conversation is still the filter's to decide — which is what keeps
    // recognising related traffic from being a way past the policy.
    //
    // It boots the published disk and opens a conversation under the shipped
    // policy, then injects an error from the far side quoting one of that
    // conversation's datagrams. The quote is built to satisfy every agreement
    // `lfw_flow::icmp` corroborates one by, so the frame really is related and
    // is not merely refused as unreadable — and the shipped policy, whose rules
    // are both about UDP, has no rule about it, so it falls to the default deny.
    // A document adding one `tracking="related"` rule is then submitted, and the
    // same error on the same flow crosses.
    //
    // BOTH HALVES ARE THE EXPERIMENT and neither alone is. A denial on its own
    // would leave "the policy refused it" and "the tracker never related it"
    // looking alike; an admission on its own would say nothing about the
    // default. And the denial is what the connection history carries: an error
    // opens no conversation, so a filter decision on it names no lifecycle event
    // unless the record says which policy outcome it was.
    //
    // A `Client` scenario necessarily: the document goes over HTTP with a real
    // client, and the classification is a metric.
    Scenario {
        name: "related-icmp",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Related,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "connection-lifecycle",
        document: LIFECYCLE_DOCUMENT,
        image: ImageUnderTest::BuiltForTheScenario,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Lifecycle,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The one scenario that puts a **flood** across the appliance, and the only
    // one whose contract is about how much state a burst of traffic can make
    // the node hold. The threat model carries a connection-flood adversary
    // separately from untrusted traffic for exactly this reason: its every
    // frame is well formed and its weapon is the per-connection state each one
    // commits.
    //
    // It opens one conversation the shipped policy admits and, alongside it
    // from the first injection pass, sixty-four distinct five-tuples addressed
    // to a port no rule is about. Each of those opens a flow and is then
    // refused by the default deny, so the appliance gives every slot back in
    // the evaluation that refused it — which is the property that keeps
    // default deny from being a state-exhaustion amplifier.
    //
    // The conversation's reply is deferred past the burst, so **its delivery is
    // a packet the table carried after the table had absorbed the flood**, and
    // no rule of the document names the port it is addressed to: only its flow
    // could have carried it. Beside it the exposition states the arithmetic —
    // the openings, what gave each slot back, and an occupancy that is a small
    // fraction of the burst rather than a multiple of it.
    //
    // Its own boot rather than an extension of `stateful-tracking`, which
    // already opens a conversation: the flood moves the occupancy, lifecycle
    // and refusal counters that scenario asserts a quiet table's values for, so
    // merging the two would make either one's failure unattributable — and it
    // would put the burst's frames into two scenarios' recordings, which are
    // judged block by block.
    //
    // A `Client` scenario, because the whole of the bounded-state claim is
    // arithmetic in the exposition: on the wire a flood leaves nothing but
    // sixty-four absences.
    Scenario {
        name: "connection-flood",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::Ignored,
        management: ManagementRole::Client,
        traffic: Traffic::Flood,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The only scenario that boots a node onto **generation 0** — the fail-closed
    // empty configuration — and the only one whose contract is that the appliance
    // forwards nothing at all.
    //
    // Every other scenario boots a document the fast gate has already proved
    // `config::load` accepts, so no other one can reach this state: a node that
    // committed a document is a node with a table. This one boots the document that
    // list registers as one the appliance REFUSES, and the registration is what
    // makes that a declared expectation rather than a bypass — a document that
    // quietly became valid fails the fast gate for saying so, long before this
    // boot.
    //
    // Its evidence is the two things such a node has, and no others. Its management
    // port takes its addressing from the *committed* configuration and is therefore
    // unaddressed, so nothing can scrape it, download from it, or ask it anything:
    // what is left is the **serial console** and the **absence of any forwarded
    // frame**. Both are held inside the boot contract
    // ([`crate::forward_harness::BootContract::FailedClosed`]), which is also what
    // decides when the run may stop — such a node runs indefinitely and never
    // exits, so nothing else would end the boot.
    //
    // The probes it injects are the shipped document's own, between the same
    // endpoints and over the same ports, because this document's addressing is the
    // shipped one to the byte. That is what makes their absence attributable: the
    // identical traffic crosses on eleven other scenarios, and here nothing does —
    // not for want of a route or an interface.
    //
    // WHAT THIS BOOT NO LONGER ISOLATES, stated because it is a real narrowing
    // rather than a wording change. This node is in two fail-closed states at
    // once: nobody has onboarded it, and it committed no generation. The
    // ownership refusal is reached first, so the empty table is no longer what
    // stops these frames — it would stop them, and this boot does not show it.
    // What the boot still holds exactly is the claim its name is about and its
    // console carries: the appliance REFUSED THE DOCUMENT ITS OWN IMAGE CARRIES,
    // reported `config state=refused`, came up on generation 0 and committed
    // nothing above it. Booting it owned would isolate the empty table again and
    // would cost the run its only node that is fail-closed on both counts, which
    // is the state a factory-fresh appliance is actually in.
    Scenario {
        name: "fail-closed-boot",
        document: image::DUPLICATE_RULE_ID_DOCUMENT,
        image: ImageUnderTest::BuiltForTheScenario,
        console: Console::JudgedOnARefusal,
        management: ManagementRole::Station,
        // The shipped six, judged as absences by this boot's own contract rather
        // than by the probe set: `BootContract::FailedClosed` is what decides how
        // an absence reads here, and it names both reasons this node has.
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        // Fresh, so this is the whole fail-closed picture: an appliance out of the
        // box has no owner and no committed configuration, and it must carry
        // nothing under either.
        store: StoreMedium::Fresh,
    },
    // The only scenario that chooses its accelerator, and the only one whose
    // subject is the accelerator rather than the appliance.
    //
    // Everything else here runs on whatever the machine offers, which on every
    // machine that runs this gate is KVM — so the emulator was exercised only on
    // a machine that had no choice, and "runs accelerated, faults emulated" was a
    // class of defect the gate could not see. It has already cost one: a
    // VEX-encoded instruction the compiler emitted into the cryptography domain,
    // which real hardware executes and an emulator refuses while the kernel's
    // saved state excludes the vector state. A build-time check now refuses that
    // encoding outright ([`crate::crypto_profile::check_image`]), which makes
    // that particular cause impossible; this boot is the defence behind it, and
    // it holds for the next cause nobody has thought of.
    //
    // It reuses the shipped document and the published disk — the same artifact
    // `generation-swap` boots — so the whole cost is one boot and neither a
    // second document nor a second image build.
    //
    // And it judges the cryptography domain alone. That is not thrift: the
    // routed contract, the transcript and the management count are facts about
    // the image, the accelerated boots state all three, and a second verdict on
    // them would be a second reading of the same fact at the price of the slower
    // machine. The cryptography domain is the one that can only be settled here,
    // being where the acceleration lives.
    Scenario {
        name: "cryptography-under-emulation",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnCryptographyAlone,
        // Socket-backed, because a real client is what a scrape needs and this
        // boot takes none: the endpoint's surfaces are the `Client` scenarios'
        // subject, on the accelerator they already ran.
        management: ManagementRole::Station,
        // The shipped probe set, injected and left unjudged. It keeps this boot
        // the same shape as the one it repeats rather than an idle guest, and no
        // delivery is required of it.
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::Emulated,
        store: StoreMedium::Fresh,
    },
    // The two boots that are one scenario, and the only pair in this table whose
    // contract neither of them can meet alone.
    //
    // An identity that did not survive a reboot is not an identity, so the claim
    // is not about a boot at all — it is about a *medium*, read twice. The first
    // boot finds it zeroed and mints: a 128-bit name, a P-256 keypair, a
    // self-signed onboarding certificate binding the two, and the fingerprint an
    // administrator authenticates the node by, all written durably behind a device
    // barrier. The second boot attaches the same file and must report the same
    // name and the same fingerprint under a generation that did not go backwards.
    //
    // A store domain that minted afresh on every boot satisfies every assertion
    // the first boot makes, and it is the whole defect a persistent identity
    // exists to prevent. Only the second boot sees it, and only because the medium
    // outlived the first — which is why `StoreMedium` is a field on this table
    // rather than a fresh file per invocation like the recorder's disk.
    //
    // Both judge the store domain alone, on the emulated boot's terms: the routed
    // contract, the transcript and the management port's count are facts about the
    // image that fifteen other boots state, and re-stating them here would pay two
    // whole boots for a second verdict on the same fact. They reuse the shipped
    // document and the published disk, so the whole cost is two boots and no
    // second image build.
    Scenario {
        name: "store-identity-minted",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheStoredIdentityAlone,
        // Socket-backed: this boot takes no client, the endpoint's surfaces being
        // the `Client` scenarios' subject.
        management: ManagementRole::Station,
        // The shipped probe set, injected and left unjudged, so the boot keeps the
        // shape of the ones it repeats rather than being an idle guest.
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::Fresh,
    },
    Scenario {
        name: "store-identity-reloaded",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheStoredIdentityAlone,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        // The medium the boot above minted on. It must precede this one in this
        // table, and `StoreDisk::carried` says so by name when it does not.
        store: StoreMedium::CarriedFrom("store-identity-minted"),
    },
    // And the third boot of that one medium: the only ownership transfer the
    // appliance has.
    //
    // The harness writes the request onto one sector between the boots, which is
    // the whole mechanism — a reset revokes a management plane's ownership, so
    // nothing a running node could hear may invoke it, and what is left is
    // possession of the medium. The appliance must then come back a *different*
    // appliance: a different name, a different key, unowned, at the generation a
    // mint starts from, having said on the console what it destroyed.
    //
    // Two halves, and neither is the other. The console says the identity changed;
    // it cannot say the old key left the medium, because a re-mint rewrites the
    // record whatever happened to the sectors around it. So the scalar is captured
    // off the medium before this boot and required to occur nowhere on it after —
    // a needle scan over every byte of the file, which is the only shape that
    // proof has.
    Scenario {
        name: "store-identity-reset",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheStoredIdentityAlone,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        // The medium the two boots above ran on, which by here carries an
        // identity that has already been shown to survive a reboot — so what this
        // boot takes away is an identity rather than a first mint nothing depended
        // on.
        store: StoreMedium::ResetRequestedOn("store-identity-minted"),
    },
    // The four boots whose subject is a management station that MISBEHAVES, and
    // the only ones in this table where the appliance's own channel is required
    // to fail.
    //
    // Every other boot answers that dial correctly, so what the gate held was
    // that a channel comes up when the far end is well behaved. That leaves the
    // interesting half unstated: an appliance dialling out of the port that faces
    // the management-plane attacker meets a station that says nothing, one that
    // refuses, one that lies about what it received, and a link that answers for
    // somebody else — and each of those has exactly one right outcome.
    //
    // TWO THINGS HOLD ON EACH, and the second matters more than the first. The
    // appliance reports the typed outcome for what happened, after the number of
    // sessions its own bound allows. And THE NODE STAYS HEALTHY: its routed
    // contract is met in the same boot, so the dataplane went on forwarding
    // throughout; its management port reports every frame the harness put on that
    // wire to the byte, so the domain that owns the failing channel neither
    // faulted nor lost its place; and no bound of either end is exceeded — the
    // station counts the resolutions, the SYNs and the resets it sees against the
    // arithmetic of the appliance's own constants and calls a node that exceeds
    // them broken.
    //
    // One boot per misbehaviour rather than phases inside one. The boots are the
    // gate's unit of evidence, a station that changed its mind mid-run would leave
    // a reader deciding which half of a capture a frame belonged to, and a failure
    // in one of the four would be unattributable.
    //
    // Socket-backed necessarily: the whole of the evidence is frames the harness
    // composes and judges field by field, and QEMU's user-mode stack would answer
    // the dial itself.
    Scenario {
        name: "dial-unanswered",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheDialledChannelAndThePortsCount,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Misbehaves(DialMisbehaviour::SilentToTheDial),
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "dial-reset",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheDialledChannelAndThePortsCount,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Misbehaves(DialMisbehaviour::ResetsTheDial),
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    Scenario {
        name: "dial-misacknowledged",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheDialledChannelAndThePortsCount,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Misbehaves(DialMisbehaviour::AcknowledgesTheWrongSequence),
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // And the one where nothing reaches a connection at all: the station answers
    // every resolution for an address nobody asked about, so nothing is learned
    // from it and no `SYN` ever crosses — the station holds both — and each of
    // the three sessions ends on the link rather than on this node. It is the
    // boot that holds the token to the fact it names: three attempts against an
    // unresolvable next hop must all read `next-hop-unreachable`, which they do
    // only because ending a session gives its connection back and leaves the
    // next dial a table the one before it did not touch.
    Scenario {
        name: "dial-unresolvable",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheDialledChannelAndThePortsCount,
        management: ManagementRole::Station,
        traffic: Traffic::Routed,
        dial: DialContract::Misbehaves(DialMisbehaviour::AnswersForAnotherAddress),
        onboard: OnboardContract::Untouched,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::CopiedFrom("onboarding-adopted"),
    },
    // The three boots whose subject is the appliance's ONBOARDING PORT — the
    // second port its management endpoint listens on, which carries a byte
    // stream rather than a request and a response, and which no booted image had
    // ever been held to. What held it until now was the host suite and three
    // fuzz harnesses: everything above the wire, and nothing across it.
    //
    // The port is the one an administrator reaches an appliance that has never
    // met them on, so its peer is the unauthenticated management-plane attacker
    // by definition. What a session on it costs the node is a second protection
    // domain driven over a relay by that peer's bytes, at that peer's pace —
    // which is why the health half below is stated on all three.
    //
    // THREE THINGS HOLD ON EACH. The two domains that carried the session agree
    // about it, field by field, and agree with what this harness put on the
    // wire; the port's own totals place what the accounts state; and THE NODE
    // STAYS HEALTHY — its routed contract is met in the same boot, so the
    // dataplane forwarded throughout, and its management port reports every
    // frame the harness put on that wire to the byte, so the domain carrying the
    // session neither faulted nor lost its place.
    //
    // One boot per ending rather than three sessions inside one, on the dial
    // boots' terms: the port holds one connection, a station that changed its
    // mind mid-run would leave a reader deciding which session a record belonged
    // to, and a failure in one of the three would be unattributable.
    //
    // Socket-backed necessarily, and more strictly than the dial boots are. Two
    // of the three are decided by something no host TCP client can express: a
    // reset at an instant this end chooses, and a second SYN whose whole subject
    // is that nothing comes back to it. QEMU's user-mode stack would terminate
    // both and answer for the appliance.
    Scenario {
        name: "onboarding-session",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheOnboardingSessionAndThePortsCount,
        management: ManagementRole::Station,
        traffic: Traffic::Unowned,
        dial: DialContract::Answered,
        onboard: OnboardContract::Session(OnboardBehaviour::Completes),
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::Fresh,
    },
    // The same session up to the acknowledgement of its payload, ended by a
    // reset rather than a close. Neither end of the session said it was over, so
    // what both domains must report is a connection the transport stopped
    // holding — which the far end could not tell from a peer hanging up until
    // the close it is sent began carrying the ending, and which the port's own
    // `forgotten` count is the second, independent statement of.
    Scenario {
        name: "onboarding-abandoned",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheOnboardingSessionAndThePortsCount,
        management: ManagementRole::Station,
        traffic: Traffic::Unowned,
        dial: DialContract::Answered,
        onboard: OnboardContract::Session(OnboardBehaviour::Abandons),
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::Fresh,
    },
    // And the one whose subject is a SECOND connection while the first is
    // established. The port holds one and an established connection is not
    // evictable, so the second SYN finds no slot and nothing to take one from.
    // What the appliance owes it is NOTHING AT ALL — not a handshake and not a
    // refusal — so the claim is an absence the station holds on the wire, beside
    // a port that accepted one connection rather than two and a boot carrying
    // one session record rather than two.
    Scenario {
        name: "onboarding-crowded",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheOnboardingSessionAndThePortsCount,
        management: ManagementRole::Station,
        traffic: Traffic::Unowned,
        dial: DialContract::Answered,
        onboard: OnboardContract::Session(OnboardBehaviour::Crowds),
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::Fresh,
    },
    // And the boot whose subject is the TLS server behind that port, driven by
    // clients nothing in this repository wrote.
    //
    // The three above are stations: they decide how a session *ends* and prove
    // that both domains account for it. None of them speaks the protocol, and
    // until this one no booted image had ever completed a handshake with
    // anybody. What the host suite proves is that this appliance's server and
    // this appliance's client agree, which is two halves of one stack agreeing;
    // what only a real client can settle is interoperation.
    //
    // FOUR CLIENTS OVER ONE BOOT, and the order is part of the claim: the
    // handshake that completes goes first, so the three failures after it are
    // sessions on a port that has already carried one. Each failure is a
    // different cause, and each must reach the console under its own token —
    // which is the whole reason the outcome vocabulary has ten members rather
    // than one. A boot that answered every failure with one token would satisfy
    // a contract that only asked whether the handshake failed.
    //
    // It is a client-backed boot like the metrics ones and takes their
    // contracts with it rather than opting out: the request surface is pulled
    // and judged in the same boot, which is what says the node stayed healthy
    // while an unauthenticated peer drove a second protection domain four times
    // over.
    Scenario {
        name: "onboarding-tls",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheOnboardingHandshakes,
        management: ManagementRole::Client,
        traffic: Traffic::Unowned,
        dial: DialContract::Answered,
        onboard: OnboardContract::Handshakes,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::Fresh,
    },
    // And the boot whose subject is the SURFACE above that handshake: what an
    // administrator actually does once their client has connected.
    //
    // The one above proves the record layer interoperates. This proves the two
    // things that layer exists to carry — the page an administrator reads the
    // fingerprint off, and the certificate signing request they take to the
    // management application — and it proves them the way an administrator
    // would: every request is pinned to the digest the STORE domain printed on
    // this same boot, so a page that carried one fingerprint and a certificate
    // that carried another would fail before a byte of the body was read.
    //
    // The request is then read back by `openssl req`, which shares no code with
    // this appliance and is the same family of tool the management server
    // parses with. A request this appliance emits that `openssl` will not read
    // is a request the management server will not sign.
    //
    // THREE OF THE FIVE MUST BE REFUSED, each under a token of its own: an
    // address that does not exist, the configuration upload asked for with no
    // package behind it, and the page under a method it is not served with. A
    // boot that answered all three the same way would satisfy a contract that
    // only asked whether a bad request was refused. Note that the second is now
    // a *served* route refusing an empty upload rather than an address that does
    // not exist, which is what keeps the three tokens three.
    Scenario {
        name: "onboarding-requests",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheOnboardingRequests,
        management: ManagementRole::Client,
        traffic: Traffic::Unowned,
        dial: DialContract::Answered,
        onboard: OnboardContract::Requests,
        accelerator: Accelerator::WhateverTheMachineOffers,
        store: StoreMedium::Fresh,
    },
    // And the pair that puts the whole of onboarding on a booted image: the
    // harness stops reading what the appliance serves and starts being the
    // thing an administrator carries it to.
    //
    // The first boot is the management server. It fetches the request, reads it
    // back with `openssl`, issues a device certificate against a certification
    // authority generated for this checkout alone, composes a package to the
    // package contract, and uploads it as the body of `POST /configuration.tar`
    // over the same pinned TLS every other client on this port uses. What it
    // holds the appliance to is not that the upload succeeded: it is that the
    // appliance printed **this authority's own fingerprint**, computed here by
    // the profile's definition before the appliance said it, and the endpoint
    // the package named — so a node that installed some other anchor, or none,
    // fails on a number rather than on a status line.
    //
    // TWO PACKAGES ARE REFUSED FIRST, each under a token of its own, because
    // an install shuts the surface and so is the last thing this boot can do.
    // One is well formed and certified to a **different appliance's key** — the
    // fixture the management server itself produced, which needs nothing
    // composed — and one is this appliance's own package in an archive that is
    // not ustar. They are two different things for an administrator to go and
    // fix, and an appliance that answered both the same way would satisfy a
    // contract that only asked whether a bad package was refused.
    //
    // The second boot is what makes the close *permanent* rather than
    // per-boot. It carries the same medium into a second boot and finds the
    // appliance owned: the same identifier and the same key, at a generation
    // the install advanced, with every address the surface once had — the page,
    // the request, and the route that took the package, offered the very
    // package that was accepted — answering that this appliance already has an
    // owner. A close that a restart undid satisfies everything the first boot
    // asserts and nothing here.
    Scenario {
        name: "onboarding-owned",
        document: image::CONFIGURATION_DOCUMENT,
        image: ImageUnderTest::Published,
        console: Console::JudgedOnTheOwnedApplianceServingNothing,
        management: ManagementRole::Client,
        traffic: Traffic::Routed,
        dial: DialContract::Answered,
        onboard: OnboardContract::Owned,
        accelerator: Accelerator::WhateverTheMachineOffers,
        // The medium the boot above was adopted on. It must precede this one in
        // this table, and `StoreDisk::carried` says so by name when it does not.
        store: StoreMedium::CarriedFrom("onboarding-adopted"),
    },
];

/// What one boot was observed to do, beyond meeting its contract.
struct Observed {
    /// The initial sequence number the appliance answered this boot's one
    /// management connection with, where it opened one.
    management_tcp_isn: Option<u32>,
    /// The identity the store domain reported, where the boot judged one.
    /// Reported back rather than re-read, because the claim the pair makes is
    /// between two boots and only the run has seen both.
    store_identity: Option<store_contract::Identity>,
    /// Whether QEMU executed this boot on the host's own processor. Reported
    /// back rather than re-derived, because the run's summary states a *contrast*
    /// between the accelerators and a contrast asserted from a second probe of
    /// the KVM device would be a claim about the device rather than about the
    /// boots that ran.
    accelerated: bool,
}

/// Boot every scenario in `scenarios` and answer what the run proved.
fn run_scenarios(root: &Path, scenarios: &[Scenario]) -> Result<String, String> {
    check_media_order(scenarios)?;
    let judged = scenarios
        .iter()
        .filter(|scenario| matches!(scenario.console, Console::Judged))
        .count();
    let scraped = scenarios
        .iter()
        .filter(|scenario| scenario.management.user_network())
        .count();

    // What each boot chose for its one management connection, kept so the
    // *unpredictability* of it can be judged across boots. RFC 6528 makes that a
    // security property and no single boot can show it: a constant initial
    // sequence number is an off-path injection primitive against exactly the
    // adversary this port faces, and it looks perfectly correct in one
    // scenario.
    let mut sequence_numbers: Vec<(&str, u32)> = Vec::new();
    // Which accelerator each boot actually got, which is what the run may claim
    // about them and nothing more.
    let mut accelerated: Vec<(&str, bool)> = Vec::new();
    // The identity each boot that judged one reported. Kept for the same reason
    // the sequence numbers are: no single boot can show that an identity SURVIVED
    // a reboot, and a domain that minted afresh on every boot looks perfectly
    // correct in one scenario.
    let mut identities: Vec<(&str, store_contract::Identity)> = Vec::new();
    for scenario in scenarios {
        // What this boot's medium says about ownership, decided before the boot
        // rather than read out of it: every forwarding contract below rests on
        // it, so a run that derived it from the appliance's own answer could not
        // catch the appliance being wrong.
        let owner = ownership_at_boot(scenarios, scenario)?;
        match run_scenario(root, scenario, Run::Shipping, owner) {
            Ok(observed) => {
                if let Some(isn) = observed.management_tcp_isn {
                    sequence_numbers.push((scenario.name, isn));
                }
                if let Some(identity) = observed.store_identity {
                    identities.push((scenario.name, identity));
                }
                accelerated.push((scenario.name, observed.accelerated));
            }
            Err(verdict) => {
                return Err(diagnose::after_shipping_failure(
                    &format!("system scenario {}", scenario.name),
                    verdict,
                    &scenario_log(root, scenario, Run::Shipping),
                    &scenario_log(root, scenario, Run::Diagnostic),
                    || run_scenario(root, scenario, Run::Diagnostic, owner).map(|_| ()),
                ));
            }
        }
    }
    let distinct = judge_sequence_numbers(&sequence_numbers)?;
    let carried = judge_carried_media(scenarios, &identities)?;
    Ok(format!(
        "{} system scenarios on the {} kernel, {judged} of them judged against the \
         configuration transcript, the clock record, the hardware probe's record and the \
         management port's count, and \
         {scraped} scraped with curl against the document each was built from; {distinct}{carried}{}",
        scenarios.len(),
        Run::Shipping.config(),
        describe_the_emulated_boots(scenarios, &accelerated),
    ))
}

/// How many scenarios boot their own copy of a medium some earlier boot was
/// onboarded on.
///
/// Read as data by [`crate::reference_contract`] rather than restated in prose,
/// because it is the premise the forwarding half of most of this table rests on:
/// a scenario moved off a copied medium changes what the gate proves, and a
/// sentence saying otherwise would go on reading correctly.
pub(crate) fn copied_medium_scenario_count() -> usize {
    SCENARIOS
        .iter()
        .filter(|scenario| matches!(scenario.store, StoreMedium::CopiedFrom(_)))
        .count()
}

/// Whether the appliance a scenario boots **already has an owner** when it
/// starts, derived from the medium it attaches rather than stated beside it.
///
/// Derived, because a field saying so would be a second statement of the same
/// fact and the two would drift: a scenario switched from a fresh medium to a
/// copied one would keep claiming what it no longer boots, and the claim is what
/// every forwarding contract in this table rests on. Walking the chain instead
/// means the table can only say one thing.
///
/// The chain has three ends. A fresh medium is an appliance that mints itself and
/// so has no owner. A reset request is the one act that gives an owner up, and it
/// takes effect on the boot that finds it — this one. Otherwise the answer is the
/// source's, upgraded to owned where that source is the boot an install adopted:
/// what a medium carries out of a boot is what the boot left on it.
///
/// # Errors
/// A source no scenario in this table declares, and a source chain that returns
/// to a scenario it already visited.
fn ownership_at_boot(scenarios: &[Scenario], scenario: &Scenario) -> Result<Ownership, String> {
    let mut at = scenario;
    // Bounded by the table's own length, and by a value no scenario controls: a
    // chain longer than the number of scenarios has visited one of them twice,
    // which is a cycle. Unbounded, that is an xtask that never returns.
    for _ in 0..=scenarios.len() {
        let source = match at.store {
            StoreMedium::Fresh | StoreMedium::ResetRequestedOn(_) => {
                return Ok(Ownership::Unowned);
            }
            StoreMedium::CarriedFrom(source) | StoreMedium::CopiedFrom(source) => source,
        };
        let Some(found) = scenarios.iter().find(|other| other.name == source) else {
            return Err(format!(
                "system scenario {} takes the store medium the {source} boot left and this table \
                 declares no scenario by that name, so the medium it boots is decided by whatever \
                 file an earlier run happened to leave",
                at.name
            ));
        };
        // An install is the only thing that gives an appliance an owner, so a
        // source that ran one leaves an owned medium whatever it started from.
        if found.onboard.onboards() {
            return Ok(Ownership::Owned);
        }
        at = found;
    }
    Err(format!(
        "the store media the scenario table declares form a cycle reachable from {}, so no boot \
         in it has a medium whose contents any scenario decides",
        scenario.name
    ))
}

/// Hold the scenario table's store media to being **declared before they are
/// used**, before a single boot runs.
///
/// The disks themselves say this too — a source file that is not there names the
/// boot that was to leave it — but they say it one boot in, after an image build
/// and everything the table put ahead of the offender. Saying it here costs a
/// walk of a fixed list and turns a table edit that reordered a pair into a
/// verdict a reader gets immediately.
///
/// # Errors
/// A source declared after the boot that takes its medium, or not at all.
fn check_media_order(scenarios: &[Scenario]) -> Result<(), String> {
    for (at, scenario) in scenarios.iter().enumerate() {
        let (source, how) = match scenario.store {
            StoreMedium::Fresh => continue,
            StoreMedium::CarriedFrom(source) => (source, "carries"),
            StoreMedium::CopiedFrom(source) => (source, "copies"),
            StoreMedium::ResetRequestedOn(source) => (source, "requests a factory reset on"),
        };
        let found = scenarios
            .iter()
            .position(|other| other.name == source)
            .ok_or_else(|| {
                format!(
                    "system scenario {} {how} the store medium the {source} boot leaves, and this \
                     table declares no scenario by that name",
                    scenario.name
                )
            })?;
        if found >= at {
            return Err(format!(
                "system scenario {} {how} the store medium the {source} boot leaves, and {source} \
                 is declared at position {} of this table against its own {}. The medium has to \
                 exist before a boot can take it, so the source must come first",
                scenario.name,
                found + 1,
                at + 1
            ));
        }
    }
    Ok(())
}

/// Hold every boot that reloaded a medium to the boot that minted the identity on
/// it.
///
/// This is the half of the store contract no boot makes: the medium outlives one
/// invocation deliberately, and only the run has seen both readings of it. A
/// scenario naming a source whose identity the run does not hold is a finding
/// rather than a skip — either the two are out of order in the table, or the
/// source boot judged no identity, and both would leave the claim vacuously true.
fn judge_carried_media(
    scenarios: &[Scenario],
    identities: &[(&str, store_contract::Identity)],
) -> Result<String, String> {
    let held = |name: &str| {
        identities
            .iter()
            .find(|(observed, _)| *observed == name)
            .map(|(_, identity)| identity)
    };
    let mut proved = Vec::new();
    for scenario in scenarios {
        let (source, reset) = match scenario.store {
            // A copy makes no claim about the medium: the boot that took it is
            // not stating that an identity survived anything, it is stating that
            // an appliance somebody owns forwards. Holding a copy's identity to
            // its source's would read as a persistence proof and would be
            // satisfied by `std::fs::copy` rather than by the appliance. What
            // these boots are held to instead is the forwarding domain's own
            // ownership record, on every one of them.
            StoreMedium::Fresh | StoreMedium::CopiedFrom(_) => continue,
            StoreMedium::CarriedFrom(source) => (source, false),
            StoreMedium::ResetRequestedOn(source) => (source, true),
        };
        let Some(minted) = held(source) else {
            return Err(format!(
                "system scenario {} inherits the store medium the {source} boot minted on, and \
                 this run holds no identity for {source}. Either the two are out of order in the \
                 scenario table — the minting boot must precede the one that inherits it — or \
                 {source} does not judge the store domain at all, and either way the claim this \
                 pair makes about that medium would be vacuously true",
                scenario.name
            ));
        };
        let Some(returned) = held(scenario.name) else {
            return Err(format!(
                "system scenario {} inherits a store medium and judged no identity of its own, so \
                 there is nothing to hold to the {source} boot's",
                scenario.name
            ));
        };
        let pair = (source, minted);
        let mine = (scenario.name, returned);
        proved.push(if reset {
            store_contract::hold_reset_to_source(pair, mine)?
        } else {
            store_contract::hold_to_source(pair, mine)?
        });
    }
    if proved.is_empty() {
        return Ok(String::new());
    }
    Ok(format!("; {}", proved.join("; ")))
}

/// What the run may say about the accelerators it used, from what the boots
/// actually got.
///
/// The clause exists because the emulated boot's whole value is a *contrast* —
/// the shipped image proved on the emulator while the rest of the run proved it
/// on a processor — and on a machine with no usable KVM there is no contrast to
/// report: every boot was emulated, so the forced one repeated under emulation
/// what all of them had already done there. Saying so is the point. A fixed
/// sentence claiming the contrast would be false on exactly the machine where the
/// claim matters least and would be believed anyway, which is how a run comes to
/// assert a property of its runner as a property of the image.
fn describe_the_emulated_boots(scenarios: &[Scenario], accelerated: &[(&str, bool)]) -> String {
    let forced: Vec<&str> = scenarios
        .iter()
        .filter(|scenario| scenario.accelerator == Accelerator::Emulated)
        .map(|scenario| scenario.name)
        .collect();
    if forced.is_empty() {
        return String::new();
    }
    let named = forced.join(", ");
    let others = accelerated
        .iter()
        .filter(|(name, was)| *was && !forced.contains(name))
        .count();
    if others == 0 {
        return format!(
            "; {named} asked for emulation on a machine that accelerated no boot of this run, so \
             it drew no contrast: every scenario ran on the emulator, and the cryptography domain \
             is proved there and nowhere else"
        );
    }
    format!(
        "; {named} ran on the emulator whatever the machine offered, proving the shipped image's \
         published cryptographic vectors and its mutually-authenticated session there, against \
         {others} boot(s) of the same image that ran on the processor"
    )
}

/// Hold the initial sequence numbers the boots chose to being *pairwise*
/// different.
///
/// The scenarios that open a connection boot the same disk, so nothing but the
/// per-boot `RDRAND` secret and the time component separates their numbers
/// (RFC 6528): two equal ones mean one of the two is missing, which is the whole
/// of what makes an initial sequence number unguessable. Every pair is compared
/// rather than every adjacent pair, because a repeat is a repeat wherever it
/// falls in the run order — comparing neighbours alone would pass a run in which
/// the first and last boots agreed. Every boot must have opened a connection,
/// too — a run that opened none proves nothing and must not read as a pass.
///
/// # Errors
/// The verdict, naming the numbers observed.
pub(crate) fn judge_sequence_numbers(observed: &[(&str, u32)]) -> Result<String, String> {
    if observed.is_empty() {
        return Err(String::from(
            "no scenario opened a TCP connection to the management port, so nothing was judged \
             about the sequence numbers the appliance chooses. Every routed scenario opens one, so \
             this means none of them reached the point where it could",
        ));
    }
    for (index, (first, earlier)) in observed.iter().enumerate() {
        for (second, later) in &observed[index + 1..] {
            if earlier == later {
                return Err(format!(
                    "scenarios {first} and {second} were both answered with initial sequence \
                     number {earlier}. Nothing but the per-boot RDRAND secret and a monotonic time \
                     component separates two boots of one disk (RFC 6528), so an equal pair means \
                     one of the two is not reaching the generator — and a predictable initial \
                     sequence number lets an off-path attacker inject into a connection it cannot \
                     see"
                ));
            }
        }
    }
    // The count of *values*, not of boots: the two are equal only because the
    // loop above has just proved they are, and reporting the boot count under
    // this wording is what let the claim outlive the comparison behind it.
    let distinct: BTreeSet<u32> = observed.iter().map(|&(_, isn)| isn).collect();
    Ok(format!(
        "{} distinct initial sequence numbers across the {} boot(s) that opened a connection",
        distinct.len(),
        observed.len()
    ))
}

/// Where one scenario's serial capture goes, per run. The two runs never share
/// a path, so a diagnostic re-run cannot overwrite the failing shipping run's
/// log — which is the evidence it was called to explain.
fn scenario_log(root: &Path, scenario: &Scenario, run: Run) -> PathBuf {
    root.join("build/image")
        .join(format!("qemu-{}{}.log", scenario.name, run.name_suffix()))
}

/// The disk a scenario boots.
///
/// A [`Run::Diagnostic`] re-run always assembles its own disk into the build
/// tree, `ImageUnderTest::Published` scenarios included. It may not call
/// [`image::image`]: that publishes into `dist/`, which holds the release
/// artifact the failing run was judging, and overwriting it with a debug disk
/// would destroy the thing under assessment.
/// The label one scenario's boot runs under: the stem of its run log, its OVMF
/// variable store, its data disk and its store medium.
///
/// One place, because a **carried** store medium is looked up by the label its
/// *source* boot filed it under — always that source's shipping label, so a
/// diagnostic re-run of the reloading scenario reads the same medium the shipping
/// run judged rather than a file no boot ever wrote.
fn scenario_run_label(name: &str, run: Run) -> String {
    format!("qemu-{name}{}", run.name_suffix())
}

fn scenario_disk(root: &Path, scenario: &Scenario, run: Run) -> Result<PathBuf, String> {
    let name = scenario.name;
    match (&scenario.image, run) {
        (ImageUnderTest::Published, Run::Shipping) => Ok(root.join("dist").join(DIST_DISK)),
        (ImageUnderTest::BuiltForTheScenario, Run::Shipping) => Ok(image::scenario_image(
            root,
            run.config(),
            Path::new(scenario.document),
            name,
        )?),
        (_, Run::Diagnostic) => Ok(image::scenario_image(
            root,
            run.config(),
            Path::new(scenario.document),
            &format!("{name}{}", run.name_suffix()),
        )?),
    }
}

fn run_scenario(
    root: &Path,
    scenario: &Scenario,
    run: Run,
    owner: Ownership,
) -> Result<Observed, String> {
    let name = scenario.name;
    let path = root.join(scenario.document);
    let document = fs::read(&path)
        .map_err(|error| format!("scenario {name}: read {}: {error}", path.display()))?;
    // The bench, read out of the document under the standing that document is
    // registered with — so a document a fail-closed scenario boots is one whose
    // refusal has been asserted rather than assumed, and a document every other
    // scenario boots is one `config::load` accepts whole.
    let standing = image::standing_of(Path::new(scenario.document))
        .map_err(|error| format!("scenario {name}: {error}"))?;
    let topology = Topology::from_document_with(&document, standing)
        .map_err(|error| format!("scenario {name}: {}: {error}", path.display()))?;

    let disk = scenario_disk(root, scenario, run)?;

    match scenario.console {
        Console::JudgedOnARefusal => {
            return run_fail_closed_scenario(
                root, scenario, run, &disk, &document, &topology, owner,
            );
        }
        Console::JudgedOnCryptographyAlone => {
            return run_cryptography_scenario(root, scenario, run, &disk, &topology, owner);
        }
        Console::JudgedOnTheStoredIdentityAlone => {
            return run_store_scenario(root, scenario, run, &disk, &topology, owner);
        }
        // The dial-misbehaviour and onboarding boots run the ordinary path:
        // their routed contract is half of what they prove, so they are boots of
        // the same shape as every other station-backed one and differ in what
        // the console is read for afterwards.
        Console::Ignored
        | Console::Judged
        | Console::JudgedOnTheDialledChannelAndThePortsCount
        | Console::JudgedOnTheOnboardingSessionAndThePortsCount
        | Console::JudgedOnTheOnboardingHandshakes
        | Console::JudgedOnTheOnboardingRequests
        | Console::JudgedOnTheOnboardingInstall
        | Console::JudgedOnTheOwnedApplianceServingNothing => {}
    }

    let log_name = format!("{}.log", scenario_run_label(name, run));
    let backing = if scenario.management.user_network() {
        // Both at once, because a reservation that released its socket before the
        // next one bound would let the host answer with the same port twice — and
        // QEMU refuses a duplicate forwarding rule by exiting.
        let [host_port, onboard_port] = forward_harness::reserve_host_ports::<2>()
            .map_err(|error| format!("scenario {name}: {error}"))?;
        ManagementBacking::UserNetwork {
            host_port,
            onboard_port,
        }
    } else {
        ManagementBacking::Socket
    };
    let booted = boot_and_forward(
        root,
        &disk,
        &log_name,
        &topology,
        ForwardBench {
            management: backing,
            traffic: scenario.traffic,
            dial: scenario.dial,
            onboard: scenario.onboard,
            store: scenario.store,
            owner,
        },
    )
    .map_err(|error| format!("scenario {name}: {error}"))?;

    // The table before the verdict: what the two endpoints exchanged and what
    // the appliance refused is the thing a smoke run is run to see, and the
    // verdict is only the count of it. For the alternate scenario it is also
    // where a reader sees the second document's addresses on the wire.
    print!("{}", booted.traffic.render());
    for answered in &booted.management_replies {
        println!("{answered}");
    }

    let log = scenario_log(root, scenario, run);
    // The scrape before the console, because it is the whole of what this
    // scenario proves and its evidence belongs where a reader looks first.
    let scraped = match &scenario.management {
        ManagementRole::Station => String::new(),
        ManagementRole::Client if booted.scrapes.is_empty() => {
            return Err(format!(
                "scenario {name}: the boot met its routed contract and no scrape was taken, so \
                 nothing was proved about the metrics endpoint\n  full run log: {}",
                log.display()
            ));
        }
        ManagementRole::Client => {
            let judged = metrics_contract::judge(
                &booted.scrapes,
                booted.dataplane_frames,
                booted.policy,
                &topology,
            )
            .map_err(|error| {
                format!(
                    "scenario {name}: {error}\n  full run log: {}",
                    log.display()
                )
            })?;
            let evidence = metrics_contract::evidence(&booted.scrapes, &judged);
            println!("{evidence}");
            append_evidence(
                &log,
                "the metrics scrape this boot was judged by",
                &evidence,
            )
            .map_err(|error| format!("scenario {name}: {error}"))?;
            if let Some(applied) = &booted.applied {
                // Ahead of the recordings, because it is the whole of what this
                // scenario proves and a reader looks for it first.
                let transcript = applied.render();
                println!("{transcript}");
                append_evidence(
                    &log,
                    "the configuration this boot submitted, and what the node said about it",
                    &transcript,
                )
                .map_err(|error| format!("scenario {name}: {error}"))?;
            }
            if let Some(revoked) = &booted.revoked {
                // Beside the submission it followed, because the two are one
                // statement: the document changed and these are the conversations
                // it ended.
                let transcript = revoked.render();
                println!("{transcript}");
                append_evidence(
                    &log,
                    "what that commit did to the conversations the node was already carrying",
                    &transcript,
                )
                .map_err(|error| format!("scenario {name}: {error}"))?;
            }
            let judged = judge_recordings(root, name, &booted, &topology, &log, owner)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            println!("{judged}");
            append_evidence(
                &log,
                "the two recordings this boot was judged by, and their agreement with the \
                 exposition and the wire",
                &judged,
            )
            .map_err(|error| format!("scenario {name}: {error}"))?;
            match &booted.applied {
                Some(applied) => format!(
                    "; {} scrapes and both recordings judged together; generation {} submitted \
                     over HTTP and in force on the dataplane{}",
                    booted.scrapes.len(),
                    applied.generation,
                    match &booted.revoked {
                        Some(revoked) => format!(
                            ", which took back {} of the {} conversations it was carrying",
                            revoked.revoked, revoked.assured_before
                        ),
                        None => String::new(),
                    }
                ),
                None => format!(
                    "; {} scrapes and both recordings judged together",
                    booted.scrapes.len()
                ),
            }
        }
    };
    // What the store domain said about itself, on the two boots whose subject
    // is an appliance changing hands. Held out here because the claim the pair
    // makes is between two boots and only the run has seen both.
    let mut identity = None;
    let judged = match scenario.console {
        // Unreachable for the two narrow ones: `run_scenario` hands a refusal
        // scenario to `run_fail_closed_scenario` and a cryptography-only one to
        // `run_cryptography_scenario` before reaching here. Neither could be
        // judged from here anyway — there is no transcript of an accepted
        // document on a node that accepted none, and this boot's contract is not
        // the one either of them owes.
        Console::Ignored
        | Console::JudgedOnARefusal
        | Console::JudgedOnCryptographyAlone
        | Console::JudgedOnTheStoredIdentityAlone => String::new(),
        Console::JudgedOnTheDialledChannelAndThePortsCount => {
            // The appliance's own account of the channel, held to the one
            // outcome this boot's station can produce.
            let dial = judge_dial(scenario, &booted, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // And the evidence that the node stayed healthy under it: every
            // frame the harness put on that wire, reported to the byte, over a
            // boot in which most of them were spent carrying a channel that
            // never came up.
            let management = management_contract::judge(&booted.serial, &log, booted.management)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!("; {dial}; {management}")
        }
        Console::JudgedOnTheOnboardingSessionAndThePortsCount => {
            // Both domains' account of the session, held to what the station on
            // this end of it did.
            let onboarded = judge_onboarding(scenario, &booted, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // And the evidence that the node stayed healthy while it carried
            // one: every frame the harness put on that wire, reported to the
            // byte, over a boot in which many of them were spent waking a domain
            // that has no timer of its own.
            let management = management_contract::judge(&booted.serial, &log, booted.management)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!("; {onboarded}; {management}")
        }
        Console::JudgedOnTheOnboardingRequests => {
            if booted.requests.is_empty() {
                return Err(format!(
                    "scenario {name}: the boot met its routed contract and ran no client against \
                     the onboarding surface, so nothing was proved about what it serves\n  \
                     full run log: {}",
                    log.display()
                ));
            }
            let evidence = onboard_request_contract::evidence(&booted.requests);
            println!("{evidence}");
            append_evidence(
                &log,
                "the requests this boot made on the onboarding surface, and what came back",
                &evidence,
            )
            .map_err(|error| format!("scenario {name}: {error}"))?;
            let served = onboard_request_contract::judge(&booted.requests, &booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!("; {served}")
        }
        Console::JudgedOnTheOnboardingInstall
        | Console::JudgedOnTheOwnedApplianceServingNothing => {
            let Some(installs) = &booted.installs else {
                return Err(format!(
                    "scenario {name}: the boot met its routed contract and this run's management \
                     server never reached the onboarding surface, so nothing was proved about \
                     what an appliance does when one arrives\n  full run log: {}",
                    log.display()
                ));
            };
            let evidence = onboard_install_contract::evidence(installs);
            println!("{evidence}");
            append_evidence(
                &log,
                "what this run's management server did to the appliance, and what came back",
                &evidence,
            )
            .map_err(|error| format!("scenario {name}: {error}"))?;
            // The store domain's own account first: it is what an install
            // changes, so the contract is between the two records and reading
            // one of them twice would be this harness agreeing with itself.
            let reported = store_contract::judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            let install =
                onboard_install_contract::judge(installs, &reported, &booted.serial, &log)
                    .map_err(|error| format!("scenario {name}: {error}"))?;
            let summary = reported.summary();
            identity = Some(reported);
            format!("; {install}; the store domain reports {summary}")
        }
        Console::JudgedOnTheOnboardingHandshakes => {
            if booted.handshakes.is_empty() {
                return Err(format!(
                    "scenario {name}: the boot met its routed contract and ran no client against \
                     the onboarding port, so nothing was proved about the server behind it\n  \
                     full run log: {}",
                    log.display()
                ));
            }
            // The clients' own transcripts first, for the reason every other
            // transcript here goes first: what a reader wants is what was said.
            let evidence = onboard_tls_contract::evidence(&booted.handshakes);
            println!("{evidence}");
            append_evidence(
                &log,
                "the clients this boot ran against the onboarding port, and what came back",
                &evidence,
            )
            .map_err(|error| format!("scenario {name}: {error}"))?;
            let handshakes = onboard_tls_contract::judge(&booted.handshakes, &booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!("; {handshakes}")
        }
        Console::Judged => {
            let contract = ConfigContract::from_document(&document)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            contract
                .judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // The other console channel, and the one record whose content the
            // build cannot predict: what the appliance measured about its own
            // hardware. Judged after the transcript because a node that refused
            // its configuration is the larger finding.
            let clock = clock_contract::judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // The other record whose content is a measurement: what the
            // hardware probe proved about the instruction sets the
            // cryptography plan is designed around.
            let probe = probe_contract::judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // And the records whose content is the milestone this whole
            // hardware profile exists for: every cryptographic primitive
            // answering its published vectors on this part, and costing little
            // enough that the accelerated backend must be the one running.
            let crypto = crypto_contract::judge(&booted.serial, &log, booted.hardware_accelerated)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // And the record whose content the build knows exactly: the frames
            // the harness put on the management wire, which the appliance must
            // report to the frame and to the byte.
            let management = management_contract::judge(&booted.serial, &log, booted.management)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // And the record whose content the build knows because it decided
            // how the station on the far end of the dial would behave — where
            // this boot's dial contract states one. A boot that answers the dial
            // and requires nothing of it has no outcome to hold the record to,
            // and reads none: its subject is the document rather than the
            // channel, and the appliance's own addressing decides what a channel
            // to a first-party constant does under a second document.
            let dial = match scenario.dial.verdict() {
                None => String::new(),
                Some(_) => format!(
                    "; {}",
                    judge_dial(scenario, &booted, &log)
                        .map_err(|error| format!("scenario {name}: {error}"))?
                ),
            };
            // Last, over every channel at once: the field the others do not
            // judge, on the records they do not name.
            let stamps = stamp_contract::judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!(
                "; {}; {clock}; {probe}; {crypto}; {management}{dial}; {stamps}",
                contract.summary()
            )
        }
    };
    // Whatever else this boot judged, it is held to the ownership its medium
    // carried — the precondition every forwarding verdict above rests on, and the
    // one an appliance states for itself on the only surface it always has.
    let owned = ownership_contract::judge(&booted.serial, owner, &log)
        .map_err(|error| format!("scenario {name}: {error}"))?;
    println!(
        "  system scenario ok: {name} on the {} kernel ({}; {owned}{judged}{scraped}); QEMU \
         output is in {}",
        run.config(),
        booted.traffic.summary(),
        log.display()
    );
    Ok(Observed {
        management_tcp_isn: booted.management_tcp_isn,
        store_identity: identity,
        accelerated: booted.hardware_accelerated,
    })
}

/// Hold the appliance's record of its dialled channel to what this scenario's
/// station did, where the scenario reads it.
///
/// A scenario whose dial contract states no verdict has nothing to judge, and
/// saying so is not the same as passing: the two arms that call this both choose
/// a contract that states one, so a `None` here is a table entry that pairs a
/// console variant with a dial nobody decided.
fn judge_dial(scenario: &Scenario, booted: &Booted, log: &Path) -> Result<String, String> {
    let Some(owed) = scenario.dial.verdict() else {
        return Err(String::from(
            "this scenario reads the appliance's record of its dialled channel and its dial \
             contract requires nothing of one, so there is no outcome to hold the record to",
        ));
    };
    dial_contract::judge(
        &booted.serial,
        log,
        owed,
        (
            forward_harness::DIAL_DESTINATION,
            forward_harness::DIAL_PORT,
        ),
        booted.dial_claim,
    )
}

/// Hold both domains' account of the onboarding session to what this scenario's
/// station did, where the scenario reads it.
///
/// [`judge_dial`]'s shape and its reasoning: a scenario whose onboarding
/// contract states no verdict has nothing to judge, and saying so is not the
/// same as passing. The station's own account is required for the same reason —
/// the bytes the console reports received are held to the bytes this end put on
/// the wire, and a boot that reported none observed nothing to compare against.
fn judge_onboarding(scenario: &Scenario, booted: &Booted, log: &Path) -> Result<String, String> {
    let Some(owed) = scenario.onboard.verdict() else {
        return Err(String::from(
            "this scenario reads the appliance's account of an onboarding session and its \
             onboarding contract opens none, so there is no session to hold the records to",
        ));
    };
    let Some(observed) = booted.onboard else {
        return Err(String::from(
            "this scenario opens an onboarding session and the boot reported no account of one, \
             so the bytes the console states received have nothing independent to be held to",
        ));
    };
    onboard_contract::judge(&booted.serial, log, owed, observed)
}

/// Boot one scenario on the **emulator** and judge the cryptography domain,
/// which is the whole of what it is for.
///
/// The shortest of the three, and every omission is deliberate rather than a
/// surface this node lacks — which is what separates it from its fail-closed
/// sibling. This node has every surface: it committed the shipped document, it
/// forwards, its management port answers. All of that is judged by the boots that
/// ran on the processor, and re-judging it here would pay a whole emulated boot
/// for a second reading of a fact about the image. What only this boot can settle
/// is whether the shipped cryptography executes on an emulated processor at all,
/// so the cryptography domain's records are read and nothing else is.
///
/// Its measured costs come back without a verdict, and that needs no arrangement
/// here: the judge asserts a ceiling only on a boot executing on real hardware,
/// because a cycle count taken while every instruction is a host function call is
/// a figure about the emulator. This boot reaches that path rather than avoiding
/// it.
///
/// Neither data-disk verdict is owed either, and for a reason worth stating: the
/// run ends the moment the cryptography domain finishes, which may be before the
/// recorder has proved its own path to the medium. A boot that asserted the
/// witness pattern here would be asserting a race.
///
/// Answers no sequence number: nothing opens a connection to the management port.
fn run_cryptography_scenario(
    root: &Path,
    scenario: &Scenario,
    run: Run,
    disk: &Path,
    topology: &Topology,
    owner: Ownership,
) -> Result<Observed, String> {
    let name = scenario.name;
    let log_name = format!("{}.log", scenario_run_label(name, run));
    let booted = boot(
        root,
        disk,
        &log_name,
        BootContract::Cryptography,
        topology,
        Bench {
            accelerator: scenario.accelerator,
            management: ManagementBacking::Socket,
            traffic: scenario.traffic,
            dial: scenario.dial,
            onboard: scenario.onboard,
            store: scenario.store,
            owner,
        },
    )
    .map_err(|error| format!("scenario {name}: {error}"))?;
    let log = scenario_log(root, scenario, run);
    let crypto = crypto_contract::judge(&booted.serial, &log, booted.hardware_accelerated)
        .map_err(|error| format!("scenario {name}: {error}"))?;
    let owned = ownership_contract::judge(&booted.serial, owner, &log)
        .map_err(|error| format!("scenario {name}: {error}"))?;
    println!(
        "  system scenario ok: {name} on the {} kernel ({crypto}; {owned}); QEMU output is in {}",
        run.config(),
        log.display()
    );
    Ok(Observed {
        management_tcp_isn: None,
        store_identity: None,
        accelerated: booted.hardware_accelerated,
    })
}

/// Boot one scenario and judge the **store domain** alone, which is the whole of
/// what it is for.
///
/// [`run_cryptography_scenario`]'s shape, and every omission is deliberate on the
/// same terms: this node has every surface, the boots that ran before it judged
/// all of them, and re-judging any of it here would pay a boot for a second
/// reading of a fact about the image. What only this boot can contribute is the
/// identity on its medium — and even that is half a claim, the other half being
/// the partner boot that reads the same medium back.
///
/// Answers no sequence number: nothing opens a connection to the management port.
fn run_store_scenario(
    root: &Path,
    scenario: &Scenario,
    run: Run,
    disk: &Path,
    topology: &Topology,
    owner: Ownership,
) -> Result<Observed, String> {
    let name = scenario.name;
    let log_name = format!("{}.log", scenario_run_label(name, run));
    let booted = boot(
        root,
        disk,
        &log_name,
        BootContract::StoreIdentity,
        topology,
        Bench {
            accelerator: scenario.accelerator,
            management: ManagementBacking::Socket,
            traffic: scenario.traffic,
            dial: scenario.dial,
            onboard: scenario.onboard,
            store: scenario.store,
            owner,
        },
    )
    .map_err(|error| format!("scenario {name}: {error}"))?;
    let log = scenario_log(root, scenario, run);
    let identity = store_contract::judge(&booted.serial, &log)
        .map_err(|error| format!("scenario {name}: {error}"))?;
    let owned = ownership_contract::judge(&booted.serial, owner, &log)
        .map_err(|error| format!("scenario {name}: {error}"))?;
    println!(
        "  system scenario ok: {name} on the {} kernel ({}; {owned}); QEMU output is in {}",
        run.config(),
        identity.summary(),
        log.display()
    );
    Ok(Observed {
        management_tcp_isn: None,
        store_identity: Some(identity),
        accelerated: booted.hardware_accelerated,
    })
}

/// Boot one scenario whose node comes up **forwarding nothing**, and report what
/// the console said about why.
///
/// Short by comparison with its sibling, and every omission is a surface such a
/// node does not have. It committed no generation, so its management port is
/// unaddressed: nothing scrapes it, nothing downloads a recording from it, and no
/// counter exists to cross-check. What is left is the two things the criterion
/// names — the serial console, and the absence of any forwarded frame — and both
/// are decided inside the boot contract, whose verdict is this function's.
///
/// Answers no sequence number: no connection was opened to the management port,
/// there being nothing there to open one to.
fn run_fail_closed_scenario(
    root: &Path,
    scenario: &Scenario,
    run: Run,
    disk: &Path,
    document: &[u8],
    topology: &Topology,
    owner: Ownership,
) -> Result<Observed, String> {
    let name = scenario.name;
    let transcript = crate::config_transcript::RefusedContract::from_document(document)
        .map_err(|error| format!("scenario {name}: {error}"))?;
    let log_name = format!("{}.log", scenario_run_label(name, run));
    let booted = boot_and_fail_closed(
        root,
        disk,
        &log_name,
        topology,
        &transcript,
        scenario.store,
        owner,
    )
    .map_err(|error| format!("scenario {name}: {error}"))?;
    // The table, which on this scenario is the evidence rather than the preamble:
    // every row is a probe the shipped document forwards, and every one of them
    // reads `refused`.
    print!("{}", booted.traffic.render());
    let log = scenario_log(root, scenario, run);
    let owned = ownership_contract::judge(&booted.serial, owner, &log)
        .map_err(|error| format!("scenario {name}: {error}"))?;
    println!(
        "  system scenario ok: {name} on the {} kernel ({}; {}; {owned}); QEMU output is in {}",
        run.config(),
        booted.traffic.summary(),
        transcript.summary(),
        log.display()
    );
    Ok(Observed {
        management_tcp_isn: None,
        store_identity: None,
        accelerated: booted.hardware_accelerated,
    })
}

/// Boot `disk` through OVMF/GRUB with two socket-backed NICs and assert the
/// bidirectional routed contract stated between `topology`'s endpoints,
/// returning what the boot was observed to do: the guest's serial output
/// (always also written to `build/image/<log_name>`) for callers that
/// additionally assert on a structured console channel, and the traffic the
/// probes produced.
pub(crate) fn boot_and_forward(
    root: &Path,
    disk: &Path,
    log_name: &str,
    topology: &Topology,
    bench: ForwardBench,
) -> Result<Booted, String> {
    let ForwardBench {
        management,
        traffic,
        dial,
        onboard,
        store,
        owner,
    } = bench;
    boot(
        root,
        disk,
        log_name,
        BootContract::Routed,
        topology,
        Bench {
            // The routed contract is a statement about the image, and every boot
            // of it takes whatever the machine offers. The one boot that chooses
            // is the one whose subject is the accelerator itself.
            accelerator: Accelerator::WhateverTheMachineOffers,
            management,
            traffic,
            dial,
            onboard,
            store,
            owner,
        },
    )
}

/// Judge both recordings a boot pulled — each on its own terms, then the two of
/// them against each other, against the exposition the same boot answered, and
/// against the bytes the harness put on the wire.
///
/// The order is the order the findings are worth reading in. A body that is not
/// a pcapng file at all is reported as that and not as a pairing failure; only
/// once both parse is the interesting question reachable, which is whether the
/// three surfaces tell one story ([`crate::surface_contract`]).
///
/// Both bodies are also written into the build tree, so a human can open them
/// in Wireshark or `tcpdump -r` after a run without booting anything again.
///
/// The disk half — read separately by [`crate::data_disk`] — is what makes the
/// download evidence rather than a round trip through the appliance's own
/// memory: a recorder that answered a plausible body out of nothing would
/// satisfy the client and leave the medium empty, and a harness that only asked
/// over HTTP would not notice.
fn judge_recordings(
    root: &Path,
    scenario: &str,
    booted: &Booted,
    topology: &Topology,
    log: &Path,
    owner: Ownership,
) -> Result<String, String> {
    // The events the probes oblige the connection history to hold, which is what
    // bounds it from below. Not the frame count: the log holds a record where the
    // appliance reached a lifecycle or policy event and nowhere else, so holding
    // one per frame would be the defect rather than the contract.
    let owed_events = booted
        .injected
        .iter()
        .filter(|injected| injected.event.is_some())
        .count();
    let expectations = [
        recording_contract::Expectation {
            target: pd_runtime::LOG_TARGET,
            snap_len: lfw_recorder::deck::LOG_SNAP_LEN as usize,
            least_packets: owed_events,
        },
        recording_contract::Expectation {
            target: pd_runtime::CAPTURE_TARGET,
            snap_len: lfw_recorder::deck::CAPTURE_SNAP_LEN as usize,
            // The frames the harness itself put across the appliance, which is
            // the number of observations the router must have decided on. At
            // least, not exactly: the management port's own frames and any
            // re-injection are decided on too.
            least_packets: booted.dataplane_frames as usize,
        },
    ];
    if booted.recordings.len() != expectations.len() {
        return Err(format!(
            "the boot met its contract and pulled {} recordings rather than {}, so nothing was \
             proved about the download path\n  full run log: {}",
            booted.recordings.len(),
            expectations.len(),
            log.display()
        ));
    }
    let mut evidence = String::from("  both recordings, downloaded and parsed as pcapng:");
    let mut parsed = Vec::new();
    for (download, expected) in booted.recordings.iter().zip(&expectations) {
        let found = recording_contract::judge(download, expected)?;
        evidence.push('\n');
        evidence.push_str(&recording_contract::evidence(
            download,
            &found,
            expected.snap_len,
        ));
        evidence.push('\n');
        evidence.push_str(&keep(root, scenario, download)?);
        parsed.push(found);
    }

    // The second scrape, which is the one `metrics_contract` judges and the one
    // whose counters have advanced past the first connection.
    let exposition = booted.scrapes.last().ok_or(
        "the recordings were pulled and no scrape was taken, so the recorder's own published \
         counts are not available to compare them against",
    )?;
    let [log_parsed, capture_parsed] = parsed.as_slice() else {
        return Err(format!(
            "{} recordings parsed and the contract is stated over two",
            parsed.len()
        ));
    };
    // What the appliance's own exposition says about the decisions the recordings
    // describe. Read here rather than inside the judgement so that
    // `surface_contract::judge` stays a pure function of parsed inputs.
    let mut drop_reasons = BTreeMap::new();
    for reason in surface_contract::DROP_REASONS {
        drop_reasons.insert(
            reason.to_owned(),
            metrics_contract::drop_reason_total(&exposition.body, reason)?,
        );
    }
    let mut rules = Vec::new();
    for id in topology.rule_ids() {
        rules.push(surface_contract::DeclaredRule {
            id: id.as_str().to_owned(),
            hits: metrics_contract::rule_hits(&exposition.body, id.as_str())?,
        });
    }
    let published = surface_contract::Published {
        forwarded_frames: metrics_contract::forwarded_frames_total(&exposition.body)?,
        drop_reasons,
        rules,
    };
    let agreement = surface_contract::judge(
        &surface_contract::Surface {
            target: pd_runtime::LOG_TARGET,
            snap_len: lfw_recorder::deck::LOG_SNAP_LEN,
            parsed: log_parsed,
            published_records: metrics_contract::sink_records(&exposition.body, "log")?,
        },
        &surface_contract::Surface {
            target: pd_runtime::CAPTURE_TARGET,
            snap_len: lfw_recorder::deck::CAPTURE_SNAP_LEN,
            parsed: capture_parsed,
            published_records: metrics_contract::sink_records(&exposition.body, "capture")?,
        },
        &surface_contract::Wire {
            injected: &booted.injected,
            ports: topology.interfaces().len(),
        },
        &published,
        // Whether this boot can have opened a conversation at all, taken from the
        // medium the harness attached: an appliance nobody has onboarded carries
        // nothing, so its history is legitimately empty and its capture is not.
        matches!(owner, Ownership::Owned),
    )
    .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?;
    evidence.push('\n');
    evidence.push_str(&agreement.evidence());
    Ok(evidence)
}

/// Write one downloaded recording into the build tree, answering the line that
/// says where it landed.
///
/// A run that proves something about a file and then discards it leaves a
/// reader with nothing to open: the next question after "the contract held" is
/// always "what was in it", and re-running a ten-minute boot to ask it is the
/// cost this avoids. The name carries the scenario, so two scenarios' captures
/// cannot overwrite each other.
fn keep(root: &Path, scenario: &str, download: &Download) -> Result<String, String> {
    let file = download.target.trim_start_matches('/');
    let path = root
        .join("build/image")
        .join(format!("qemu-{scenario}-{file}"));
    fs::write(&path, &download.body)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(format!(
        "    kept at {} — open it with `tcpdump -r` or Wireshark",
        path.display()
    ))
}

/// Write one body of evidence into the run log, behind the guest's own output,
/// under a heading that says what it is.
///
/// The log is the artifact a reader opens after a failure, and a proof that
/// exists only in a terminal that has scrolled away is not evidence. The
/// heading is the caller's rather than fixed here: a log carrying three
/// different proofs under one title tells a reader the first thing wrong about
/// the other two. Appended rather than interleaved: the capture above it is the
/// guest's, byte for byte, and nothing this harness writes may land inside it.
fn append_evidence(log: &Path, heading: &str, evidence: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(log)
        .map_err(|error| format!("open {} to append the evidence: {error}", log.display()))?;
    writeln!(file, "\n# {heading}\n{evidence}")
        .map_err(|error| format!("append the evidence to {}: {error}", log.display()))
}

/// Boot `disk` expecting the node to come up and **forward nothing**, because the
/// configuration domain refuses the document the image carries.
///
/// No injected packet may come back on any port, the management wire included, and
/// the console must carry the whole of `transcript` — the refusal naming the
/// document's own reason, the configuration domain's `state=refused`, the
/// forwarding domain's fail-closed record, and nothing that says a generation above
/// zero ever reached the dataplane.
pub(crate) fn boot_and_fail_closed(
    root: &Path,
    disk: &Path,
    log_name: &str,
    topology: &Topology,
    transcript: &crate::config_transcript::RefusedContract,
    store: StoreMedium,
    owner: Ownership,
) -> Result<Booted, String> {
    boot(
        root,
        disk,
        log_name,
        BootContract::FailedClosed { transcript },
        topology,
        Bench {
            accelerator: Accelerator::WhateverTheMachineOffers,
            // Socket-backed, so the harness sees every frame that port emits and
            // can hold it to emitting none. A real client would be pointless:
            // there is nothing at the other end of the forward, the port being
            // unaddressed until a generation commits.
            management: ManagementBacking::Socket,
            // The probes the shipped document forwards, injected between the same
            // endpoints over the same ports — which is what makes their absence
            // the policy having never been committed rather than a bench
            // mismatch. This document's addressing is the shipped one to the
            // byte, for exactly that.
            traffic: Traffic::Routed,
            dial: DialContract::Answered,
            onboard: OnboardContract::Untouched,
            store,
            owner,
        },
    )
}

/// Boot `disk` expecting NO slot to be bootable: no injected packet may come
/// back in any form, and the guest must emit `marker` — the boot manager's
/// structured halt record. Returns the same observation as
/// [`boot_and_forward`], whose traffic half records that nothing moved.
pub(crate) fn boot_and_halt(
    root: &Path,
    disk: &Path,
    log_name: &str,
    marker: &str,
    topology: &Topology,
) -> Result<Booted, String> {
    boot(
        root,
        disk,
        log_name,
        BootContract::Halted { marker },
        topology,
        Bench {
            accelerator: Accelerator::WhateverTheMachineOffers,
            management: ManagementBacking::Socket,
            // A halted slot forwards nothing, so which set would have been
            // injected decides nothing about the verdict; the routed set keeps
            // the one thing it does decide — the frames put on the wire — the
            // same as every other halt scenario's.
            traffic: Traffic::Routed,
            dial: DialContract::Answered,
            onboard: OnboardContract::Untouched,
            // A fresh medium, so the appliance on it has no owner — which decides
            // nothing here: no slot boots, so no domain reads the word.
            store: StoreMedium::Fresh,
            owner: Ownership::Unowned,
        },
    )
}

fn boot(
    root: &Path,
    disk: &Path,
    log_name: &str,
    contract: BootContract,
    topology: &Topology,
    bench: Bench,
) -> Result<Booted, String> {
    let Bench {
        accelerator,
        management,
        traffic,
        dial,
        onboard,
        store,
        owner,
    } = bench;
    let run_label = log_name.strip_suffix(".log").unwrap_or(log_name);
    // Whether this boot reads the recordings back follows from the backing
    // rather than being a second decision beside it: a real client is exactly
    // what a download needs, and there is no scenario that has one and does not
    // use it ([`ManagementRole::Client`]).
    let recordings = !management.is_socket();
    let backends = forward_harness::NicBackends::new(management)?;
    let Invocation {
        mut command,
        acceleration,
        data,
        store: store_disk,
    } = qemu_base(root, "stdio", disk, run_label, accelerator, store)?;
    command.arg("-monitor").arg("none");
    backends.apply(&mut command, topology)?;

    let description = acceleration.describe();
    println!("  QEMU {run_label}: {description}");
    let log = root.join("build/image").join(log_name);
    // The marker closing the header is [`GUEST_OUTPUT_MARKER`] rather than a
    // literal, because `diagnose` splits a run log on it to tell the harness's
    // own words from the guest's — and a release capture with nothing after it
    // is the finding that note exists for.
    let header = format!(
        "# librefirewall QEMU run: {run_label}\n\
         # {description}\n\
         {GUEST_OUTPUT_MARKER}"
    );
    // Which data-disk verdict this boot owes, taken before the contract is
    // handed over: a boot that runs the appliance must leave the witness pattern
    // on the medium, and one with no bootable slot must leave the sector alone.
    //
    // A node that refused its own configuration is on the first side of that line
    // and not the second, which is the distinction the two absences make easy to
    // get wrong. It forwards nothing — but every protection domain came up, and the
    // recorder's proof of the path to the medium is not a dataplane matter: it maps
    // no configuration at all. So the witness must be there, and its absence would
    // mean a domain never started rather than a policy never committed.
    //
    // The cryptography boot owes neither, which is the one case where the answer
    // is not one of the two. It stops the instant the cryptography domain
    // finishes, and nothing orders that against the recorder's own proof of the
    // medium: a witness asserted here would be asserted on a race, and the same
    // sector asserted untouched would be asserted against a domain that was
    // running.
    let data_disk = match contract {
        BootContract::Halted { .. } => DataDiskVerdict::SectorUntouched,
        BootContract::Routed | BootContract::FailedClosed { .. } => DataDiskVerdict::WitnessWritten,
        BootContract::Cryptography | BootContract::StoreIdentity => {
            DataDiskVerdict::NotThisBootsSubject
        }
    };
    // The store medium's own verdict, which is not the recorder's and is decided
    // on different terms. A boot with no bootable slot must leave it as the
    // zeroes it was made as; a boot that ran the appliance must have opened its
    // first sector with the state record's magic — either because it minted one or
    // because it reloaded the one already there. A boot whose subject is the
    // *accelerator* owes neither, for the reason it owes neither of the
    // recorder's: it ends the moment the cryptography domain finishes, which
    // nothing orders against the store domain's own write.
    //
    // A carried medium is the one case where "written" is not this boot's doing,
    // and asserting it anyway is the point: the file must still be a record after
    // the second boot read it, because a reload that rewrote or cleared the medium
    // would be an appliance losing its identity by looking at it.
    let store_medium = match contract {
        BootContract::Halted { .. } => DataDiskVerdict::SectorUntouched,
        BootContract::Routed | BootContract::FailedClosed { .. } | BootContract::StoreIdentity => {
            DataDiskVerdict::WitnessWritten
        }
        BootContract::Cryptography => DataDiskVerdict::NotThisBootsSubject,
    };
    let booted = forward_harness::run_boot_test(
        command,
        backends,
        BootTest {
            contract,
            root,
            log_path: &log,
            log_header: &header,
            topology,
            traffic,
            dial,
            onboard,
            hardware_accelerated: acceleration.is_hardware(),
        },
    )?;

    // The data disk, judged after the boot contract and never instead of it.
    // Which verdict is owed follows from the contract, and the pair is what
    // makes either one evidence: a boot that ran the appliance must have left
    // the witness pattern on the medium, and a boot with no bootable slot must
    // have left the same sector untouched. A harness asserting only the first
    // would pass on a host that wrote the file itself.
    let verdict = match data_disk {
        DataDiskVerdict::WitnessWritten => Some(data.judge_written()),
        DataDiskVerdict::SectorUntouched => Some(data.judge_untouched()),
        DataDiskVerdict::NotThisBootsSubject => None,
    }
    .transpose()
    .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?;
    if let Some(verdict) = verdict {
        println!("  data disk {run_label}: {verdict}");
    }
    let store_verdict = match store_medium {
        DataDiskVerdict::WitnessWritten => Some(store_disk.judge_written()),
        DataDiskVerdict::SectorUntouched => Some(store_disk.judge_untouched()),
        DataDiskVerdict::NotThisBootsSubject => None,
    }
    .transpose()
    .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?;
    if let Some(verdict) = store_verdict {
        println!("  store medium {run_label}: {verdict}");
    }
    // And, on the one boot that asked for a factory reset, the half no console
    // record can settle: that the key the medium held before it is nowhere on the
    // medium after it.
    if let Some(verdict) = store_disk
        .judge_secret_erased()
        .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?
    {
        println!("  store medium {run_label}: {verdict}");
    }
    // And, on the one boot that reloads a live key and lends it to a second
    // protection domain, the surface: that the scalar it signed with twice reached
    // no console record. The regions the two domains share are guest RAM and are
    // not readable from here, so what the key cannot cross is argued from the
    // grants and the ABI; what it visibly did not reach is checked.
    if let Some(verdict) = store_disk
        .judge_secret_off_the_console(&booted.serial)
        .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?
    {
        println!("  store medium {run_label}: {verdict}");
    }
    // And, on every boot that pulled the recordings, the medium itself: the
    // extents the appliance wrote, read by a process the guest cannot reach.
    if recordings {
        // Whether this boot can have written a conversation history: an appliance
        // no management plane has taken forwards nothing, so it opens no flow and
        // its history extent is legitimately empty. Taken from the medium the
        // harness attached rather than from the recording, which would be the
        // recording judging itself.
        let conversations = matches!(owner, Ownership::Owned);
        let on_disk = data
            .judge_recordings(conversations)
            .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?;
        println!("  data disk {run_label}: {on_disk}");
        append_evidence(
            &log,
            "the two recording extents, read off the disk image after shutdown",
            &on_disk,
        )?;
    }
    Ok(booted)
}

/// Boot the disk `dist/` holds interactively, on QEMU's own user-mode network.
///
/// The caller assembles that disk in the DEBUG kernel configuration (see
/// `main`'s `run` arm): this is the one command whose output a human reads as
/// it happens, so the kernel's serial diagnostics are worth their cost here
/// exactly as they are not in the gate.
pub(crate) fn run_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    let path = root.join(image::CONFIGURATION_DOCUMENT);
    let topology = Topology::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let Invocation {
        mut command,
        acceleration,
        data: _,
        store: _,
    } = qemu_base(
        root,
        "mon:stdio",
        &disk,
        "run",
        Accelerator::WhateverTheMachineOffers,
        // A fresh medium, so an interactive run mints an identity rather than
        // inheriting whichever scenario ran last.
        StoreMedium::Fresh,
    )?;
    println!("QEMU run: {}", acceleration.describe());
    // Interactive runs have no harness peer to dial into, so back every NIC
    // port with QEMU's self-contained user-mode stack instead. The management
    // port is attached like the others: without it the third driver instance
    // finds no device at 00:04.0 and parks on a refusal, which is a boot no
    // shipped image would ever perform.
    for nic in every_guest_nic() {
        command
            .arg("-netdev")
            .arg(format!("user,id={}", nic.netdev_id()))
            .arg("-device")
            .arg(nic_device(&topology, nic)?);
    }
    run_command(&mut command, "run QEMU")?;
    Ok(())
}

/// Which guest NIC a `-device` argument is for.
///
/// A type rather than a port number, because the two are not the same kind of
/// thing: a dataplane port is one of the document's `<interface>` elements and
/// is indexed by the `port=` it claims, while the management port is the
/// document's one `<management>` element and has no number at all. A bare
/// `usize` would have to mean "index into the interfaces" and "the one past the
/// end" at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuestNic {
    /// Dataplane port `n`, whose MAC the document's interface on it claims.
    Dataplane(usize),
    /// The management port, whose MAC the document's `<management>` element
    /// claims.
    Management,
}

impl GuestNic {
    /// The slot this NIC occupies, which decides both its netdev id and its PCI
    /// address. One derivation for both kinds: the management port sits one past
    /// the dataplane ports, so `addr=0{slot+2}.0` reproduces 00:02.0, 00:03.0
    /// and 00:04.0 — and 00:04.0 is the device whose ECAM page the system
    /// description grants as `ecam2` at PCIEXBAR + (4 << 15).
    pub(crate) const fn slot(self) -> usize {
        match self {
            Self::Dataplane(port) => port,
            Self::Management => PORTS,
        }
    }

    /// The netdev id the backend is joined by, `socket` under the harness and
    /// `user` for interactive runs.
    pub(crate) fn netdev_id(self) -> String {
        format!("n{}", self.slot())
    }
}

/// The virtio-net-pci `-device` argument for one guest NIC, pinned to the PCI
/// address the system description assigns it, with no option ROM (so the
/// firmware gains no PXE payload).
///
/// The MAC is the derivation this function exists for. Every one of them used to
/// be a literal here that had to equal a literal in the harness and a third in
/// the document, with nothing comparing the three; now a NIC can only be given a
/// MAC the document claims — a dataplane port's from the `<interface>` on it, and
/// the management port's from the `<management>` element — so the address a
/// contract expects the appliance to answer to is the address the port carries.
///
/// # Errors
/// A dataplane port with no interface in the document, which the topology names.
pub(crate) fn nic_device(topology: &Topology, nic: GuestNic) -> Result<String, String> {
    let [a, b, c, d, e, f] = match nic {
        GuestNic::Dataplane(port) => topology.port_mac(port).map_err(|error| error.to_string())?,
        GuestNic::Management => topology.management().mac,
    };
    Ok(format!(
        "virtio-net-pci,netdev={},disable-legacy=on,disable-modern=off,\
         mac={a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x},bus=pcie.0,addr=0{}.0,romfile=",
        nic.netdev_id(),
        nic.slot() + 2
    ))
}

/// Every NIC the image expects to find, in slot order: one per dataplane port,
/// then the management port. A shorter list is a boot with a driver instance
/// staring at an absent device.
pub(crate) fn every_guest_nic() -> Vec<GuestNic> {
    (0..PORTS)
        .map(GuestNic::Dataplane)
        .chain([GuestNic::Management])
        .collect()
}

/// Build the shared QEMU invocation that boots the deployable disk through
/// OVMF (UEFI) and the signed GRUB image, rather than QEMU's direct multiboot
/// loader. This exercises the same firmware -> boot-manager -> seL4 chain the
/// hardware appliance uses. The disk itself is writable so GRUB can persist
/// boot-selection state.
///
/// Each invocation gets its own writable copy of the OVMF variable store, named
/// after `run_label` and reset from the pristine template every time, so one
/// A/B scenario's UEFI boot-variable writes cannot influence the next. Like the
/// rest of `build/image` — the scenario disk and the run logs included — it
/// assumes one build at a time; the build tree is not a concurrency domain.
fn qemu_base(
    root: &Path,
    serial: &str,
    disk: &Path,
    run_label: &str,
    accelerator: Accelerator,
    store: StoreMedium,
) -> Result<Invocation, String> {
    require_file(disk)?;

    let code = locate(OVMF_CODE_CANDIDATES, "OVMF code firmware")?;
    let vars_template = locate(OVMF_VARS_CANDIDATES, "OVMF variable store")?;
    let vars = root
        .join("build/image")
        .join(format!("OVMF_VARS-{run_label}.fd"));
    if let Some(parent) = vars.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    copy_file(&vars_template, &vars)?;

    let acceleration = Acceleration::choose(accelerator);
    let data = DataDisk::create(root, run_label)?;
    // The appliance's own medium: created fresh, carried from the boot that minted
    // an identity on it, or copied from the boot that was given an owner. Which one
    // is the scenario's decision, so a boot cannot accidentally inherit an identity
    // it was meant to mint, nor forward under an owner it was meant to be without.
    let store = match store {
        StoreMedium::Fresh => StoreDisk::create(root, run_label)?,
        StoreMedium::CarriedFrom(source) => {
            StoreDisk::carried(root, &scenario_run_label(source, Run::Shipping))?
        }
        // The source's *shipping* label like the two around it, and this run's own
        // label for the destination: a diagnostic re-run copies the same owned
        // medium into a file of its own rather than over the shipping run's.
        StoreMedium::CopiedFrom(source) => {
            StoreDisk::copied(root, &scenario_run_label(source, Run::Shipping), run_label)?
        }
        // The request is written here, on the host side of the emulation, because
        // that is what the mechanism *is*: one sector of a medium somebody has in
        // their hands.
        StoreMedium::ResetRequestedOn(source) => {
            StoreDisk::reset_requested(root, &scenario_run_label(source, Run::Shipping))?
        }
    };

    let mut command = Command::new("qemu-system-x86_64");
    command
        .current_dir(root)
        // `hpet=on` explicitly, and not because QEMU's q35 default is off — it
        // is on. A default is a value QEMU may change between versions, and the
        // clock domain's whole first step is probing a block at 0xFED00000: a
        // machine that stopped presenting one would turn every system scenario
        // into a `hpet-not-present` refusal, reported as this project's defect.
        // The system description grants the region unconditionally, so stating
        // the device here is what keeps the two ends of that grant agreeing.
        .args([
            "-machine",
            "q35,hpet=on",
            "-accel",
            acceleration.qemu_accel(),
        ])
        .args(["-cpu", GUEST_CPU])
        .args(["-m", "1G", "-display", "none"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            code.display()
        ))
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", vars.display()))
        // Attach the disk as an explicit device with bootindex=0 so OVMF's
        // boot order starts at GRUB on the disk rather than at the firmware's
        // own network-boot options for the virtio NICs.
        .arg("-drive")
        .arg(format!(
            "if=none,id=boot,format=raw,file={}",
            disk.display()
        ))
        .args(["-device", "ide-hd,drive=boot,bootindex=0"])
        // `-no-reboot` turns a guest reset request into a QEMU exit instead of
        // a boot loop. There is deliberately no `-no-shutdown` beside it:
        // letting a guest power-off exit QEMU is what keeps the harness's fast,
        // specific "QEMU exited" diagnostic reachable — otherwise every
        // guest-initiated exit degrades into the 180 s timeout — and it is what
        // makes the boot manager's halt path observable as an exit at all.
        .args(["-serial", serial, "-no-reboot"]);
    // The recorder's device, beside the boot disk and before the NICs. It is
    // attached to every invocation rather than to the scenarios that judge it,
    // because a domain staring at an absent device is a different boot from the
    // one the image was assembled for.
    data.attach(&mut command);
    // And the store device beside it, one PCI slot further on. Attached to every
    // invocation for the reason the data device is, and after it so the two
    // `-device` arguments read in the order the two ECAM pages do.
    store.attach(&mut command);
    Ok(Invocation {
        command,
        acceleration,
        data,
        store,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_accelerators_present_the_same_guest_cpu() {
        // The asserted boot contract must not depend on the runner's host CPU,
        // so the CPU model is one pinned string and only `-accel` varies.
        assert_eq!(Acceleration::Kvm.qemu_accel(), "kvm");
        assert_eq!(
            Acceleration::Tcg {
                kvm_rejected_because: "probe failed".to_owned(),
            }
            .qemu_accel(),
            "tcg"
        );
        assert!(
            !GUEST_CPU.contains("host"),
            "the host CPU must never leak in"
        );
    }

    #[test]
    fn a_tcg_fallback_always_carries_the_reason_kvm_was_rejected() {
        let kvm = Acceleration::Kvm.describe();
        assert!(kvm.contains("accel=kvm") && kvm.contains(GUEST_CPU));
        assert!(!kvm.contains("kvm-rejected"));

        let tcg = Acceleration::Tcg {
            kvm_rejected_because: "cannot open /dev/kvm read-write: Permission denied".to_owned(),
        }
        .describe();
        assert!(tcg.contains("accel=tcg") && tcg.contains(GUEST_CPU));
        assert!(
            tcg.contains("Permission denied"),
            "the rejection cause must survive into the log: {tcg}"
        );
    }

    #[test]
    fn detection_reports_a_concrete_reason_when_kvm_is_unusable() {
        // Whatever this machine offers, the decision must be self-describing:
        // either accelerated, or emulated WITH the reason attached.
        match Acceleration::detect() {
            Acceleration::Kvm => assert!(Path::new(KVM_DEVICE).exists()),
            Acceleration::Tcg {
                kvm_rejected_because,
            } => assert!(
                kvm_rejected_because.contains(KVM_DEVICE),
                "the reason must name the device it probed: {kvm_rejected_because}"
            ),
            // Unreachable: `detect` probes the device and reports what it found,
            // and a request is the one thing it is never asked about.
            Acceleration::TcgByRequest => {
                unreachable!("detection cannot produce a boot's own request")
            }
        }
    }

    /// A boot that asks for emulation gets it on every machine, and says which
    /// of the two reasons it is emulating for. A run that reported "accel=tcg"
    /// identically for a deliberate choice and for a machine that could not
    /// accelerate would leave the log unable to tell a proof from a degradation.
    #[test]
    fn a_requested_emulation_is_taken_whatever_the_machine_offers() {
        let requested = Acceleration::choose(Accelerator::Emulated);
        assert_eq!(requested.qemu_accel(), "tcg");
        assert!(!requested.is_hardware());
        let described = requested.describe();
        assert!(described.contains("accel=tcg") && described.contains(GUEST_CPU));
        assert!(
            described.contains("emulation-requested") && !described.contains("kvm-rejected"),
            "a deliberate emulation must not read as a rejected accelerator: {described}"
        );
        // And the other request is the machine's answer, whatever this machine's
        // answer is.
        let offered = Acceleration::choose(Accelerator::WhateverTheMachineOffers);
        assert!(!matches!(offered, Acceleration::TcgByRequest));
    }

    /// Exactly one scenario forces emulation, and it repeats a boot the run
    /// already makes rather than adding a document or an image build. Both halves
    /// are the cost argument the boot was accepted on: a second table entry that
    /// quietly grew a second image would be a different bargain.
    #[test]
    fn one_scenario_forces_emulation_and_pays_for_one_boot() {
        let forced: Vec<&Scenario> = SCENARIOS
            .iter()
            .filter(|scenario| scenario.accelerator == Accelerator::Emulated)
            .collect();
        let [emulated] = forced.as_slice() else {
            panic!(
                "{} scenarios force emulation and the run pays for one",
                forced.len()
            );
        };
        assert!(
            matches!(emulated.console, Console::JudgedOnCryptographyAlone),
            "the forced boot judges the cryptography domain and nothing else"
        );
        assert!(
            matches!(emulated.image, ImageUnderTest::Published)
                && SCENARIOS.iter().any(|scenario| {
                    scenario.name != emulated.name
                        && scenario.document == emulated.document
                        && matches!(scenario.image, ImageUnderTest::Published)
                }),
            "the forced boot must reuse a published disk another scenario already boots"
        );
        // And it takes no client, so it pulls no surface: the endpoint's three
        // are the accelerated scenarios' subject.
        assert!(!emulated.reaches_the_management_port());
    }

    /// The run may only claim the contrast it actually drew. On a machine that
    /// accelerated nothing there is none, and the clause says so instead of
    /// asserting a property of the runner as one of the image.
    #[test]
    fn the_summary_claims_a_contrast_only_where_one_was_drawn() {
        let names: Vec<(&str, bool)> = SCENARIOS
            .iter()
            .map(|scenario| {
                (
                    scenario.name,
                    scenario.accelerator == Accelerator::WhateverTheMachineOffers,
                )
            })
            .collect();
        let accelerated = describe_the_emulated_boots(SCENARIOS, &names);
        assert!(
            accelerated.contains("cryptography-under-emulation")
                && accelerated.contains("ran on the processor"),
            "{accelerated}"
        );

        let emulated: Vec<(&str, bool)> = names.iter().map(|&(name, _)| (name, false)).collect();
        let alone = describe_the_emulated_boots(SCENARIOS, &emulated);
        assert!(
            alone.contains("drew no contrast") && !alone.contains("ran on the processor"),
            "{alone}"
        );
    }

    /// The shipped bench, so a device argument is checked against the same
    /// document the appliance in the image was built from.
    fn bench() -> Topology {
        Topology::from_document(include_bytes!(
            "../../../systems/qemu-x86_64/configuration.xml"
        ))
        .expect("the shipped document describes the bench")
    }

    #[test]
    fn each_port_gets_its_pinned_pci_address_and_no_option_rom() {
        let topology = bench();
        // The three addresses the system description grants an ECAM page for,
        // and the management port is the third: `ecam2` is the page of device 4.
        assert!(
            nic_device(&topology, GuestNic::Dataplane(0))
                .unwrap()
                .contains("addr=02.0")
        );
        assert!(
            nic_device(&topology, GuestNic::Dataplane(1))
                .unwrap()
                .contains("addr=03.0")
        );
        assert!(
            nic_device(&topology, GuestNic::Management)
                .unwrap()
                .contains("addr=04.0")
        );
        for nic in every_guest_nic() {
            assert!(
                nic_device(&topology, nic).unwrap().ends_with("romfile="),
                "an option ROM would give the firmware a PXE payload"
            );
        }
        // Every NIC on its own netdev id and its own slot, or two would share a
        // backend and a PCI function.
        let slots: Vec<usize> = every_guest_nic().iter().map(|nic| nic.slot()).collect();
        assert_eq!(slots, (0..=PORTS).collect::<Vec<_>>());
    }

    /// The management port answers to an address no dataplane port on either
    /// bench does. Two NICs sharing one would have a routed frame accepted by
    /// whichever saw it first — and now that both come out of one document, this
    /// is a check on what that document says rather than on a literal.
    #[test]
    fn a_managed_port_carries_a_mac_no_dataplane_port_claims() {
        for topology in [bench(), alternate()] {
            let management = topology.management().mac;
            for port in 0..PORTS {
                assert_ne!(topology.port_mac(port), Ok(management));
            }
            for endpoint in topology.endpoints() {
                assert_ne!(endpoint.mac, management);
            }
            assert!(
                nic_device(&topology, GuestNic::Management)
                    .unwrap()
                    .contains(&mac_argument(management))
            );
        }
    }

    /// The MAC as a `-device` argument renders it, so a test compares the string
    /// QEMU is given rather than a second formatting of the same bytes.
    fn mac_argument([a, b, c, d, e, f]: [u8; 6]) -> String {
        format!("mac={a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }

    /// The cross-artifact fact that used to be a comment saying nothing checked
    /// it: the MAC QEMU puts on a port is the MAC the document's interface on
    /// that port claims, so the appliance answers to the address it was
    /// configured with.
    #[test]
    fn the_mac_a_port_carries_is_the_one_its_interface_claims() {
        let topology = bench();
        for port in 0..PORTS {
            let [a, b, c, d, e, f] = topology.port_mac(port).expect("a claimed port");
            assert!(
                nic_device(&topology, GuestNic::Dataplane(port))
                    .unwrap()
                    .contains(&format!(
                        "mac={a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}"
                    )),
                "port {port}"
            );
        }
        // Two ports must not answer to one address, or a routed frame would be
        // accepted by whichever NIC saw it first. `config` refuses a document
        // that says so; this is the check on the argument that reaches QEMU.
        assert_ne!(topology.port_mac(0), topology.port_mac(1));
    }

    #[test]
    fn a_port_this_build_has_none_of_yields_no_device_argument() {
        let error = nic_device(&bench(), GuestNic::Dataplane(PORTS))
            .expect_err("there is no such dataplane port");
        assert!(error.contains(&format!("{PORTS}")), "{error}");
    }

    /// The alternate scenario's document is a different bench, and the device
    /// arguments it produces must differ in every MAC — the property scenario 3
    /// rests on.
    fn alternate() -> Topology {
        Topology::from_document(include_bytes!("../scenarios/alternate-addressing.xml"))
            .expect("the alternate document describes a bench")
    }

    #[test]
    fn the_alternate_document_puts_different_macs_on_every_port() {
        let shipped = bench();
        let alternate = alternate();
        // Every NIC, the management one included: its MAC is in the document
        // now, so scenario 3 re-derives it like the rest and a management
        // endpoint answering there proves it read the second document.
        for nic in every_guest_nic() {
            assert_ne!(
                nic_device(&shipped, nic).unwrap(),
                nic_device(&alternate, nic).unwrap(),
                "{nic:?}"
            );
        }
    }
}
