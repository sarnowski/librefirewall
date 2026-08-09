//! The Microkit system description read back into Rust and held to the
//! constants the protection domains compile against.
//!
//! `systems/qemu-x86_64/librefirewall.system` is consumed by the Microkit tool
//! and by nothing else, so every fact a crate compiles against it — a region's
//! extent, its cacheability, the perms it is granted under, *which domains map
//! it at all*, the direction a notification channel is granted in — was a
//! precondition delegated to a file no build step ever read. A
//! disagreement surfaced as a truncated mapping, a device register written
//! through a cached mapping, a domain reaching bytes it was meant never to
//! reach, or a missing signal — at boot, on the one path with no shell and no
//! operator to notice. This module is the enforcer those preconditions
//! name.
//!
//! # No adversary, and that is the point
//!
//! Nothing here reads hostile input: the file is source-controlled and is
//! edited by the same people who edit the constants it must agree with, so
//! no threat-model adversary is named for this path. What it defends against
//! is the ordinary edit that moves one side and not the other — which is why
//! [`REGIONS`], [`IO_PORTS`], [`DOMAINS`], [`CHANNEL_ENDS`] and
//! [`MODELLED_TAGS`] are *exhaustive* rather than best-effort. A region, an
//! I/O-port window, a domain, a channel end, or an element type this module
//! does not name is a finding, not a silent skip: a region nothing claims is a
//! grant nothing compares, and it would enter the description already exempt
//! from the check that exists to judge it.
//!
//! # The grant is a set, and both directions of it are checked
//!
//! A rule names the domains that map its region *exactly*, so the table states
//! what is withheld as directly as what is given. That is what makes the
//! narrowed forwarder grant a build-time property rather than a diff nobody
//! read: the forwarder maps two ring regions, and mapping a buffer pool into it
//! — the one edit that would hand a compromised forwarder every frame in flight
//! — fails here, at the point the edit is made.
//!
//! # A memory mapping is not the only authority a description grants
//!
//! `<ioport>` hands a protection domain a window of the x86 I/O permission
//! bitmap, which is authority over a device on exactly the footing a `<map>` is
//! authority over memory: `in` and `out` are privileged instructions, and a
//! domain holding a port executes them against whatever decodes it. [`IO_PORTS`]
//! is therefore judged the way [`REGIONS`] is, in both directions and against
//! the crate constants the driver forms its addresses from — a grant no rule
//! names, a rule no grant matches, and a window that moved or widened are four
//! separate findings rather than four silences.
//!
//! # Why the scanner is a scanner and not a substring search
//!
//! The file is written to be read by people, and two of its habits defeat the
//! obvious approach outright:
//!
//! * Every `<protection_domain>` carries a `stack_size`. A search for
//!   `size=` matches it, and a checker built that way compares a stack against
//!   a memory region. Attribute names here are lexed whole and read from the
//!   element that carries them, so `stack_size` and `size` are two names and a
//!   `<protection_domain>` is not a `<memory_region>`.
//! * The file's comment blocks quote the very markup they explain — an `<end>`,
//!   a `cached="true"` — because that is how you explain it. Anything inside
//!   `<!-- -->` is markup to a substring search and to nothing else.
//!
//! Everything the scanner cannot classify stops the gate and names
//! itself: an unterminated comment, an unterminated attribute value, an
//! unterminated element, character data outside markup, an element type this
//! module does not model. A cross-check that passes on a file it did not
//! understand is worse than no cross-check, because it reports the agreement it
//! never established.
//!
//! # Reading it is not enough: it must be a document Microkit can read
//!
//! Understanding the file and the file being well-formed XML are two different
//! properties, and only the first was ever established here. The Microkit tool
//! reads this description with a conformant XML parser, so a rule XML imposes
//! that this scanner waved through produced a description that satisfied every
//! table above and then could not be assembled into an image at all — and
//! because this check is what the fast gate runs, that is a commit qualified on
//! the way in and unbootable from the moment it lands. A horizontal rule typed
//! into one of the comment blocks did exactly that.
//!
//! So the scanner is deliberately no more permissive than XML on any rule an
//! edit to this file can trip: the bytes are UTF-8; a comment body carries no
//! `--`; the XML declaration sits at the first byte or nowhere; the document
//! has exactly one root element; attributes are separated by whitespace; and an
//! attribute value carries no raw `<`, no `&` that does not open a character
//! reference or one of the five predefined entities, and no control character
//! beyond tab, newline and carriage return. Where the two could differ the
//! scanner takes the narrower reading — being stricter than XML costs a
//! description nobody would write, while being looser costs the property this
//! module exists for.

use std::{fs, path::Path};

use lfw_blk::{
    BAR_WINDOW_SIZE as BLK_BAR_WINDOW_SIZE, BLK_IO_REGION_SIZE,
    DMA_REGION_SIZE as BLK_DMA_REGION_SIZE,
};
use lfw_hpet::{INTERRUPT_PIN as HPET_INTERRUPT_PIN, MMIO_REGION_SIZE};
use lfw_metrics::{MANAGEMENT_PORT_DOMAIN, PORT_DOMAINS, STATS_REGION_SIZE};
use lfw_rtc::{INDEX_PORT, PORT_COUNT as CMOS_PORT_COUNT};
use nic_driver_core::bringup::{BAR_WINDOW_SIZE, VQ_REGION_SIZE};
use pd_runtime::{
    FLOW_TABLE_REGION_SIZE, FORWARD_REGION_SIZE, POOL_REGION_SIZE, RETURN_REGION_SIZE,
};
use uart_16550::{COM1_BASE, PORT_COUNT as COM1_PORT_COUNT};
use virtio::pci::PCI_CONFIG_LEN;
use wire::{
    CLOCK_CALIBRATION_REGION_SIZE, CONFIG_ACK_REGION_SIZE, CONFIG_REGION_SIZE,
    CONFIG_REPLY_REGION_SIZE, CONFIG_REQUEST_REGION_SIZE, DOWNLOAD_REPLY_REGION_SIZE,
    DOWNLOAD_REQUEST_REGION_SIZE, ENDPOINT_REGION_SIZE, INSTALL_STAGING_REGION_SIZE,
    LOG_CONSUME_REGION_SIZE, LOG_RECORDS_REGION_SIZE, OWNERSHIP_REGION_SIZE,
    RELAY_REPLY_REGION_SIZE, RELAY_REQUEST_REGION_SIZE, SIGN_REPLY_REGION_SIZE,
    SIGN_REQUEST_REGION_SIZE, TAP_CONSUME_REGION_SIZE, TAP_RECORDS_REGION_SIZE,
};

use crate::{image::SYSTEM_DESCRIPTION, util::Error};

/// The exported Rust constant one `<memory_region>`'s `size` must equal.
///
/// There is deliberately no way to name none. A rule that could opt out is a
/// rule an author reaches for instead of exporting the constant, and the
/// exemption then outlives the reason for it: where nothing exported states a
/// region's extent, exporting it is the work.
struct ExpectedSize {
    /// Carried beside the value so a disagreement names both sides rather than
    /// printing two numbers.
    rust_name: &'static str,
    bytes: usize,
}

/// How a region must be mapped. Both values are correctness premises a crate
/// reasons from, not tuning: `virtio::queue`'s fences order CPU-visible memory
/// only and suffice *because* the DMA regions are cached and x86 DMA is
/// cache-coherent, while a device register reached through a cached mapping is
/// not reached at all.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cacheability {
    Cached,
    Uncached,
}

impl Cacheability {
    /// The attribute value that expresses this, and what the gate compares
    /// against. Microkit defaults `cached` to true; the description states it
    /// on every map regardless, so a premise is declared where the mapping is
    /// granted rather than inherited from a default that can move.
    fn attribute(self) -> &'static str {
        match self {
            Self::Cached => "true",
            Self::Uncached => "false",
        }
    }

    /// Why this region has to be mapped this way, quoted into the finding: a
    /// bare "expected true, found false" tells an author what to type and not
    /// what they broke.
    fn premise(self) -> &'static str {
        match self {
            Self::Cached => {
                "`virtio::queue`'s memory-ordering argument names a cached mapping as its \
                 premise: its fences order CPU-visible memory only, which suffices because x86 \
                 DMA is cache-coherent and the region is cached"
            }
            Self::Uncached => {
                "device MMIO: a register read or written through a cached mapping reaches the \
                 cache and not the device"
            }
        }
    }
}

/// One `<map>` a rule admits: the domain that makes it, and what that domain
/// may do to the region through it.
///
/// Perms belong to the grant and not to the region, because one region can be
/// two different authorities at once. The configuration handover is exactly
/// that: `cfg` is the config domain's to write and the forwarder's only to
/// read, and that asymmetry is the whole of what makes the handover a protocol
/// between two domains rather than a shared scratch area. A single `perms` per
/// region could state at most one of the two — necessarily the wider one — and
/// the narrower grant, the one actually doing the withholding, would be
/// compared against nothing.
struct Grant {
    domain: &'static str,
    /// The `perms` attribute this domain's `<map>` must carry, exactly.
    /// Recorded rather than derived because no Rust constant states an
    /// authority: this is where a widened grant — an executable buffer pool, a
    /// writable ECAM page, a forwarder that can rewrite the configuration it is
    /// about to be judged by — becomes a build failure instead of a diff nobody
    /// read.
    perms: &'static str,
}

/// The two authorities this description grants, as constructors rather than
/// literals. The table below is read as a table, and what a reader must see at
/// a glance is which domain reaches which region and how; two dozen identical
/// `perms: "rw"` spellings bury the two that are not.
const fn read_write(domain: &'static str) -> Grant {
    Grant {
        domain,
        perms: "rw",
    }
}

/// As [`read_write`], for a domain admitted to read a region and not to change
/// it.
const fn read_only(domain: &'static str) -> Grant {
    Grant { domain, perms: "r" }
}

/// One `<memory_region>` the description is expected to declare, with
/// everything about it this gate can judge.
struct RegionRule {
    /// The `name` attribute, matched exactly. Exact rather than by prefix so a
    /// renamed or newly split region fails as unmodelled instead of being
    /// silently measured against the constant of the region it replaced.
    name: &'static str,
    size: ExpectedSize,
    cacheability: Cacheability,
    /// Every `<map>` of this region — every one of them, and no other. Naming
    /// the set rather than a minimum is what lets the table say *this domain
    /// must not map this region*, which no other attribute of a `<map>` can
    /// express: a withheld mapping has no element to carry a rule. Both
    /// directions are findings, because a grant that appeared and a grant that
    /// vanished are the two ways this file stops meaning what the code assumes.
    grants: &'static [Grant],
    /// The sentence elsewhere in the repository that this row's *exclusions*
    /// are what make true, where one exists. `None` where no domain's absence
    /// is claimed anywhere and the region simply has no other user; `Some` is
    /// quoted into the finding, so a widened grant reports what the widening
    /// costs rather than what to type. A claim on a rule that withholds its
    /// region from nobody is a defect in the rule, and is tested for.
    ///
    /// It is about exclusion alone: where what a rule withholds is an
    /// authority rather than a mapping — `cfg`, `cfgack` — the withholding
    /// lives in a [`Grant`]'s perms and there is nothing for this field to say.
    withheld: Option<&'static str>,
}

impl RegionRule {
    /// What this rule admits `domain` to do, or `None` where it admits nothing
    /// at all — the case [`check_region_mappers`] reports.
    fn grant(&self, domain: &str) -> Option<&Grant> {
        self.grants.iter().find(|grant| grant.domain == domain)
    }

    /// The domains this rule grants the region to, as a finding has to read it.
    /// The empty set is spelled out rather than printed as `[]`: a region
    /// reachable by no domain is the interesting case, and a bare pair of
    /// brackets reads as a rule with something missing.
    fn granted_to(&self) -> String {
        if self.grants.is_empty() {
            return "no protection domain at all".to_owned();
        }
        format!(
            "{:?}",
            self.grants
                .iter()
                .map(|grant| grant.domain)
                .collect::<Vec<_>>()
        )
    }
}

/// What a pool region's exclusions buy, quoted into the finding that reports
/// one being widened. Shared by both pools because the argument is the same
/// one twice, and the two must never drift apart: a check that defended pool 0
/// and not pool 1 would defend neither direction of traffic.
///
/// The forwarder is deliberately **not** among the domains this withholds a
/// pool from, and has not been since routing landed: `RouteStage` rewrites a
/// frame's Ethernet and IPv4 headers in the buffer they arrived in, which is a
/// grant that was decided and human-approved rather than acquired.
/// What the region split still establishes is [`RETURN_WITHHELD`], and that is
/// the load-bearing one.
const POOL_WITHHELD: &str = "the receiving driver maps no pool of its own. It hands that pool's \
     physical address to its NIC as a DMA target and dereferences no byte of it, so a mapping \
     would be authority with no use (pds/nic-driver's crate header) — and the DMA target the \
     device writes would additionally become reachable from the CPU side of the same domain. The \
     forwarder's own pool mapping is not an exclusion this rule defends: it is granted, because a \
     domain that rewrites a header must reach the bytes";

/// As [`POOL_WITHHELD`], for the log transport — the exclusion that holds
/// between the ten writing domains, and the one thing about a log region that
/// is a mapping rather than an authority.
///
/// What each pair's *perms* withhold is a different argument and is not stated
/// here: it lives in the [`Grant`]s, exactly as `cfg`/`cfgack`'s does, because
/// both domains map both regions of a pair and only the authority differs.
const LOG_WITHHELD: &str = "no writing domain maps another writing domain's ring, in either \
     direction. A compromised parser domain cannot read what a driver has said about itself, \
     cannot rewrite it, and cannot silence it by advancing a consume cursor that is not its own \
     — every pair of writing domains is disjoint here, and this row is what makes that true \
     (systems/qemu-x86_64/librefirewall.system, beside the log regions)";

/// What the management port's regions withhold, and it is the isolation
/// required of a port that carries no forwarded traffic: the
/// mutual exclusion between that port and the dataplane. Quoted into the
/// finding on either half being widened, because either half alone would leave
/// the property untrue.
const MANAGEMENT_WITHHELD: &str = "the forwarder maps no management region and the management      domain maps no dataplane one. The design isolates the management port from the dataplane      and gives it no forwarded traffic, and that isolation is exactly this mutual exclusion — a      frame cannot cross between the two because no domain is granted a region on both sides of      it. A dataplane grant appearing on the management domain would put the domain that will one      day terminate an operator's session on the path of every frame in flight; a management grant      appearing on the forwarder would let the routing stage reach a port that is meant to be      unreachable from it";

/// As [`MANAGEMENT_WITHHELD`], for the management port's transmit pipeline — the
/// three regions a reply travels out on, and what keeps the dataplane off them.
const MANAGEMENT_TRANSMIT_WITHHELD: &str = "the forwarder maps no part of the management port's \
     transmit pipeline, and the management domain and its driver instance are the only domains \
     that map any of it. The two sit at opposite ends of it: the management domain OWNS this pool \
     — it allocates a buffer, writes a reply into it, lends it, and consumes the returns — and the \
     driver maps the pool to write the virtio-net header in front of the frame and produces those \
     returns. A grant to the forwarder would put a dataplane domain on a port the design makes \
     unreachable from it, and a grant to any third domain would be a second writer of a pool that \
     has one owner";

/// As [`POOL_WITHHELD`], for the management port's receive pool: the one pool in
/// this description whose mapper holds it READ-ONLY.
const MANAGEMENT_RECEIVE_POOL_WITHHELD: &str = "the driver that receives into this pool maps no \
     part of it, and the domain that reads it cannot write it. The driver is granted the physical \
     address alone (pds/nic-driver's crate header) — a mapping would additionally make the DMA \
     target the device writes reachable from the CPU side of the same domain — and the management \
     domain maps it READ-ONLY, because a frame this appliance was sent is parsed and never \
     altered: a reply is composed in storage of that domain's own and copied into a buffer of the \
     *transmit* pool. Read-write here would be authority to rewrite a frame under the decision \
     that inspected it, for a use no code has";

/// As [`POOL_WITHHELD`], for the return rings — the exclusion the forwarder's
/// isolation now rests on entirely.
const RETURN_WITHHELD: &str = "the forwarder maps no return ring. It is a region of its own \
     rather than a third field beside `ForwardRings` precisely so that it can be withheld \
     (pd_runtime's `ReturnRing`: \"what denies the forwarder the ability to forge a return — the \
     one move that would put a live buffer back on an owner's free stack\"), and a forwarder that \
     could produce on it would be a second producer on a ring that admits exactly one. This is \
     what a compromised forwarder is still unable to do: it can corrupt a frame in flight, and it \
     cannot hand a live DMA target back to be issued a second time";

/// What the block device's four regions withhold, quoted into the finding on
/// any of them gaining a second mapper.
///
/// It is the mirror image of the NIC regions' exclusions, and the sentence
/// worth having is the one about the direction nobody asks for: not only does
/// no other domain reach the medium, this domain reaches no wire.
const RECORDER_DEVICE_WITHHELD: &str = "the recorder is the only domain that maps any part of \
     the block device, and it maps no part of any network one. No other domain holds its ECAM \
     page, its BAR window, its DMA region or its staging window, so nothing else in this system \
     can put a byte on persistent storage or read one back — and this domain holds no ecam0..2, \
     no bar0..2, no vq0..2, no buffer pool of either dataplane or management pipeline, no \
     `ForwardRings`, no `ReturnRing` and no `<ioport>`, so an attacker who reaches the domain \
     that owns the disk reaches no network device by doing so. The staging window in particular \
     is withheld from the management domain deliberately rather than by omission: a download is \
     answered out of `dl_reply`, a bounded copy the recorder composed, because a read grant here \
     would expose whatever that domain happened to be staging at the time";

/// As [`RECORDER_DEVICE_WITHHELD`], for the store device — and it is the
/// strongest exclusion in this table, because what it withholds is the
/// appliance's private key.
///
/// The scalar is plaintext on that medium, deliberately and for want of anywhere
/// to keep a wrapping key, so physical possession of the store IS identity theft.
/// This row is what makes possession the only way to it: the store domain maps
/// the whole of the second block device and no other domain maps any part of it,
/// so nothing else in this system can read the key or write another one. The
/// RECORDER in particular is excluded, and that is the pair worth naming — two
/// block devices, two domains, neither reaching the other's — because a shared
/// grant would put the scalar within reach of the domain a download request
/// reaches and the recording within reach of the domain that holds the scalar.
const STORE_DEVICE_WITHHELD: &str = "the store domain is the only domain that maps any part of \
     the appliance's own store device, and it maps no part of any other device. No other domain \
     holds its ECAM page, its BAR window, its DMA region or its staging window — the RECORDER \
     included, which owns the other block device and reaches none of this one — so nothing else \
     in this system can read the appliance's private scalar or write an identity over it. And \
     this domain holds no ecam0..3, no bar0..3, no blk_dma, no blk_io, no vq0..2, no buffer pool \
     of either dataplane or management pipeline, no `ForwardRings`, no `ReturnRing`, no \
     configuration region, no tap, no download region and no `<ioport>`, so an attacker who \
     reaches the domain holding the device key reaches nothing else by doing so. The one thing \
     it now holds beyond the device is the signing delegation, whose peer is the cryptography \
     domain — which holds no network region of any kind — so there is still no path from a \
     packet to those bytes: a compromise would have to traverse a domain no frame reaches, to \
     arrive at an ABI with no field for a key";

/// What the signing delegation's two regions withhold, and it is the one claim in
/// this table whose subject is a thing that must *not* be able to cross.
///
/// The property is a conjunction and neither half establishes it: `wire::signing`
/// has no field for a private key in either direction, so there is nothing to put
/// one in; and the store domain is the only writer of the reply, so the only bytes
/// the cryptography domain can read are ones that domain chose to publish. An ABI
/// that could carry a key would carry it through perfectly correct grants, and
/// grants alone would leave a domain free to write one into a region it shares.
/// This rule is the half a checker can hold — the type system holds the other —
/// and it is quoted into the finding on either region gaining a mapper.
const SIGNING_WITHHELD: &str = "exactly two domains map the signing delegation, and no third \
     maps either half in either direction. The FORWARDER above all: a dataplane domain able to \
     write `sign_request` would have the appliance's own key sign bytes of its choosing, which \
     is the one thing a signing oracle must not be. No driver, no recorder, no console, and — \
     deliberately rather than pending — not the management domain: when it terminates sessions \
     it asks over a channel granted and reviewed then. Between the two that do map it the \
     withholding is in the perms, and it is what makes a forged authentication \
     unrepresentable: the cryptography domain states the request and CANNOT WRITE THE REPLY, so \
     it cannot publish a signature the device key never produced and then present it as the \
     appliance's; and the store domain answers and cannot write the question. The key itself \
     cannot cross either region, which is a property of this row TOGETHER WITH the ABI — \
     `wire::signing` has no field a 32-byte scalar fits in, in either direction, and this row is \
     what makes the holder the only party that chooses what the asking domain reads";

/// What the onboarding package's staging region withholds, and why the one edge
/// it does open is one this system can afford.
///
/// It is the only region written by the domain an unauthenticated peer talks to
/// and read by the domain that holds the device key, so the direction is worth
/// stating rather than leaving to be noticed. Three things make it safe, and the
/// checker holds only the first:
///
/// * **The grant.** Exactly two domains, and the perms are the asymmetry: the
///   store domain cannot write here, so it cannot install an archive nobody
///   uploaded; the cryptography domain cannot read the verdict into existence,
///   the reply being a region it may only read.
/// * **The reader's snapshot.** The store domain copies the whole region into
///   its own `blk2_io` window before it looks at a byte, so every rule is applied
///   to bytes the writer can no longer reach — which is what makes "the archive
///   that passed is the archive that was written" true against a writer that
///   keeps writing.
/// * **What crosses.** A byte string and nothing else. No address, no
///   descriptor, no pointer and no length the reader believes: the length is a
///   word of the request and is ranged against this region's own extent.
const INSTALL_STAGING_WITHHELD: &str = "exactly two domains map the onboarding package's staging      region, and no third maps it in either direction — no driver, no forwarder, no recorder, no      console, no configuration domain, and NOT THE MANAGEMENT DOMAIN, which owns the port the      upload arrives on and hands the session's bytes to the cryptography domain rather than      placing them here itself. Between the two that do map it the withholding is in the perms,      and this is the one row where the WRITER is the domain an unauthenticated peer talks to: it      may fill this region and may not read the answer, and the store domain — which holds the      device key and owns the medium an ownership is written to — may read it and CANNOT WRITE IT,      so it cannot install an archive nobody uploaded. What makes the direction affordable is not      this row alone: the reader snapshots the whole region into its own staging window before it      applies a rule, so what it validates is bytes the writer can no longer reach, and what      crosses is a byte string with no address, no descriptor and no pointer in it";

/// What the TLS relay's two regions withhold, and why the pair widens nothing.
///
/// The bytes that cross are ciphertext the management domain already carried: one
/// direction is what a peer put on the wire and that domain read off it, the
/// other is what it is about to put back. So the grant costs that domain nothing
/// it did not have. What it must not reach is everything behind those bytes — the
/// arena, the device key, the session secrets, every decrypted byte — and none of
/// that has a field in `wire::relay` in either direction.
///
/// The half a checker can hold is the mapper set and the perms. A third mapper
/// would be a domain reading an operator's session; and between the two that do
/// map it, a management domain able to write the reply could put bytes of its own
/// choosing on the wire as though the terminating end had produced them, which
/// under the appliance's own identity is a forgery rather than a wrong answer.
const RELAY_WITHHELD: &str = "exactly two domains map the TLS relay, and no third maps either \
     half in either direction — no driver, no forwarder, no recorder, no console, no \
     configuration domain, and NOT THE STORE DOMAIN, which holds the private scalar and must \
     map no region a frame's bytes reach. Between the two that do map it the withholding is in \
     the perms: the management domain states what arrived and CANNOT WRITE THE REPLY, so it \
     cannot put records of its own choosing on the wire as though the terminating end had \
     produced them; and the cryptography domain answers and cannot write the question. What \
     crosses is ciphertext the management domain already carried or is about to carry, so this \
     pair widens that domain's reach over nothing — and what stays behind it, the arena, the \
     key, the session secrets and every plaintext byte, has no field in `wire::relay` to cross \
     in";

/// What the connection table's single mapper buys, quoted into the finding on it
/// gaining a second one.
///
/// This is the one exclusion in this table that a *soundness* argument rests on
/// rather than an isolation one. Everywhere else a second mapper would widen
/// authority; here it would make the forwarder's `&mut` to the region undefined
/// behaviour, because that borrow's whole justification is that no other holder
/// of those bytes exists.
const FLOW_TABLE_WITHHELD: &str = "the forwarder is the ONLY domain that maps the connection \
     table, and it is the only region in this system a domain borrows MUTABLY. Every other region \
     is shared, so its type exposes no safe path to its own bytes and a `&` is sound whatever the \
     peers do; a `FlowTable` is an ordinary Rust value with methods taking `&mut self`, and \
     `pd_runtime::attach_flow_table!` forms a `&mut` to it on the strength of this row naming one \
     grant. A second mapper of any kind — read-only included — would make that reference \
     undefined rather than merely contended, so this is not an isolation preference but the \
     premise of the borrow. It also carries no `phys_addr`, so no driver can be handed its \
     address and no device can reach it by DMA either";

/// What the ownership word withholds, which is an authority rather than a
/// mapping: exactly one domain may say this appliance has an owner.
const OWNERSHIP_WITHHELD: &str = "the store domain is the ONLY writer of the word that decides \
     whether this appliance forwards anything, and the forwarder the only reader. The write \
     grant is withheld from every other domain including the forwarder itself, because a \
     forwarder that could write it could onboard the appliance it decides traffic for; and the \
     read grant is withheld from the domains that would otherwise be tempted to act on it — the \
     configuration domain, so ownership cannot become a table composed by the parser that reads \
     an attacker's document, and the management domain, so the domain facing the management-plane \
     attacker cannot learn from a mapping what it can already learn by asking the store domain \
     for the identity. No `phys_addr`, so no device reaches it by DMA either";

/// What the management endpoint withholds, which is an authority in one
/// direction and a piece of knowledge in the other.
const ENDPOINT_WITHHELD: &str = "the store domain is the ONLY writer of the address this \
     appliance dials, and the management domain the only reader. The write grant is withheld from \
     every other domain including the management domain itself, because a domain that could write \
     it could point the appliance's own management channel at a peer of its choosing — which is \
     the one thing an attacker who reached that domain would most want. The read grant is \
     withheld from the configuration domain, so where this appliance reports to cannot become a \
     value composed by the parser that reads an attacker's document; and from the forwarder, \
     which decides frames, so a compromised dataplane cannot tell an operator's session from the \
     traffic around it. What a read here confers is an address literal and a port and nothing \
     else — values the management server publishes to every appliance it owns and that appear in \
     the clear on the wire — so the grant is narrow because what it carries authenticates \
     nothing. No `phys_addr`, so no device reaches it by DMA either";

/// What the capture tap's two regions withhold — the mirrored permissions that
/// make a stored capture the forwarder's testimony rather than the recorder's.
const TAP_WITHHELD: &str = "exactly two domains map the tap, and no third maps either half in \
     either direction: no driver, so a compromised driver cannot see what was decided about the \
     frames it delivered; not the management domain, so the domain that answers a download \
     cannot read the ring ahead of the recorder or write into it; and not the console, which \
     keeps the two output channels disjoint. What the perms withhold between the two that do map \
     it is the other half and is stated in the grants: the forwarder produces and cannot move the \
     consume cursor, so it cannot discard observations while reporting none lost, and the \
     recorder consumes and cannot write a record, so it cannot commit to the medium an \
     observation the forwarding domain never made";

/// What the download handover's two regions withhold, on the tap's terms and
/// with the forwarder's exclusion as the load-bearing half.
const DOWNLOAD_WITHHELD: &str = "the forwarder maps NEITHER download region, in either \
     direction, which is the counterpart of it mapping no `blk_io`: the dataplane can neither see \
     what an operator is downloading nor influence what comes back. A forwarder able to write \
     `dl_reply` would answer a download with bytes of its own while the recorder reported having \
     served the medium's. No driver and no console maps either half. Between the two domains that \
     do, the withholding is in the perms: the management domain states the request and cannot \
     write the answer, and the recorder answers and cannot write the question";

/// What `cfg` having two readers and `cfgack` one writer withholds, quoted into
/// the finding on the management domain gaining the acknowledgement region.
/// What the submission channel's two rows withhold, in both directions at once.
const CONFIG_SUBMISSION_WITHHELD: &str = "the FORWARDER maps NEITHER submission region, in \
     either direction, and neither does any driver or the recorder: a document on its way to \
     being decided is not something a dataplane domain has any use for, and a forwarder able to \
     write `cfg_reply` could answer an operator's `GET /config` with a policy the appliance is \
     not running. The two mappers are the two ends of one conversation and the perms carry which \
     end speaks in which direction";

const CONFIG_ACK_WITHHELD: &str = "the management domain reads `cfg` and maps `cfgack` NOT AT \
     ALL, which is what makes it a weaker consumer of the handover than the forwarder rather than \
     a second one. The forwarder is the consumer of the two-phase commit: it reads the OFFERED \
     generation, stages a table and acknowledges, and a commit waits for that acknowledgement. \
     The management domain reads the COMMITTED generation alone \
     (`pd_runtime::CommittedReader`), so it cannot delay a commit, cannot refuse one on anybody's \
     behalf, and holds no region an acknowledgement could be forged in. A `cfgack` grant here \
     would make 'every consumer has staged' a conjunction over two domains and hand the domain \
     that answers the management-plane attacker the word that releases a generation";

/// Every memory region the description may declare, and what each one owes the
/// code. A region absent from this table fails the gate; so does a rule here
/// that matches no region, because a rule defending nothing reads as coverage.
const REGIONS: &[RegionRule] = &[
    // The two ECAM pages. Their extent is fixed by PCIe rather than by us, but
    // that is what makes the row load-bearing rather than ceremonial:
    // `PciConfig::new`'s safety contract is stated in terms of "the mapped
    // 4 KiB ECAM page", and pds/nic-driver names this file as what guarantees
    // it. A short region truncates the mapping the whole capability-pointer
    // walk is bounded against.
    RegionRule {
        name: "ecam0",
        size: ExpectedSize {
            rust_name: "virtio::pci::PCI_CONFIG_LEN",
            bytes: PCI_CONFIG_LEN,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("nic_driver0")],
        withheld: None,
    },
    RegionRule {
        name: "ecam1",
        size: ExpectedSize {
            rust_name: "virtio::pci::PCI_CONFIG_LEN",
            bytes: PCI_CONFIG_LEN,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("nic_driver1")],
        withheld: None,
    },
    RegionRule {
        name: "ecam2",
        size: ExpectedSize {
            rust_name: "virtio::pci::PCI_CONFIG_LEN",
            bytes: PCI_CONFIG_LEN,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("nic_driver2")],
        withheld: None,
    },
    RegionRule {
        name: "bar0",
        size: ExpectedSize {
            rust_name: "nic_driver_core::bringup::BAR_WINDOW_SIZE",
            bytes: BAR_WINDOW_SIZE,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("nic_driver0")],
        withheld: None,
    },
    RegionRule {
        name: "bar1",
        size: ExpectedSize {
            rust_name: "nic_driver_core::bringup::BAR_WINDOW_SIZE",
            bytes: BAR_WINDOW_SIZE,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("nic_driver1")],
        withheld: None,
    },
    RegionRule {
        name: "bar2",
        size: ExpectedSize {
            rust_name: "nic_driver_core::bringup::BAR_WINDOW_SIZE",
            bytes: BAR_WINDOW_SIZE,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("nic_driver2")],
        withheld: None,
    },
    // The block device's four regions. Its ECAM page and BAR window are the same
    // two kinds of grant the NIC drivers hold, and the constants they are
    // compared against are deliberately `lfw_blk`'s own rather than
    // `nic_driver_core`'s: the two are independent device classes with
    // independent bounds, and citing one for the other would let a change to
    // either move the other's mapped window with nothing failing. That the two
    // BAR windows are the same number today is a coincidence neither crate
    // promises.
    RegionRule {
        name: "ecam3",
        size: ExpectedSize {
            rust_name: "virtio::pci::PCI_CONFIG_LEN",
            bytes: PCI_CONFIG_LEN,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("recorder")],
        withheld: Some(RECORDER_DEVICE_WITHHELD),
    },
    RegionRule {
        name: "bar3",
        size: ExpectedSize {
            rust_name: "lfw_blk::BAR_WINDOW_SIZE",
            bytes: BLK_BAR_WINDOW_SIZE,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("recorder")],
        withheld: Some(RECORDER_DEVICE_WITHHELD),
    },
    RegionRule {
        name: "blk_dma",
        size: ExpectedSize {
            rust_name: "lfw_blk::DMA_REGION_SIZE",
            bytes: BLK_DMA_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("recorder")],
        withheld: Some(RECORDER_DEVICE_WITHHELD),
    },
    RegionRule {
        name: "blk_io",
        size: ExpectedSize {
            rust_name: "lfw_blk::BLK_IO_REGION_SIZE",
            bytes: BLK_IO_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("recorder")],
        withheld: Some(RECORDER_DEVICE_WITHHELD),
    },
    // The store device's four regions — a SECOND block device, not a second view
    // of the recorder's. Every rule names one domain, and the recorder is not
    // it: that mutual exclusion is what keeps the private scalar out of reach of
    // the domain a download request reaches, and the recording out of reach of
    // the domain that holds the scalar.
    RegionRule {
        name: "ecam4",
        size: ExpectedSize {
            rust_name: "virtio::pci::PCI_CONFIG_LEN",
            bytes: PCI_CONFIG_LEN,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("store")],
        withheld: Some(STORE_DEVICE_WITHHELD),
    },
    RegionRule {
        name: "bar4",
        size: ExpectedSize {
            rust_name: "lfw_blk::BAR_WINDOW_SIZE",
            bytes: BLK_BAR_WINDOW_SIZE,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("store")],
        withheld: Some(STORE_DEVICE_WITHHELD),
    },
    RegionRule {
        name: "blk2_dma",
        size: ExpectedSize {
            rust_name: "lfw_blk::DMA_REGION_SIZE",
            bytes: BLK_DMA_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("store")],
        withheld: Some(STORE_DEVICE_WITHHELD),
    },
    RegionRule {
        name: "blk2_io",
        size: ExpectedSize {
            rust_name: "lfw_blk::BLK_IO_REGION_SIZE",
            bytes: BLK_IO_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("store")],
        withheld: Some(STORE_DEVICE_WITHHELD),
    },
    // The timer block, and the one region whose rule cites a constant that is
    // NOT the extent of the thing inside it. `lfw_hpet::MMIO_LENGTH` is the
    // register block: 0x400 bytes, which is what that crate addresses within
    // and what its offset assertions are stated against. It is not what a grant
    // can be — Microkit maps pages — so the crate derives `MMIO_REGION_SIZE`
    // from it exactly as `wire` derives a log region's size from the type
    // inside it, and that is the constant this row compares. Citing
    // `MMIO_LENGTH` here would fail on a description no operator could fix, and
    // citing `pd_runtime::MAPPING_ALIGN` would compare the grant against the
    // page size — a number that agrees with this one by coincidence and would
    // go on agreeing if the block moved or grew.
    RegionRule {
        name: "hpet",
        size: ExpectedSize {
            rust_name: "lfw_hpet::MMIO_REGION_SIZE",
            bytes: MMIO_REGION_SIZE,
        },
        cacheability: Cacheability::Uncached,
        grants: &[read_write("clock")],
        withheld: None,
    },
    RegionRule {
        name: "vq0",
        size: ExpectedSize {
            rust_name: "nic_driver_core::bringup::VQ_REGION_SIZE",
            bytes: VQ_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver0")],
        withheld: None,
    },
    RegionRule {
        name: "vq1",
        size: ExpectedSize {
            rust_name: "nic_driver_core::bringup::VQ_REGION_SIZE",
            bytes: VQ_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver1")],
        withheld: None,
    },
    RegionRule {
        name: "vq2",
        size: ExpectedSize {
            rust_name: "nic_driver_core::bringup::VQ_REGION_SIZE",
            bytes: VQ_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2")],
        withheld: None,
    },
    // The six regions one pipeline each direction is granted as. Port 0
    // receives into pool0 and transmits out of pool1, so the *driver* that maps
    // a pool is always the one that did not receive into it — which is why the
    // two pools' mapper sets are each other's mirror rather than each other's
    // copy. The forwarder maps both, being the domain that rewrites headers in
    // either direction.
    RegionRule {
        name: "pool0",
        size: ExpectedSize {
            rust_name: "pd_runtime::POOL_REGION_SIZE",
            bytes: POOL_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("forwarder"), read_write("nic_driver1")],
        withheld: Some(POOL_WITHHELD),
    },
    RegionRule {
        name: "fwd0",
        size: ExpectedSize {
            rust_name: "pd_runtime::FORWARD_REGION_SIZE",
            bytes: FORWARD_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[
            read_write("forwarder"),
            read_write("nic_driver0"),
            read_write("nic_driver1"),
        ],
        withheld: None,
    },
    RegionRule {
        name: "free0",
        size: ExpectedSize {
            rust_name: "pd_runtime::RETURN_REGION_SIZE",
            bytes: RETURN_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver0"), read_write("nic_driver1")],
        withheld: Some(RETURN_WITHHELD),
    },
    RegionRule {
        name: "pool1",
        size: ExpectedSize {
            rust_name: "pd_runtime::POOL_REGION_SIZE",
            bytes: POOL_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("forwarder"), read_write("nic_driver0")],
        withheld: Some(POOL_WITHHELD),
    },
    RegionRule {
        name: "fwd1",
        size: ExpectedSize {
            rust_name: "pd_runtime::FORWARD_REGION_SIZE",
            bytes: FORWARD_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[
            read_write("forwarder"),
            read_write("nic_driver0"),
            read_write("nic_driver1"),
        ],
        withheld: None,
    },
    RegionRule {
        name: "free1",
        size: ExpectedSize {
            rust_name: "pd_runtime::RETURN_REGION_SIZE",
            bytes: RETURN_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver0"), read_write("nic_driver1")],
        withheld: Some(RETURN_WITHHELD),
    },
    // The management port's two pipelines. The shapes are the dataplane's and
    // the constants are the same three, and what differs is the far end of the
    // receive one: there is no egress driver, so the management domain is what
    // produces the returns and mgmt_rx_free is granted to it read-write. That is
    // the same producer/consumer split free0 and free1 already have between two
    // drivers — which is why this rule's exclusion is MANAGEMENT_WITHHELD, the
    // dataplane mutual exclusion, and not RETURN_WITHHELD.
    //
    // mgmt_rx_pool is read by the management domain and written by nothing with a
    // CPU: the frame it parses is copied out of that pool, and the reply goes
    // into the transmit pool it owns. The transmit three are that pool and its
    // rings, with the two domains at opposite ends of each — the management
    // domain owning the pool and consuming the returns, the driver writing the
    // device header and producing them.
    RegionRule {
        name: "mgmt_rx_pool",
        size: ExpectedSize {
            rust_name: "pd_runtime::POOL_REGION_SIZE",
            bytes: POOL_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("management")],
        withheld: Some(MANAGEMENT_RECEIVE_POOL_WITHHELD),
    },
    RegionRule {
        name: "mgmt_rx_fwd",
        size: ExpectedSize {
            rust_name: "pd_runtime::FORWARD_REGION_SIZE",
            bytes: FORWARD_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2"), read_write("management")],
        withheld: Some(MANAGEMENT_WITHHELD),
    },
    RegionRule {
        name: "mgmt_rx_free",
        size: ExpectedSize {
            rust_name: "pd_runtime::RETURN_REGION_SIZE",
            bytes: RETURN_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2"), read_write("management")],
        withheld: Some(MANAGEMENT_WITHHELD),
    },
    RegionRule {
        name: "mgmt_tx_pool",
        size: ExpectedSize {
            rust_name: "pd_runtime::POOL_REGION_SIZE",
            bytes: POOL_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2"), read_write("management")],
        withheld: Some(MANAGEMENT_TRANSMIT_WITHHELD),
    },
    RegionRule {
        name: "mgmt_tx_fwd",
        size: ExpectedSize {
            rust_name: "pd_runtime::FORWARD_REGION_SIZE",
            bytes: FORWARD_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2"), read_write("management")],
        withheld: Some(MANAGEMENT_TRANSMIT_WITHHELD),
    },
    RegionRule {
        name: "mgmt_tx_free",
        size: ExpectedSize {
            rust_name: "pd_runtime::RETURN_REGION_SIZE",
            bytes: RETURN_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2"), read_write("management")],
        withheld: Some(MANAGEMENT_TRANSMIT_WITHHELD),
    },
    // The configuration handover, and the one place in this description where
    // what a rule withholds is an authority rather than a mapping: both domains
    // map both regions, and each may write exactly the one it speaks in. That
    // is why a rule's perms are per grant. A `cfg` the forwarder could write
    // would let it rewrite the table it is about to be held to and leave the
    // publisher reporting a generation nobody runs; a `cfgack` the config
    // domain could write would let it forge the acknowledgement that releases
    // its own generation, which is the whole of what the second phase is for.
    // `cfg` has a second reader and `cfgack` still one writer, and that is where
    // the claim sits: the management domain reads the committed generation to
    // learn its own addressing and takes no part in the commit, so a `cfgack`
    // grant to it is the edit CONFIG_ACK_WITHHELD refuses. On `cfg` itself no
    // exclusion is claimed — a driver has no more use for a configuration image
    // than for a parser — so the perms carry the argument there.
    //
    // The recorder is not a reader, and the row is the reason it cannot become
    // one by accident: it held this grant while attaching the region nowhere and
    // compiling its interface names in, so the authority existed and no code
    // consumed it. A grant ahead of its consumer is a grant nothing reviews
    // against a use, and this table is where the two are made one statement — so
    // the change that starts reading the document adds the grant back in the
    // same breath as the code that needs it.
    RegionRule {
        name: "cfg",
        size: ExpectedSize {
            rust_name: "wire::CONFIG_REGION_SIZE",
            bytes: CONFIG_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[
            read_write("config"),
            read_only("forwarder"),
            read_only("management"),
        ],
        withheld: None,
    },
    // The calibration: three words published under a seqlock, written by the
    // domain that measured them and read by every domain that converts a counter
    // reading with them — which, since a log record carries the instant it was
    // emitted at, is all of them. What this rule withholds is therefore an
    // authority and not a mapping, so it lives in the perms and `withheld` has
    // nothing to say (see the field's own note); the system description carries
    // what the one-writer direction is worth.
    RegionRule {
        name: "clock",
        size: ExpectedSize {
            rust_name: "wire::CLOCK_CALIBRATION_REGION_SIZE",
            bytes: CLOCK_CALIBRATION_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[
            read_write("clock"),
            read_only("config"),
            read_only("console"),
            read_only("forwarder"),
            read_only("hardware_probe"),
            read_only("crypto"),
            read_only("management"),
            read_only("nic_driver0"),
            read_only("nic_driver1"),
            read_only("nic_driver2"),
            read_only("recorder"),
            read_only("store"),
        ],
        withheld: None,
    },
    // The ownership word: one writer, one reader, and no channel — the reader is
    // woken by the frames it decides on, so it reads this on a wakeup it was
    // going to have. As with `clock`, what this rule withholds is an authority
    // and not a mapping, so the perms carry the argument and `withheld` states
    // the exclusion the perms cannot.
    RegionRule {
        name: "owner",
        size: ExpectedSize {
            rust_name: "wire::OWNERSHIP_REGION_SIZE",
            bytes: OWNERSHIP_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("store"), read_only("forwarder")],
        withheld: Some(OWNERSHIP_WITHHELD),
    },
    // Where the appliance dials: one writer, one reader, and no channel — the
    // reader is woken on a period and by its own port's traffic, so it reads this
    // on a wakeup it was going to have. As with `owner`, what this rule withholds
    // is an authority and a piece of knowledge rather than a mapping, so the perms
    // carry half the argument and `withheld` states the exclusions they cannot.
    RegionRule {
        name: "endpoint",
        size: ExpectedSize {
            rust_name: "wire::ENDPOINT_REGION_SIZE",
            bytes: ENDPOINT_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("store"), read_only("management")],
        withheld: Some(ENDPOINT_WITHHELD),
    },
    RegionRule {
        name: "cfgack",
        size: ExpectedSize {
            rust_name: "wire::CONFIG_ACK_REGION_SIZE",
            bytes: CONFIG_ACK_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("config"), read_write("forwarder")],
        withheld: Some(CONFIG_ACK_WITHHELD),
    },
    // The connection table: one region, one mapper, and the only `&mut` borrow of
    // a region anywhere in this system.
    RegionRule {
        name: "flow_table",
        size: ExpectedSize {
            rust_name: "pd_runtime::FLOW_TABLE_REGION_SIZE",
            bytes: FLOW_TABLE_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("forwarder")],
        withheld: Some(FLOW_TABLE_WITHHELD),
    },
    // The capture tap, and the download handover: two more two-region handovers
    // built the way `cfg`/`cfgack` and every log ring are, and read here the same
    // way. In both, the two rows of a pair are each other's mirror, and a pair
    // that stopped mirroring is the edit these rules exist to refuse.
    RegionRule {
        name: "tap",
        size: ExpectedSize {
            rust_name: "wire::TAP_RECORDS_REGION_SIZE",
            bytes: TAP_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("forwarder"), read_only("recorder")],
        withheld: Some(TAP_WITHHELD),
    },
    RegionRule {
        name: "tap_consume",
        size: ExpectedSize {
            rust_name: "wire::TAP_CONSUME_REGION_SIZE",
            bytes: TAP_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("forwarder"), read_write("recorder")],
        withheld: Some(TAP_WITHHELD),
    },
    // The configuration submission channel: the same two-region mirror, and the
    // pair whose direction carries the most. `cfg_request` is management's to write
    // because a document arrives on a TCP connection it terminates; `cfg_reply` is
    // the config domain's, because it holds the datastore and is the only domain
    // that can say what is running. Crossing either is the finding: a config domain
    // able to write the request would decide on bytes nobody submitted, and a
    // management domain able to write the reply would answer `GET /config` with a
    // document the appliance is not running — which an operator would then edit and
    // submit, so a fabricated statement about the policy in force is worse than a
    // wrong one.
    //
    // The direction of *parsing* is what the exclusion below claims, and it is the
    // whole reason the config domain exists: the domain that reads an attacker's
    // XML holds no frame buffer, and the domain that holds two frame pipelines
    // reads none of it.
    RegionRule {
        name: "cfg_request",
        size: ExpectedSize {
            rust_name: "wire::CONFIG_REQUEST_REGION_SIZE",
            bytes: CONFIG_REQUEST_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("management"), read_only("config")],
        withheld: Some(CONFIG_SUBMISSION_WITHHELD),
    },
    RegionRule {
        name: "cfg_reply",
        size: ExpectedSize {
            rust_name: "wire::CONFIG_REPLY_REGION_SIZE",
            bytes: CONFIG_REPLY_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("management"), read_write("config")],
        withheld: Some(CONFIG_SUBMISSION_WITHHELD),
    },
    RegionRule {
        name: "dl_request",
        size: ExpectedSize {
            rust_name: "wire::DOWNLOAD_REQUEST_REGION_SIZE",
            bytes: DOWNLOAD_REQUEST_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("management"), read_only("recorder")],
        withheld: Some(DOWNLOAD_WITHHELD),
    },
    RegionRule {
        name: "dl_reply",
        size: ExpectedSize {
            rust_name: "wire::DOWNLOAD_REPLY_REGION_SIZE",
            bytes: DOWNLOAD_REPLY_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("management"), read_write("recorder")],
        withheld: Some(DOWNLOAD_WITHHELD),
    },
    // The signing delegation, the download handover's split with the roles
    // exchanged: the domain that asks writes the question and reads the answer,
    // and the domain that holds the key writes the answer and reads the question.
    RegionRule {
        name: "sign_request",
        size: ExpectedSize {
            rust_name: "wire::SIGN_REQUEST_REGION_SIZE",
            bytes: SIGN_REQUEST_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("crypto"), read_only("store")],
        withheld: Some(SIGNING_WITHHELD),
    },
    RegionRule {
        name: "sign_reply",
        size: ExpectedSize {
            rust_name: "wire::SIGN_REPLY_REGION_SIZE",
            bytes: SIGN_REPLY_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("crypto"), read_write("store")],
        withheld: Some(SIGNING_WITHHELD),
    },
    // The onboarding package's staging region, beside the delegation it is
    // asked about over. It is the delegation's third region rather than a pair
    // of its own: nothing is answered here, so there is no reverse direction to
    // grant.
    RegionRule {
        name: "install_staging",
        size: ExpectedSize {
            rust_name: "wire::INSTALL_STAGING_REGION_SIZE",
            bytes: INSTALL_STAGING_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("crypto"), read_only("store")],
        withheld: Some(INSTALL_STAGING_WITHHELD),
    },
    // The TLS relay, the signing delegation's split between a different pair of
    // domains: the one that owns the network writes what arrived and reads what
    // to send, and the one that terminates the session writes the answer and
    // reads the question.
    RegionRule {
        name: "relay_request",
        size: ExpectedSize {
            rust_name: "wire::RELAY_REQUEST_REGION_SIZE",
            bytes: RELAY_REQUEST_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("management"), read_only("crypto")],
        withheld: Some(RELAY_WITHHELD),
    },
    RegionRule {
        name: "relay_reply",
        size: ExpectedSize {
            rust_name: "wire::RELAY_REPLY_REGION_SIZE",
            bytes: RELAY_REPLY_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("management"), read_write("crypto")],
        withheld: Some(RELAY_WITHHELD),
    },
    // The log transport: one ring per writing domain, split into two regions so
    // the two directions can carry opposite authority. Every pair below is the
    // same two rows twice over, and the pattern is the whole of the design:
    //
    //  * `log_<domain>` holds the slots and the producer cursor. The writer has
    //    it read-write and the console read-only, so the console cannot store
    //    into a slot, cannot advance the cursor that publishes one, and cannot
    //    rewrite the count of what that domain says it lost. A console that
    //    could would attribute a line to a domain that never emitted it — and
    //    it is the one domain whose output an operator reads as testimony about
    //    the others.
    //  * `log_<domain>_consume` holds the console's consume cursor and nothing
    //    else. The console has it read-write and the writer read-only, so a
    //    writer cannot forge how much of its own ring has been read: one that
    //    could would move the cursor forward to reuse slots the console had not
    //    rendered, discarding records while its own drop count stayed at zero —
    //    silent loss reported as none.
    //
    // Neither property survives the two being one region, and neither is
    // visible in a mapper set: both domains map both halves, so only the perms
    // differ, which is why a rule's perms are per grant. The two rows of a pair
    // therefore read as each other's mirror, and a pair that stopped mirroring
    // is exactly the edit these rules exist to refuse.
    RegionRule {
        name: "log_forwarder",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("forwarder"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_forwarder_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("forwarder"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_nic_driver0",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver0"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_nic_driver0_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("nic_driver0"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_nic_driver1",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver1"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_nic_driver1_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("nic_driver1"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_clock",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("clock"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_clock_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("clock"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_nic_driver2",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_nic_driver2_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("nic_driver2"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_management",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("management"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_management_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("management"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_recorder",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("recorder"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_recorder_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("recorder"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_config",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("config"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_config_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("config"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_hardware_probe",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("hardware_probe"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_hardware_probe_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("hardware_probe"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_crypto",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("crypto"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_store",
        size: ExpectedSize {
            rust_name: "wire::LOG_RECORDS_REGION_SIZE",
            bytes: LOG_RECORDS_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("store"), read_only("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_store_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("store"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    RegionRule {
        name: "log_crypto_consume",
        size: ExpectedSize {
            rust_name: "wire::LOG_CONSUME_REGION_SIZE",
            bytes: LOG_CONSUME_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("crypto"), read_write("console")],
        withheld: Some(LOG_WITHHELD),
    },
    // The metric shards: one per protection domain, each with exactly one
    // writer and — for the nine that are not the reader's own — exactly one
    // reader. The perms carry the whole argument, as `cfg`'s do: the management
    // domain renders every one of these into the exposition an operator scrapes,
    // so it must read all ten, and a grant that let it *write* one would let
    // the domain an attacker reaches first forge a clean line for a port that is
    // dropping every frame.
    RegionRule {
        name: "stats_forwarder",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("forwarder"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_nic_driver0",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver0"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_nic_driver1",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver1"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_nic_driver2",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("nic_driver2"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    // The one region in this description with a single mapper, and it is a
    // decision: the renderer walks one uniform array of ten shards rather than
    // nine regions plus a live read of its own counters, so a scrape is one set
    // of numbers taken at one publish. It costs no cross-domain authority, which
    // is why "exactly one mapper" is the rule rather than a finding.
    RegionRule {
        name: "stats_management",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_console",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("console"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_config",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("config"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_clock",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("clock"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_recorder",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("recorder"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_hardware_probe",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("hardware_probe"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_crypto",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("crypto"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    RegionRule {
        name: "stats_store",
        size: STATS_SIZE,
        cacheability: Cacheability::Cached,
        grants: &[read_write("store"), read_only("management")],
        withheld: Some(STATS_WITHHELD),
    },
    // The appliance's one allocator, and the one region with no structure.
    RegionRule {
        name: "arena_crypto",
        size: ExpectedSize {
            rust_name: "crypto::arena::ARENA_BYTES",
            bytes: ARENA_BYTES,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("crypto")],
        withheld: Some(
            "every other domain, in both directions. A TLS session's ephemeral keys live here \
             while it runs, so a second mapper would be a second reader of key material — and \
             the dataplane domains keep having no allocator at all, which is what this region \
             being reachable from exactly one domain is the mechanism for",
        ),
    },
];

/// The arena's size, restated from the domain that declares it.
///
/// `pds/crypto` is a binary and cannot be depended on, so the number crosses
/// as a literal and this rule is what holds the two equal — the same shape the
/// log regions' sizes cross in.
const ARENA_BYTES: usize = 0x20_0000;

/// Every shard is one page of the same type, so the eleven rules share one
/// expectation rather than restating it eleven times.
const STATS_SIZE: ExpectedSize = ExpectedSize {
    rust_name: "lfw_metrics::STATS_REGION_SIZE",
    bytes: STATS_REGION_SIZE,
};

/// What the shard rows withhold, quoted into the finding on any of them being
/// widened.
const STATS_WITHHELD: &str = "one writer and one reader per shard, and every other domain maps \
     none of it in either direction. A domain that could write another's shard could make a port \
     that is dropping every frame report a clean line — and the reader is the domain that faces \
     the management-plane attacker, so its grant is READ-ONLY on all ten that are not its own: \
     a `/metrics` surface it could edit would let a compromise of it hide the compromise. The \
     console in particular maps no shard but its own, which is the same exclusion the log rings \
     already make one step further: there it cannot forge a record, here it cannot forge a \
     number";

/// What an I/O-port grant withholds, quoted into the finding that reports one
/// being widened, moved, or handed to a second domain.
///
/// Not [`Option`] as a region's is: a port window is carved out of a 65536-port
/// space in which every other port is refused, so a rule that withheld nothing
/// would be a rule granting the whole space. There is no shape of this table
/// that has nothing to say here, and making it unrepresentable is cheaper than
/// a test asserting it.
const COM1_WITHHELD: &str = "every other port in the 65536-port space stays refused to this \
     domain: no PCI configuration address/data pair at 0xCF8/0xCFC — a second path to every \
     device's configuration space, beside the ECAM mappings the drivers hold — no PS/2 \
     controller, no PIC, no PIT, no CMOS/RTC and no debug port. The CMOS pair belongs to the \
     clock domain and to it alone, so the domain that renders an operator's only output cannot \
     read or stop the clock; the drivers and the forwarder hold zero ports between them, so an \
     attacker who reaches either reaches no port instruction that will execute. This row is also \
     what makes the console the sole writer of the serial device: several writers on one \
     unsynchronised register file splice their bytes into one another, and a capability held by \
     exactly one domain is what makes that unrepresentable rather than unlikely";

/// As [`COM1_WITHHELD`], for the CMOS window the clock domain holds.
///
/// The two rows together are what replaced "one domain holds every port this
/// system grants" with something narrower and still worth defending: the
/// windows are disjoint, each has exactly one holder, and neither holder can
/// reach the other's device.
const CMOS_WITHHELD: &str = "every other port in the 65536-port space stays refused to this \
     domain, the serial controller at 0x3F8 included — so the domain that reads a \
     battery-backed register file cannot write the console line an operator reads its result on, \
     and a compromised clock reaches no other device at all. Two ports and not eight: \
     `lfw_rtc` forms exactly `INDEX_PORT` and `DATA_PORT`, selects all nine registers it can \
     name through the first, and const-asserts every index it can write to leave bit 7 clear — \
     so no invocation it can make disables the non-maskable interrupt or leaves this window";

/// The exported Rust constant one attribute of an `<ioport>` must equal.
///
/// [`ExpectedSize`] is this shape for a region's extent, and is deliberately
/// not reused: a port window is two facts rather than one, and neither of them
/// is a byte count. Both come from `crates/uart-16550`, whose header takes the
/// window as the premise its addressing rests on — "every address as
/// `COM1_BASE | offset` with the base's alignment to an eight-port window
/// asserted at build time, so no address it can form leaves this row". This is
/// where that delegated precondition is enforced.
struct ExpectedPort {
    /// Carried beside the value so a disagreement names both sides rather than
    /// printing two numbers.
    rust_name: &'static str,
    value: u64,
}

/// One `<ioport>` the description may declare: which domain may hold which
/// window of the x86 I/O permission bitmap.
///
/// An I/O-port grant is authority exactly as a `<map>` is. On x86 `in` and
/// `out` are privileged and seL4 gates them per port, so a window handed to a
/// domain is that domain's licence to drive whatever decodes it — and a window
/// that widened, moved, or turned up in a second domain is a capability change
/// on the same footing as a widened memory grant, human-reviewed the same way.
struct IoPortRule {
    domain: &'static str,
    /// The `id` attribute — the grant's identifier *within* the domain, and the
    /// granularity the authority exists at, exactly as a [`ChannelEnd`]'s is. A
    /// domain may hold several windows, so "which window" is a question about
    /// one id and never about the domain, and keying on the domain alone would
    /// judge the first grant and exempt every later one.
    id: &'static str,
    /// The first port in the window, and how many consecutive ports follow it.
    /// Held as the two attributes the description writes rather than as a
    /// range, because those two are what an edit moves.
    addr: ExpectedPort,
    size: ExpectedPort,
    withheld: &'static str,
}

/// Every I/O-port grant the description may declare. Two rows, on two domains,
/// each holding one window — and the count is the property rather than an
/// accident of how little the system does: a third row is a third domain able
/// to reach a device by port invocation, and adding one is a capability change
/// to review. What the table states beyond the windows themselves is that they
/// are disjoint and that neither domain holds the other's.
const IO_PORTS: &[IoPortRule] = &[
    IoPortRule {
        domain: "console",
        id: "0",
        addr: ExpectedPort {
            rust_name: "uart_16550::COM1_BASE",
            value: COM1_BASE as u64,
        },
        size: ExpectedPort {
            rust_name: "uart_16550::PORT_COUNT",
            value: COM1_PORT_COUNT as u64,
        },
        withheld: COM1_WITHHELD,
    },
    IoPortRule {
        domain: "clock",
        id: "0",
        addr: ExpectedPort {
            rust_name: "lfw_rtc::INDEX_PORT",
            value: INDEX_PORT as u64,
        },
        size: ExpectedPort {
            rust_name: "lfw_rtc::PORT_COUNT",
            value: CMOS_PORT_COUNT as u64,
        },
        withheld: CMOS_WITHHELD,
    },
];

/// What the clock domain's interrupt grant withholds, quoted into the finding
/// that reports it moving.
const TICK_IRQ_WITHHELD: &str = "an IRQHandler capability on ONE I/O APIC input and nothing \
     beside it: this domain cannot mask another input, cannot route one, and holds no capability \
     over the interrupt controller at all. It is also the whole of what can enter that domain \
     after `init` — no protection domain in this system can raise it — so a pin that moved would \
     be an interrupt delivered to a handler that programmed a different one, and a domain that is \
     never woken again";

/// One `<irq>` the description may declare: which domain may acknowledge which
/// interrupt, on which input.
///
/// An interrupt grant is authority exactly as a `<map>` and an `<ioport>` are.
/// It places an IRQHandler capability in the domain's CNode and binds the input
/// to that domain's notification, so it decides both what may wake the domain
/// and which input the kernel will let it acknowledge — and it is the only
/// capability in this system that a *device* exercises rather than a domain.
struct IrqRule {
    domain: &'static str,
    /// The `id` attribute. It shares its namespace with a `<channel>` end's
    /// `id`, which is the whole reason it is keyed on here: a domain reaches
    /// both through `Channel::new(id)`, so an interrupt and a peer's channel
    /// numbered the same would be one slot with two meanings.
    id: &'static str,
    /// The I/O APIC input, against the constant the domain programs its timer
    /// to drive. The two are one fact stated twice.
    pin: ExpectedPort,
    /// The delivery mode. Stated because it decides what the *handler* owes: an
    /// edge-triggered input is lowered by the device itself, and a level one
    /// obliges a write back to the device on every interrupt.
    trigger: &'static str,
    withheld: &'static str,
}

/// Every interrupt grant the description may declare. One row, and the count is
/// the property rather than an accident: a second row is a second domain the
/// hardware can enter, and adding one is a capability change to review.
const IRQS: &[IrqRule] = &[IrqRule {
    domain: "clock",
    id: "0",
    pin: ExpectedPort {
        rust_name: "lfw_hpet::INTERRUPT_PIN",
        value: HPET_INTERRUPT_PIN as u64,
    },
    trigger: "edge",
    withheld: TICK_IRQ_WITHHELD,
}];

/// Every protection domain the description may declare. Exhaustive in both
/// directions like the rest: the domain names are what [`RegionRule::mappers`]
/// and [`CHANNEL_ENDS`] are written in, so a domain renamed here and not there
/// would leave both tables judging a domain that no longer exists while the one
/// that replaced it is judged by nothing.
const DOMAINS: &[&str] = &[
    "forwarder",
    "config",
    "nic_driver0",
    "nic_driver1",
    "nic_driver2",
    "console",
    "clock",
    "management",
    "recorder",
    "hardware_probe",
    "crypto",
    "store",
];

/// Whether a protection domain may hold a send capability on one channel it is
/// an end of.
enum Notification {
    /// The domain signals the other end: `notify` absent (Microkit's default is
    /// true) or stated `"true"`.
    MaySend,
    /// The domain must hold no send capability at all, which Microkit expresses
    /// as an explicit `notify="false"`. `claim` is the sentence elsewhere in
    /// the repository that this row is what makes true.
    MayNotSend { claim: &'static str },
}

/// One `<end>` the description may declare.
struct ChannelEnd {
    domain: &'static str,
    /// The `id` attribute — the channel's identifier *within* that domain, and
    /// the granularity a send capability actually exists at: a protection
    /// domain notifies through `Channel::new(id)`, so "may this domain send" is
    /// a question about one id and never about the domain. Keying the rule on
    /// the domain alone was true only while every channel a domain ended was
    /// granted the same way, and the configuration handover is what ended that:
    /// the forwarder may signal the config domain and may signal neither
    /// driver.
    id: &'static str,
    notification: Notification,
}

/// What the forwarder's two *driver* channel ends are worth, quoted into the
/// finding that reports one being widened. Shared by both, because it is one
/// argument twice and a check that defended the forwarder against one driver
/// and not the other would defend neither direction of traffic.
const DRIVER_CHANNEL_ONE_WAY: &str = "pds/nic-driver's crate header takes this as a property of \
     the system rather than of its own code: its `notified` entrypoint is \"unreachable by \
     *capability* rather than by control flow\", which holds only while these two ends carry \
     notify=\"false\". A driver never leaves `init` and so never reaches the Microkit event loop, \
     so a forwarder able to signal one would hold authority over a domain that cannot answer, and \
     the claim that entrypoint rests on would stop being true. The configuration channel is the \
     one end this domain may send on, and it was granted deliberately and reviewed; these two \
     were not";

/// As [`DRIVER_CHANNEL_ONE_WAY`], for the management port's channel. A claim of
/// its own rather than a third use of that one, because what it protects is not
/// the same thing: the forwarder's two ends are about a domain that holds one
/// send capability and must hold no more, and this end is about a domain that
/// holds none at all.
const MANAGEMENT_CHANNEL_ONE_WAY: &str = "the management domain holds EXACTLY TWO send      capabilities in this system — on the configuration domain, where a submitted document is      otherwise invisible to a peer that never polls, and on the cryptography domain, where a      TLS record written into the relay is invisible for the same reason — and this is an end      that says it is neither. It is a notified-driven consumer here: it is woken, it drains,      it returns. A send capability on this end would be one on a driver that never leaves      `init` and so could never observe it — authority for nothing — and it would make      pds/nic-driver's claim that its `notified` entrypoint is unreachable by *capability*      false for the third instance while staying true for the other two";

/// As [`MANAGEMENT_CHANNEL_ONE_WAY`], for the store domain's one and only end. A
/// claim of its own rather than a third use of that one, because what it protects
/// is different again: the management domain's ends are about a domain that must
/// hold no send capability *among several channels*, and this is about the domain
/// that owns the appliance's identity holding none *at all*.
const STORE_CHANNEL_RECEIVE_ONLY: &str = "the store domain holds NO send capability anywhere in \
     this system, on this channel or any other — this is the only channel it has, and it is the \
     receiver on it. It needs none: it answers a signing request by publishing into a region the \
     asking domain reads, and that domain reads for the reply in a bounded spin rather than \
     waiting for a signal, because `sign` is called synchronously inside a handshake and has no \
     continuation a notification could resume. So a send capability here would be authority no \
     path consumes — and it would be a wakeup capability held by the domain that owns the \
     appliance's private key on the domain that runs adopted protocol code, which is worth \
     refusing on its own terms even if the asker ever did block";

/// Every `<end>` the description may declare, and the direction that one
/// channel is granted in. An end absent from this table fails the gate, and so
/// does a row here that matches no `<end>` — the second is what stops a rule
/// from passing vacuously the day a domain or a channel id is renamed.
const CHANNEL_ENDS: &[ChannelEnd] = &[
    ChannelEnd {
        domain: "nic_driver0",
        id: "0",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "nic_driver1",
        id: "0",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "forwarder",
        id: "0",
        notification: Notification::MayNotSend {
            claim: DRIVER_CHANNEL_ONE_WAY,
        },
    },
    ChannelEnd {
        domain: "forwarder",
        id: "1",
        notification: Notification::MayNotSend {
            claim: DRIVER_CHANNEL_ONE_WAY,
        },
    },
    // The management port's channel, one-directional for the same reason and
    // with a claim of its own: the driver's `notified` is unreachable by
    // capability only while the far end of every one of its channels carries
    // notify="false", and this is the third such end.
    ChannelEnd {
        domain: "nic_driver2",
        id: "0",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "management",
        id: "0",
        notification: Notification::MayNotSend {
            claim: MANAGEMENT_CHANNEL_ONE_WAY,
        },
    },
    // The one channel granted in both directions, and the two rows that say so.
    // Applying a configuration is a two-phase commit whose phases neither end
    // can infer: the config domain offers and signals, the forwarder stages and
    // signals back — the publisher has no loop to poll from and must not
    // release a generation the consumer refused — and the config domain then
    // publishes the commit and signals again, because a forwarder that learned
    // of it only when the next frame arrived would be misconfigured for exactly
    // as long as the node was idle.
    ChannelEnd {
        domain: "forwarder",
        id: "2",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "config",
        id: "0",
        notification: Notification::MaySend,
    },
    // The download channel. The recorder signals that a window is ready; the
    // management domain answers nothing back, and this is its SECOND end — id 0
    // being nic_driver2's, where it is likewise the receiver. Both ends carry
    // notify="false" on its side, which is what keeps "this domain holds no send
    // capability at all" true rather than nearly true.
    ChannelEnd {
        domain: "recorder",
        id: "0",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "management",
        id: "1",
        notification: Notification::MayNotSend {
            claim: MANAGEMENT_CHANNEL_ONE_WAY,
        },
    },
    // The configuration submission channel, granted in BOTH directions, and the
    // one place the management domain holds a send capability at all. It must: the
    // config domain has no polling loop — it blocks in the Microkit event loop,
    // which is why it costs nothing at the highest priority in the system — so a
    // document copied into `cfg_request` is invisible to it until it is woken, and
    // the only party that knows one arrived is the domain that copied it. What the
    // capability is worth to an attacker is a wakeup at a rate they choose, on a
    // domain whose answer to one is bounded and which holds no device, no pool and
    // no ring; the same party provokes exactly that by submitting a document,
    // which is the request this appliance is now built to accept. The reverse
    // direction is the recorder channel's argument: a management domain that
    // learned of a decision only when the next frame woke it would stall a client
    // holding a connection open.
    ChannelEnd {
        domain: "config",
        id: "1",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "management",
        id: "2",
        notification: Notification::MaySend,
    },
    // The signing delegation, one-directional. The asker must be able to signal:
    // the holder blocks in the Microkit event loop, so a request written into
    // `sign_request` is invisible to it until it is woken, and making it poll
    // instead would burn the highest-but-one priority in the system to catch a
    // handshake. The holder may not signal back, for the reason below it.
    ChannelEnd {
        domain: "crypto",
        id: "0",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "store",
        id: "0",
        notification: Notification::MayNotSend {
            claim: STORE_CHANNEL_RECEIVE_ONLY,
        },
    },
    // The TLS relay, granted in BOTH directions and the only channel here that is
    // between two domains at the SAME priority. Neither is scheduled while the
    // other runs and neither has a loop a peer's write could be observed in, so
    // each side signals and returns to its event loop. A spin instead — the
    // signing delegation's shape — would burn the asking domain's whole slice
    // against a domain the scheduler has no reason to run, on the path of every
    // record of every handshake, and the alternative to that is raising one of
    // the two above the dataplane for a session an unauthenticated peer opens.
    ChannelEnd {
        domain: "management",
        id: "3",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "crypto",
        id: "1",
        notification: Notification::MaySend,
    },
    // The periodic wakeup, one-directional. The clock domain must be able to
    // signal: it is the only domain hardware tells that an interval has
    // elapsed, and the domain that owes the management channel's schedules has
    // no clock of its own to be woken by. The management end may not signal
    // back, for the reason beside it.
    ChannelEnd {
        domain: "clock",
        id: "1",
        notification: Notification::MaySend,
    },
    ChannelEnd {
        domain: "management",
        id: "4",
        notification: Notification::MayNotSend {
            claim: MANAGEMENT_CHANNEL_ONE_WAY,
        },
    },
];

/// One port's driver: the receive-pipeline region that port's frames arrive on,
/// and the protection domain the metric surface attributes them to.
///
/// This is the enforcer `lfw_metrics::PORT_DOMAINS`' precondition names.
/// That table is the join key of the interface info family — a scraper matches
/// `domain="nic_driver0"` on a counter series against the info series for the
/// interface the document put on port 0 — and *which domain drives which port* is
/// a fact of this file alone. Nothing in a configuration document states it and
/// nothing in a crate can derive it, so before this check it was a comment.
///
/// The mapping is read off the description the way the system itself establishes
/// it: a driver instance receives into the region it maps as `rx_fwd_vaddr`, and
/// the forwarder reads port *n*'s frames out of `fwd{n}`. So the domain that maps
/// `fwd{n}` as its own receive pipeline *is* the driver of port *n*, and this
/// table says which domain that must be.
struct PortDriverRule {
    /// How a finding names the port, `port 0` or `the management port`.
    port: &'static str,
    /// The `mr` of the region that port's driver maps as `rx_fwd_vaddr`.
    receive_region: &'static str,
    /// The domain `lfw_metrics` attributes that port to, taken from the constant
    /// rather than written again: a literal here would make this check compare
    /// the description against itself.
    domain: &'static str,
}

/// Every port this build has a driver for, dataplane and management alike.
///
/// Exhaustive in both directions like every other table here: a
/// `setvar_vaddr="rx_fwd_vaddr"` mapping no rule names is a fourth port whose
/// attribution nothing compares, and a rule matching no mapping is a port whose
/// driver has been renamed out from under the constant.
fn port_drivers() -> Vec<PortDriverRule> {
    let mut rules: Vec<PortDriverRule> = PORT_DOMAINS
        .iter()
        .enumerate()
        .map(|(port, domain)| PortDriverRule {
            port: match port {
                0 => "port 0",
                1 => "port 1",
                // Unreachable while the build has two dataplane ports, and a
                // name rather than a panic so a third port fails as an
                // unnamed rule instead of stopping the checker.
                _ => "a dataplane port this checker cannot name",
            },
            receive_region: match port {
                0 => "fwd0",
                1 => "fwd1",
                _ => "an unnamed receive pipeline",
            },
            domain,
        })
        .collect();
    rules.push(PortDriverRule {
        port: "the management port",
        receive_region: "mgmt_rx_fwd",
        domain: MANAGEMENT_PORT_DOMAIN,
    });
    rules
}

/// The `setvar_vaddr` a driver instance attaches its receive pipeline at. It is
/// what makes a mapping *the receive side*: the same region is mapped by the peer
/// on the other end of the pipeline under a different symbol.
const RECEIVE_PIPELINE_SYMBOL: &str = "rx_fwd_vaddr";

/// Every element type this module knows how to judge. An element outside it
/// stops the gate rather than being skipped: `<virtual_machine>` and `<vcpu>`
/// are both authority grants, and one arriving unnoticed is precisely a
/// capability change that must be looked at.
///
/// `ioport` was the case that proved the point, and `irq` was the second: each
/// entered the description as a new capability class and stopped the gate here,
/// unmodelled, rather than being granted quietly. Listing a tag is therefore
/// only half of admitting it — [`IO_PORTS`] and [`IRQS`] are the other half, and
/// a tag listed with no table behind it would turn this check from a stop into a
/// silence.
const MODELLED_TAGS: &[&str] = &[
    "system",
    "memory_region",
    "protection_domain",
    "program_image",
    "map",
    "setvar",
    "ioport",
    "irq",
    "channel",
    "end",
];

/// Read the system description and hold it to the tables above.
///
/// Runs in the fast gate and again before the Microkit tool is invoked, so a
/// divergence is a build failure at the earliest point either path reaches it.
pub(crate) fn check(root: &Path) -> Result<(), Error> {
    let path = root.join(SYSTEM_DESCRIPTION);
    let text =
        fs::read(&path).map_err(|error| Error::io("read the system description", &path, error))?;
    let elements =
        scan(&text).map_err(|why| Error::invalid(format!("{}: {why}", path.display())))?;

    let findings = findings(&elements);
    if findings.is_empty() {
        let tally =
            |tag: &str, noun| counted(elements.iter().filter(|e| e.tag == tag).count(), noun);
        println!(
            "sysdesc: {} agrees with the code that holds it: {} granted by {}, {}, {}, and {} — \
             each sized, mapped and withheld as that code requires",
            path.display(),
            tally("memory_region", "memory region"),
            tally("map", "mapping"),
            tally("ioport", "I/O-port window"),
            tally("irq", "interrupt"),
            tally("end", "channel end"),
        );
        return Ok(());
    }

    let mut report = format!(
        "{} disagreement(s) between {} and the code that maps it:\n",
        findings.len(),
        path.display()
    );
    for finding in &findings {
        report.push_str("  - ");
        report.push_str(finding);
        report.push('\n');
    }
    report.push_str(
        "The description and the constants are two statements of one fact and move together or \
         not at all. Fix whichever is wrong; if a region was renamed, split or added, give it a \
         rule in tools/xtask/src/sysdesc.rs — with the domains that map it, exactly — so the new \
         shape is checked rather than exempt.",
    );
    Err(Error::invalid(report))
}

/// Everything wrong with the parsed description, collected rather than reported
/// one at a time: a resize touches a constant and several regions at once, and
/// failing on the first would make the author rerun the gate to discover the
/// rest.
fn findings(elements: &[Element]) -> Vec<String> {
    let mut findings = Vec::new();
    check_modelled_tags(elements, &mut findings);
    let domains_agree = check_domains(elements, &mut findings);
    let regions = check_regions(elements, &mut findings);
    check_maps(elements, &regions, domains_agree, &mut findings);
    check_io_ports(elements, domains_agree, &mut findings);
    check_irqs(elements, domains_agree, &mut findings);
    check_channel_ends(elements, &mut findings);
    check_channel_ids_are_disjoint(elements, &mut findings);
    check_port_drivers(elements, &mut findings);
    check_every_map_is_addressable(elements, &mut findings);
    findings
}

/// Every `<map>` names the symbol the mapping domain reaches it through.
///
/// A `setvar_vaddr` is the whole of what turns a grant into something code can
/// address: without it, the region is mapped into the domain's address space and
/// no line in that domain can name where. Such a mapping is authority with no
/// consumer, and the rest of this module cannot see it — the mapper set, the
/// perms and the extent are all exactly right, and the grant simply does nothing
/// but widen what a compromised domain reaches.
///
/// The recorder held one: `cfg` read-only, attached nowhere, while the domain
/// composed its interface names itself. It was withdrawn, and this is what stops
/// the shape returning quietly. A region a domain must map at an address the code
/// hardcodes would fail here, which is the right outcome: it is a claim worth
/// making deliberately rather than by omission.
fn check_every_map_is_addressable(elements: &[Element], findings: &mut Vec<String>) {
    for element in elements.iter().filter(|element| element.tag == "map") {
        if element.attribute("setvar_vaddr").is_some() {
            continue;
        }
        findings.push(format!(
            "<map mr={:?}> into {:?} names no setvar_vaddr, so the region is mapped into that \
             domain and no code in it can address the mapping. That is authority with no \
             consumer: withdraw the grant, or — if a symbol genuinely cannot carry it — say so \
             where the grant is made",
            element.attribute("mr").unwrap_or("?"),
            element.owner()
        ));
    }
}

/// Which domain drives which port, against `lfw_metrics::PORT_DOMAINS`.
///
/// Both directions: a receive-pipeline mapping no rule names, a rule matching no
/// mapping, and a mapping whose owning domain is not the one the metric surface
/// attributes that port to are three separate findings. The third is the one that
/// matters — it is the shape in which every counter series of one port would be
/// joined to another port's identity, which is worse than an absent join because
/// it reads as an answer.
fn check_port_drivers(elements: &[Element], findings: &mut Vec<String>) {
    let rules = port_drivers();
    // Every `<map>` that attaches a receive pipeline, with the domain that makes
    // it: the pair *is* the port-to-driver mapping this file establishes.
    let receivers: Vec<(&str, String)> = elements
        .iter()
        .filter(|element| element.tag == "map")
        .filter(|element| element.attribute("setvar_vaddr") == Some(RECEIVE_PIPELINE_SYMBOL))
        .filter_map(|element| element.attribute("mr").map(|mr| (mr, element.owner())))
        .collect();

    for rule in &rules {
        let holders: Vec<&str> = receivers
            .iter()
            .filter(|(region, _)| *region == rule.receive_region)
            .map(|(_, domain)| domain.as_str())
            .collect();
        match holders.as_slice() {
            [domain] if *domain == rule.domain => {}
            [domain] => findings.push(format!(
                "<map mr={:?} setvar_vaddr={RECEIVE_PIPELINE_SYMBOL:?}> is made by {domain:?}, so \
                 {} is driven by that domain — and lfw_metrics::PORT_DOMAINS attributes it to \
                 {:?}. The interface info metric joins a counter series to a configured interface \
                 on exactly that name, so a disagreement here does not lose the join: it points \
                 every one of that port's counters at another port's addressing",
                rule.receive_region, rule.port, rule.domain
            )),
            [] => findings.push(format!(
                "no <map mr={:?} setvar_vaddr={RECEIVE_PIPELINE_SYMBOL:?}> exists, so nothing in \
                 this description drives {} — and lfw_metrics::PORT_DOMAINS still attributes it to \
                 {:?}, which would then be an interface identity joined to counters no domain \
                 publishes",
                rule.receive_region, rule.port, rule.domain
            )),
            many => findings.push(format!(
                "{} domains map {:?} as {RECEIVE_PIPELINE_SYMBOL:?} ({many:?}), so which of them \
                 drives {} is not stated. A receive pipeline admits exactly one consumer",
                many.len(),
                rule.receive_region,
                rule.port
            )),
        }
    }

    for (region, domain) in &receivers {
        if !rules.iter().any(|rule| rule.receive_region == *region) {
            findings.push(format!(
                "{domain:?} maps <memory_region name={region:?}> as \
                 {RECEIVE_PIPELINE_SYMBOL:?}, so it drives a port no rule in sysdesc.rs names. A \
                 port whose driver is unnamed is one lfw_metrics cannot attribute a counter series \
                 to: give it an entry in PORT_DOMAINS and a rule here, in the same change"
            ));
        }
    }
}

/// The protection domains, against [`DOMAINS`], in both directions. Returns
/// whether the two agree, which is the precondition for comparing any grant to
/// a domain by name: while they disagree the rules and the description are
/// written in two different vocabularies, and every mapper comparison would
/// restate that one disagreement once per region.
fn check_domains(elements: &[Element], findings: &mut Vec<String>) -> bool {
    let before = findings.len();
    let mut declared: Vec<&str> = Vec::new();
    for element in elements
        .iter()
        .filter(|element| element.tag == "protection_domain")
    {
        let Some(name) = required(element, "name", findings) else {
            continue;
        };
        declared.push(name);
        if !DOMAINS.contains(&name) {
            findings.push(format!(
                "line {}: <protection_domain name={name:?}> is named by no rule in sysdesc.rs, \
                 so every region it maps and every channel it ends is compared against nothing. \
                 Add it to DOMAINS, and give each region it maps a mappers entry naming it",
                element.line
            ));
        }
    }
    for domain in DOMAINS {
        if !declared.contains(domain) {
            findings.push(format!(
                "sysdesc.rs names a protection domain {domain:?} that the description does not \
                 declare. Every mappers list mentioning it then withholds nothing and grants \
                 nothing — the shape in which a renamed domain silently keeps its old rules"
            ));
        }
    }
    findings.len() == before
}

fn check_modelled_tags(elements: &[Element], findings: &mut Vec<String>) {
    for element in elements {
        if !MODELLED_TAGS.contains(&element.tag.as_str()) {
            findings.push(format!(
                "line {}: <{}> is an element type this cross-check does not model, so whatever \
                 it grants is neither compared nor reported. Teach sysdesc.rs to judge it \
                 (MODELLED_TAGS), and treat the grant itself as the security change it is, \
                 human-reviewed rather than merged",
                element.line, element.tag
            ));
        }
    }
}

/// The region names the description declares, after judging each declaration
/// against its rule. Returned so the map check can reject an `mr` naming a
/// region that does not exist.
fn check_regions(elements: &[Element], findings: &mut Vec<String>) -> Vec<String> {
    let mut declared: Vec<String> = Vec::new();
    for element in elements.iter().filter(|e| e.tag == "memory_region") {
        let Some(name) = required(element, "name", findings) else {
            continue;
        };
        if declared.iter().any(|seen| seen == name) {
            findings.push(format!(
                "line {}: a second <memory_region> is named {name:?}; Microkit resolves every \
                 `mr` by name, so one of the two grants is unreachable and which one is not \
                 stated here",
                element.line
            ));
            continue;
        }
        declared.push(name.to_owned());

        let Some(rule) = REGIONS.iter().find(|rule| rule.name == name) else {
            findings.push(format!(
                "line {}: <memory_region name={name:?}> is named by no rule in sysdesc.rs, so \
                 its size, cacheability and perms are compared against nothing. Add a \
                 RegionRule, whose ExpectedSize names the Rust constant this region must \
                 equal — exporting that constant if it is not exported yet",
                element.line
            ));
            continue;
        };

        let Some(raw) = required(element, "size", findings) else {
            continue;
        };
        match parse_int(raw) {
            Err(why) => findings.push(format!(
                "line {}: <memory_region name={name:?}> has size={raw:?}, which {why}",
                element.line
            )),
            Ok(size) => check_region_size(element.line, rule, size, findings),
        }
    }

    for rule in REGIONS {
        if !declared.iter().any(|name| name == rule.name) {
            findings.push(format!(
                "sysdesc.rs carries a rule for a memory region named {:?}, and the description \
                 declares none. A rule matching nothing defends nothing: delete it, or rename \
                 it to the region that replaced it",
                rule.name
            ));
        }
    }
    declared
}

fn check_region_size(line: usize, rule: &RegionRule, size: u64, findings: &mut Vec<String>) {
    let ExpectedSize { rust_name, bytes } = rule.size;
    if size == bytes as u64 {
        return;
    }
    findings.push(format!(
        "line {line}: <memory_region name={:?}> reserves {size:#x} bytes and {rust_name} is \
         {bytes:#x}. The protection domains map this region as {rust_name}, so the smaller of \
         the two decides what is really there: a short region truncates the mapping, and a long \
         one widens the grant past the type that names it",
        rule.name
    ));
}

fn check_maps(
    elements: &[Element],
    declared: &[String],
    domains_agree: bool,
    findings: &mut Vec<String>,
) {
    // Every (region, domain) a `<map>` grants, in source order. A pair rather
    // than a region alone because *who* maps a region is the grant; the region
    // alone only says somebody does.
    let mut granted: Vec<(&str, String)> = Vec::new();
    for element in elements.iter().filter(|e| e.tag == "map") {
        let Some(region) = required(element, "mr", findings) else {
            continue;
        };
        let domain = element.owner();
        let site = format!("line {}: <map mr={region:?}> in {domain}", element.line);

        if !declared.iter().any(|name| name == region) {
            findings.push(format!(
                "{site} names a memory region the description does not declare"
            ));
            continue;
        }
        if granted
            .iter()
            .any(|(seen, holder)| *seen == region && *holder == domain)
        {
            findings.push(format!(
                "{site} maps a region this domain already maps. One region at two addresses in \
                 one address space is an alias no attach site expects, and it leaves the \
                 granted set looking unchanged"
            ));
        }
        // A region no rule names has nothing for its maps to be judged
        // against. The missing rule is the finding; restating it once per map
        // site would bury it under itself.
        if let Some(rule) = REGIONS.iter().find(|rule| rule.name == region) {
            if let Some(cached) = required(element, "cached", findings) {
                check_map_cacheability(&site, rule, cached, findings);
            }
            check_map_perms(&site, rule, &domain, element, findings);
        }
        granted.push((region, domain));
    }

    // Only regions the description actually declares: for one it does not, the
    // rule matching nothing is already the finding (check_regions), and adding
    // "and none of its mappers map it" would report the same absence twice.
    if domains_agree {
        for rule in REGIONS
            .iter()
            .filter(|rule| declared.iter().any(|name| name == rule.name))
        {
            check_region_mappers(rule, &granted, findings);
        }
    }
}

/// The domains that map one region, against the set its rule grants it to.
///
/// Both directions, because both are how the topology stops being what the code
/// assumes: a domain that appeared holds authority nobody granted it, and one
/// that vanished cannot reach a region it is written to use.
fn check_region_mappers(rule: &RegionRule, granted: &[(&str, String)], findings: &mut Vec<String>) {
    let holders: Vec<&str> = granted
        .iter()
        .filter(|(region, _)| *region == rule.name)
        .map(|(_, domain)| domain.as_str())
        .collect();

    // An empty grant set is a real shape — a region reachable only by a device's
    // DMA — but it is also what a rule whose grants were forgotten looks like,
    // and the two must not be the same thing. The claim is what separates them:
    // a rule may say "nobody maps this" only by saying why, in which case every
    // holder below is a finding and the loop over `grants` has nothing to check.
    if rule.grants.is_empty() && rule.withheld.is_none() {
        findings.push(format!(
            "sysdesc.rs grants <memory_region name={:?}> to no protection domain and gives no \
             `withheld` claim saying why. A region reachable by no domain is admissible — a DMA \
             target the owning driver is handed the physical address of, and nothing else — but \
             it is a deliberate property to state, not the shape a rule takes when its grants \
             were left out. Name the domains that map it, or record the claim its emptiness makes",
            rule.name
        ));
        return;
    }

    let granted_to = rule.granted_to();
    for domain in &holders {
        if rule.grant(domain).is_none() {
            let mut finding = format!(
                "{domain:?} maps <memory_region name={:?}>, which sysdesc.rs grants to \
                 {granted_to} and to nothing else. A domain reaching a region it was withheld \
                 is a capability change, reviewed and approved rather than merged",
                rule.name
            );
            if let Some(claim) = rule.withheld {
                finding.push_str(". What that withholding is worth: ");
                finding.push_str(claim);
            }
            findings.push(finding);
        }
    }

    for grant in rule.grants {
        if !holders.contains(&grant.domain) {
            findings.push(format!(
                "sysdesc.rs records {:?} as mapping <memory_region name={:?}>, and it maps no \
                 such region. Either the grant was dropped — and that domain now faults on the \
                 vaddr it attaches — or the rule is stale and still judging a topology this file \
                 left behind",
                grant.domain, rule.name
            ));
        }
    }
}

/// The authority one `<map>` grants, against the authority its rule grants that
/// domain.
///
/// A domain the rule admits no grant for is left to [`check_region_mappers`]:
/// the mapping that should not exist at all is the finding, and judging the
/// perms of a grant nobody made would report one edit as two.
fn check_map_perms(
    site: &str,
    rule: &RegionRule,
    domain: &str,
    element: &Element,
    findings: &mut Vec<String>,
) {
    let Some(perms) = required(element, "perms", findings) else {
        return;
    };
    let Some(grant) = rule.grant(domain) else {
        return;
    };
    if perms == grant.perms {
        return;
    }
    findings.push(format!(
        "{site} grants perms={perms:?} where sysdesc.rs grants {domain:?} {:?} on this region. A \
         change to what a domain may do to a region is a capability change, and it is reviewed \
         and approved rather than merged; record the new grant here once it is",
        grant.perms
    ));
}

fn check_map_cacheability(site: &str, rule: &RegionRule, cached: &str, findings: &mut Vec<String>) {
    if !matches!(cached, "true" | "false") {
        findings.push(format!(
            "{site} has cached={cached:?}, which is neither \"true\" nor \"false\""
        ));
        return;
    }
    if cached == rule.cacheability.attribute() {
        return;
    }
    findings.push(format!(
        "{site} is mapped cached={cached:?} and must be cached={:?}: {}",
        rule.cacheability.attribute(),
        rule.cacheability.premise()
    ));
}

/// The I/O-port grants, against [`IO_PORTS`], in both directions — the same
/// shape [`check_region_mappers`] holds a memory grant to, for the same reason:
/// a window that appeared is authority nobody granted, and one that vanished
/// leaves the domain written to drive it faulting on its first `out`.
fn check_io_ports(elements: &[Element], domains_agree: bool, findings: &mut Vec<String>) {
    // Every (domain, id) an `<ioport>` grants. The pair rather than the domain,
    // because a domain may hold several windows and each is its own authority.
    let mut held: Vec<(String, &str)> = Vec::new();
    for element in elements.iter().filter(|e| e.tag == "ioport") {
        let domain = element.owner();
        let Some(id) = required(element, "id", findings) else {
            continue;
        };
        let site = format!("line {}: <ioport id={id:?}> in {domain}", element.line);

        if held
            .iter()
            .any(|(holder, seen)| *holder == domain && *seen == id)
        {
            findings.push(format!(
                "{site} is a second grant under an id this domain already holds, and which of \
                 the two Microkit installs in the I/O permission bitmap is not something this \
                 gate may assume"
            ));
        }
        held.push((domain.clone(), id));

        let Some(rule) = IO_PORTS
            .iter()
            .find(|rule| rule.domain == domain && rule.id == id)
        else {
            findings.push(format!(
                "{site} is an I/O-port grant no rule in sysdesc.rs names, so the window it hands \
                 this domain is compared against nothing. `in` and `out` are privileged and seL4 \
                 gates them per port, so this is a domain newly able to drive whatever decodes \
                 that window — a capability change, reviewed and approved rather than merged. \
                 Record it in IO_PORTS once it is"
            ));
            continue;
        };
        check_port_window(&site, rule, element, findings);
    }

    // As in [`check_maps`]: while the domain vocabularies disagree, every rule
    // here would report a grant that vanished, restating one rename once per
    // row.
    if !domains_agree {
        return;
    }
    for rule in IO_PORTS {
        if !held
            .iter()
            .any(|(domain, id)| domain == rule.domain && *id == rule.id)
        {
            findings.push(format!(
                "sysdesc.rs records {:?} as holding I/O-port grant id {:?}, and the description \
                 declares no such <ioport>. Either the grant was dropped — and that domain \
                 faults on its first port instruction, taking with it the one device an operator \
                 watches a failed boot on — or the rule is stale and still judging a topology \
                 this file left behind",
                rule.domain, rule.id
            ));
        }
    }
}

/// The window one `<ioport>` grants, against the window its rule admits.
///
/// Both attributes, because the two ways a grant stops being the one that was
/// approved are opposite and neither implies the other: a larger `size` widens
/// it over ports nobody reviewed, and a moved `addr` leaves the reviewed device
/// altogether for whatever decodes the new base.
fn check_port_window(site: &str, rule: &IoPortRule, element: &Element, findings: &mut Vec<String>) {
    for (attribute, expected) in [("addr", &rule.addr), ("size", &rule.size)] {
        let Some(raw) = required(element, attribute, findings) else {
            continue;
        };
        let value = match parse_int(raw) {
            Ok(value) => value,
            Err(why) => {
                findings.push(format!("{site} has {attribute}={raw:?}, which {why}"));
                continue;
            }
        };
        if value == expected.value {
            continue;
        }
        findings.push(format!(
            "{site} grants {attribute}={value:#x} and {} is {:#x}. The description and the \
             driver state one window between them — the driver forms every address inside the \
             one it compiled against — so a window this file moved or widened is authority \
             nobody reviewed, and it is a capability change reviewed and approved rather than \
             merged. What the grant as approved withholds: {}",
            expected.rust_name, expected.value, rule.withheld
        ));
    }
}

fn check_channel_ends(elements: &[Element], findings: &mut Vec<String>) {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for element in elements.iter().filter(|e| e.tag == "end") {
        let Some(domain) = required(element, "pd", findings) else {
            continue;
        };
        let Some(id) = required(element, "id", findings) else {
            continue;
        };
        let site = format!("line {}: <end pd={domain:?} id={id:?}>", element.line);

        let Some(end) = CHANNEL_ENDS
            .iter()
            .find(|end| end.domain == domain && end.id == id)
        else {
            findings.push(format!(
                "{site} names a protection domain and channel id no rule in sysdesc.rs covers, \
                 so whether it holds a send capability on this channel is compared against \
                 nothing. Add it to CHANNEL_ENDS as MaySend or MayNotSend"
            ));
            continue;
        };
        seen.push((domain, id));

        // Microkit 2.3.0 manual, section 7.6: `notify` "indicates that the protection domain
        // for this end can send a notification to the other end; defaults to
        // true". An absent attribute is therefore a granted send capability.
        let notify = element.attribute("notify").unwrap_or("true");
        if !matches!(notify, "true" | "false") {
            findings.push(format!(
                "{site} has notify={notify:?}, which is neither \"true\" nor \"false\""
            ));
            continue;
        }
        match (&end.notification, notify) {
            (Notification::MaySend, "true") | (Notification::MayNotSend { .. }, "false") => {}
            (Notification::MaySend, _) => findings.push(format!(
                "{site} carries notify=\"false\", so this domain holds no send capability on \
                 this channel and the signal it is expected to raise cannot leave it"
            )),
            (Notification::MayNotSend { claim }, _) => findings.push(format!(
                "{site} does not carry notify=\"false\", so Microkit grants this domain a send \
                 capability on the other end. {claim}"
            )),
        }
    }

    for end in CHANNEL_ENDS {
        if !seen.contains(&(end.domain, end.id)) {
            findings.push(format!(
                "sysdesc.rs carries a channel rule for {:?} on channel id {:?}, and the \
                 description makes it an end of no such channel. The rule then passes over an \
                 empty set — which is how a renamed domain, or a renumbered channel, silently \
                 loses the direction its grant was narrowed to",
                end.domain, end.id
            ));
        }
    }
}

/// Every `<irq>` the description declares is one [`IRQS`] names, on the input
/// and with the delivery mode it names — and every rule matches a grant.
///
/// [`check_io_ports`]' shape on the other capability class, and it is judged the
/// same way and for the same reason: an interrupt handed to a domain decides
/// what the hardware may wake, and one that moved to another input, another
/// delivery mode or another domain is authority nobody reviewed.
fn check_irqs(elements: &[Element], domains_agree: bool, findings: &mut Vec<String>) {
    let mut held: Vec<(String, &str)> = Vec::new();
    for element in elements.iter().filter(|e| e.tag == "irq") {
        let domain = element.owner();
        let Some(id) = required(element, "id", findings) else {
            continue;
        };
        let site = format!("line {}: <irq id={id:?}> in {domain}", element.line);

        if held
            .iter()
            .any(|(holder, seen)| *holder == domain && *seen == id)
        {
            findings.push(format!(
                "{site} is a second interrupt under an id this domain already holds, and which \
                 of the two Microkit binds to that notification bit is not something this gate \
                 may assume"
            ));
        }
        held.push((domain.clone(), id));

        let Some(rule) = IRQS
            .iter()
            .find(|rule| rule.domain == domain && rule.id == id)
        else {
            findings.push(format!(
                "{site} is an interrupt grant no rule in sysdesc.rs names, so the input it binds \
                 to this domain is compared against nothing. An `<irq>` is what decides which \
                 domain the hardware may enter and which input the kernel will let it \
                 acknowledge — a capability change, reviewed and approved rather than merged. \
                 Record it in IRQS once it is"
            ));
            continue;
        };
        check_irq_input(&site, rule, element, findings);
    }

    // As in [`check_io_ports`]: while the domain vocabularies disagree, every
    // rule here would report a grant that vanished.
    if !domains_agree {
        return;
    }
    for rule in IRQS {
        if !held
            .iter()
            .any(|(domain, id)| domain == rule.domain && *id == rule.id)
        {
            findings.push(format!(
                "sysdesc.rs records {:?} as holding interrupt id {:?}, and the description \
                 declares no such <irq>. Either the grant was dropped — and that domain arms a \
                 timer whose interrupt reaches nobody, leaving every schedule in this appliance \
                 waiting on traffic to advance — or the rule is stale and still judging a \
                 topology this file left behind",
                rule.domain, rule.id
            ));
        }
    }
}

/// The input and delivery mode one `<irq>` grants, against the rule that admits
/// them.
///
/// The pin because a grant on a different input is one the granted domain's own
/// programming will never raise, and the trigger because it decides what the
/// handler owes the device on every interrupt.
fn check_irq_input(site: &str, rule: &IrqRule, element: &Element, findings: &mut Vec<String>) {
    if let Some(raw) = required(element, "pin", findings) {
        match parse_int(raw) {
            Err(why) => findings.push(format!("{site} has pin={raw:?}, which {why}")),
            Ok(value) if value != rule.pin.value => findings.push(format!(
                "{site} grants pin={value} and {} is {}. The description and the domain state \
                 one input between them — that domain programs its timer to drive the one it \
                 compiled against — so a pin this file moved is an interrupt raised where \
                 nothing is listening and a handler woken by nothing. What the grant as \
                 approved withholds: {}",
                rule.pin.rust_name, rule.pin.value, rule.withheld
            )),
            Ok(_) => {}
        }
    }
    if let Some(trigger) = required(element, "trigger", findings)
        && trigger != rule.trigger
    {
        findings.push(format!(
            "{site} is {trigger:?}-triggered and sysdesc.rs records {:?}. The two modes oblige \
             the handler differently — a level-triggered input stays asserted until the device \
             is written back, and the domain that takes this one holds no path to write it — so \
             a mode changed here is a node that takes one interrupt and never another",
            rule.trigger
        ));
    }
}

/// No domain reaches an `<irq>` and a `<channel>` end through the same id.
///
/// Microkit gives a protection domain one notification word and one `Channel`
/// namespace over it, so an interrupt and a peer's channel numbered alike are
/// one bit with two meanings: the domain would acknowledge an interrupt it was
/// never raised, or take a peer's signal for a timer. The two tables above judge
/// each namespace separately and neither can see the collision, so it is checked
/// here, across both.
fn check_channel_ids_are_disjoint(elements: &[Element], findings: &mut Vec<String>) {
    for irq in elements.iter().filter(|e| e.tag == "irq") {
        let domain = irq.owner();
        let Some(id) = irq.attribute("id") else {
            continue;
        };
        for end in elements.iter().filter(|e| e.tag == "end") {
            if end.attribute("pd") == Some(domain.as_str()) && end.attribute("id") == Some(id) {
                findings.push(format!(
                    "line {}: <irq id={id:?}> in {domain} and the <end> at line {} share one \
                     channel id. A protection domain reaches both through `Channel::new({id})`, \
                     so the interrupt and the peer's notification would be one bit — and the \
                     domain would acknowledge an interrupt on a peer's signal, or take a peer's \
                     signal for the passage of time",
                    irq.line, end.line
                ));
            }
        }
    }
}

/// One attribute an element must carry, or a finding naming what is missing.
fn required<'a>(element: &'a Element, name: &str, findings: &mut Vec<String>) -> Option<&'a str> {
    let value = element.attribute(name);
    if value.is_none() {
        findings.push(format!(
            "line {}: <{}> carries no {name:?} attribute, so there is nothing to compare",
            element.line, element.tag
        ));
    }
    value
}

/// One element the scanner recognised.
#[derive(Debug, PartialEq, Eq)]
struct Element {
    tag: String,
    /// In source order, so a diagnostic reads like the file.
    attributes: Vec<(String, String)>,
    /// The `name` attribute of the nearest enclosing element — the protection
    /// domain a `<map>` sits in — where it has one.
    parent_name: Option<String>,
    /// 1-based, and the only thing that locates a `<channel>`'s ends: channels
    /// are unnamed, so a finding about one has nothing else to point at.
    line: usize,
}

impl Element {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(attribute, _)| attribute == name)
            .map(|(_, value)| value.as_str())
    }

    /// Where a nested element sits, for a finding that has to say which domain
    /// made the grant.
    fn owner(&self) -> String {
        match &self.parent_name {
            Some(name) => name.clone(),
            None => "no enclosing named element".to_owned(),
        }
    }
}

/// An element opened and not yet closed.
struct Open {
    tag: String,
    name: Option<String>,
    line: usize,
}

/// What reading one start tag produced.
struct StartTag {
    attributes: Vec<(String, String)>,
    /// `<x />` rather than `<x>`, so nothing nests inside it.
    self_closing: bool,
    /// The index just past the closing `>` or `/>`.
    next: usize,
}

/// Every element in document order, with comments, the XML declaration and
/// whitespace discarded.
///
/// Not a parser and not trying to be: it decides which lexical state each byte
/// is in, which is exactly what separates an attribute from a sentence about
/// one. Everything it cannot classify is an error.
fn scan(text: &[u8]) -> Result<Vec<Element>, String> {
    if let Err(error) = std::str::from_utf8(text) {
        return Err(format!(
            "line {}: the description is not valid UTF-8 ({error}). It declares that encoding and \
             is read under it, so a byte outside it is a document no conformant parser accepts",
            line_of(text, error.valid_up_to())
        ));
    }

    let mut elements = Vec::new();
    let mut open: Vec<Open> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();
    let mut at = 0;

    while at < text.len() {
        let Some(start) = find(text, at, b"<") else {
            reject_character_data(text, at, text.len())?;
            break;
        };
        reject_character_data(text, at, start)?;
        at = start;

        if starts_with(text, at, b"<!--") {
            at = skip_comment(text, at)?;
        } else if starts_with(text, at, b"<?") {
            at = skip_processing_instruction(text, at)?;
        } else if starts_with(text, at, b"<!") {
            return Err(format!(
                "line {}: a `<!` declaration (a DOCTYPE or a CDATA section) is markup this \
                 scanner does not model, and guessing at its extent is how the rest of the file \
                 stops being read correctly",
                line_of(text, at)
            ));
        } else if starts_with(text, at, b"</") {
            at = close_element(text, at, &mut open)?;
        } else {
            if open.is_empty() {
                roots.push(line_of(text, at));
            }
            at = open_element(text, at, &mut open, &mut elements)?;
        }
    }

    if let Some(unclosed) = open.last() {
        return Err(format!(
            "line {}: <{}> is opened here and never closed",
            unclosed.line, unclosed.tag
        ));
    }

    match roots.as_slice() {
        [_] => Ok(elements),
        [] => Err(
            "the description declares no root element, so there is no system for Microkit to \
             assemble and nothing here to hold to the constants"
                .to_owned(),
        ),
        [_, second, ..] => Err(format!(
            "line {second}: a second top-level element opens here. XML gives a document exactly \
             one root, so everything from this point on is content a conformant parser refuses \
             to read rather than a second half of the system"
        )),
    }
}

/// Skip one `<!-- ... -->`, holding its body to the one rule XML puts on it.
///
/// Finding the terminator and skipping to it is what let a `--` through: to a
/// search that wants only the first `-->`, the two hyphens that close a comment
/// and the two hyphens someone typed as a horizontal rule are the same bytes.
/// Walking the body is what tells them apart.
fn skip_comment(text: &[u8], at: usize) -> Result<usize, String> {
    let mut cursor = at + 4;
    loop {
        if starts_with(text, cursor, b"-->") {
            return Ok(cursor + 3);
        }
        if cursor >= text.len() {
            return Err(format!(
                "line {}: an XML comment opens here and is never closed with `-->`, so \
                 everything after it was about to be read as markup",
                line_of(text, at)
            ));
        }
        if starts_with(text, cursor, b"--") {
            return Err(format!(
                "line {}: this comment's body carries `--`, which XML admits only as the opening \
                 of the closing `-->`. The Microkit tool refuses the document over it, so a \
                 description that reads perfectly well here assembles into no image at all",
                line_of(text, cursor)
            ));
        }
        cursor += 1;
    }
}

/// Skip one `<? ... ?>`, refusing an XML declaration anywhere but the first byte.
fn skip_processing_instruction(text: &[u8], at: usize) -> Result<usize, String> {
    let end = find(text, at + 2, b"?>").ok_or_else(|| {
        format!(
            "line {}: a processing instruction opens here and is never closed with `?>`",
            line_of(text, at)
        )
    })?;
    if at != 0
        && read_name(text, at + 2).is_some_and(|(target, _)| target.eq_ignore_ascii_case("xml"))
    {
        return Err(format!(
            "line {}: an XML declaration appears here rather than as the document's very first \
             byte, which is the only place XML admits one — a comment or even a space in front of \
             it is enough to make the document one Microkit will not read",
            line_of(text, at)
        ));
    }
    Ok(end + 2)
}

/// Read one start tag, emit its element, and push it if it stays open.
fn open_element(
    text: &[u8],
    at: usize,
    open: &mut Vec<Open>,
    elements: &mut Vec<Element>,
) -> Result<usize, String> {
    let line = line_of(text, at);
    let (tag, after_tag) = read_name(text, at + 1)
        .ok_or_else(|| format!("line {line}: `<` is not followed by an element name"))?;
    let start = read_attributes(text, after_tag, &tag, line)?;

    // Read off the stack before this element joins it, so an element's own
    // `name` can never be handed to it as its parent's.
    let parent_name = open.last().and_then(|parent| parent.name.clone());
    let self_closing = start.self_closing;
    elements.push(Element {
        tag: tag.clone(),
        parent_name,
        line,
        attributes: start.attributes,
    });
    if !self_closing {
        let name = elements
            .last()
            .and_then(|element| element.attribute("name"))
            .map(str::to_owned);
        open.push(Open { tag, name, line });
    }
    Ok(start.next)
}

/// Read one end tag and match it against the innermost open element.
fn close_element(text: &[u8], at: usize, open: &mut Vec<Open>) -> Result<usize, String> {
    let line = line_of(text, at);
    let (tag, after_tag) = read_name(text, at + 2)
        .ok_or_else(|| format!("line {line}: `</` is not followed by an element name"))?;
    let next = skip_whitespace(text, after_tag);
    if text.get(next) != Some(&b'>') {
        return Err(format!(
            "line {line}: the end tag `</{tag}` is not closed by `>`"
        ));
    }
    match open.pop() {
        Some(opened) if opened.tag == tag => Ok(next + 1),
        Some(opened) => Err(format!(
            "line {line}: `</{tag}>` closes an element that is not open; <{}> was opened at line \
             {} and is still open",
            opened.tag, opened.line
        )),
        None => Err(format!(
            "line {line}: `</{tag}>` closes an element that was never opened"
        )),
    }
}

/// Read a start tag's attributes up to `>` or `/>`.
fn read_attributes(text: &[u8], mut at: usize, tag: &str, line: usize) -> Result<StartTag, String> {
    let mut attributes: Vec<(String, String)> = Vec::new();
    let mut previous: Option<String> = None;
    loop {
        let before = at;
        at = skip_whitespace(text, at);
        let separated = at > before;
        match text.get(at) {
            None => {
                return Err(format!(
                    "line {line}: the tag `<{tag}` is opened here and never closed by `>` or `/>`"
                ));
            }
            Some(b'>') => {
                return Ok(StartTag {
                    attributes,
                    self_closing: false,
                    next: at + 1,
                });
            }
            Some(b'/') if text.get(at + 1) == Some(&b'>') => {
                return Ok(StartTag {
                    attributes,
                    self_closing: true,
                    next: at + 2,
                });
            }
            Some(_) => {}
        }

        if let Some(previous) = &previous
            && !separated
        {
            return Err(format!(
                "line {}: <{tag}> runs the value of `{previous}` straight into what follows it. \
                 XML requires whitespace between two attributes, so this is a document the \
                 Microkit tool refuses rather than a tag with a compact spelling",
                line_of(text, at)
            ));
        }

        let (name, after_name) = read_name(text, at).ok_or_else(|| {
            format!(
                "line {}: <{tag}> carries something that is neither an attribute name nor the \
                 end of the tag",
                line_of(text, at)
            )
        })?;
        let after_name = skip_whitespace(text, after_name);
        if text.get(after_name) != Some(&b'=') {
            return Err(format!(
                "line {}: the attribute `{name}` of <{tag}> is not followed by `=`; a bare \
                 attribute is not something this scanner can assign a value",
                line_of(text, at)
            ));
        }
        let value_at = skip_whitespace(text, after_name + 1);
        let quote = match text.get(value_at) {
            Some(&quote @ (b'"' | b'\'')) => quote,
            _ => {
                return Err(format!(
                    "line {}: the value of `{name}` in <{tag}> is not quoted",
                    line_of(text, at)
                ));
            }
        };
        let end = find(text, value_at + 1, &[quote]).ok_or_else(|| {
            format!(
                "line {}: the value of `{name}` in <{tag}> opens with {} and is never closed, so \
                 the rest of the file was about to be read as this one value",
                line_of(text, value_at),
                quote as char
            )
        })?;
        let value = utf8(&text[value_at + 1..end], "an attribute value")?;
        check_attribute_value(&value, &name, tag, line_of(text, value_at))?;

        if attributes.iter().any(|(seen, _)| *seen == name) {
            return Err(format!(
                "line {line}: <{tag}> carries `{name}` twice, and which of the two Microkit \
                 honours is not something this gate may assume"
            ));
        }
        previous = Some(name.clone());
        attributes.push((name, value));
        at = end + 1;
    }
}

/// Hold an attribute value to the characters XML lets one carry.
///
/// The quotes bound the value for this scanner, which is why it read anything
/// between them; they do not bound it for an XML parser, which still owes the
/// three refusals below. A `<` here is the one that bites in practice: the file
/// explains markup by quoting it, and an author who moves such a quotation out
/// of a comment and into a `name` writes a description that stops being a
/// document.
fn check_attribute_value(value: &str, name: &str, tag: &str, line: usize) -> Result<(), String> {
    let refuse = |why: &str| {
        Err(format!(
            "line {line}: the value of `{name}` in <{tag}> {why}, so the Microkit tool refuses to \
             read the description at all"
        ))
    };
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => return refuse("carries a raw `<`, which XML forbids in an attribute value"),
            b'&' => {
                let rest = &value[index + 1..];
                let Some(body) = rest.split_once(';').map(|(body, _)| body) else {
                    return refuse(
                        "carries an `&` that never reaches a `;`, so it opens a \
                                   reference XML cannot end",
                    );
                };
                if !is_defined_reference(body) {
                    return refuse(&format!(
                        "carries `&{body};`, which is neither a character reference nor one of \
                         the five entities XML defines without a document type"
                    ));
                }
                index += body.len() + 2;
                continue;
            }
            byte if byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r') => {
                return refuse(&format!(
                    "carries the control character 0x{byte:02x}, which XML admits nowhere in a \
                     document"
                ));
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

/// Whether `&<body>;` names something in a document with no document type: a
/// decimal or hexadecimal character reference, or one of the five entities XML
/// itself defines. Everything else is undefined, and an undefined entity is a
/// refusal rather than a warning.
fn is_defined_reference(body: &str) -> bool {
    if matches!(body, "amp" | "lt" | "gt" | "apos" | "quot") {
        return true;
    }
    let Some(number) = body.strip_prefix('#') else {
        return false;
    };
    // XML spells a hexadecimal character reference with a lower-case `x` only.
    match number.strip_prefix('x') {
        Some(hex) => !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()),
    }
}

/// Read an XML name at `at`, returning it and the index just past it. `None`
/// when no name starts there.
fn read_name(text: &[u8], at: usize) -> Option<(String, usize)> {
    let start = at;
    if !text
        .get(start)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let mut end = start + 1;
    while text.get(end).is_some_and(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
    }) {
        end += 1;
    }
    // Every byte accepted above is ASCII, so this cannot split a character.
    Some((String::from_utf8_lossy(&text[start..end]).into_owned(), end))
}

/// Refuse non-whitespace text between elements. The description has none, and
/// a scanner that skips content it does not model is a scanner whose silence
/// means nothing.
fn reject_character_data(text: &[u8], from: usize, to: usize) -> Result<(), String> {
    match text[from..to]
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
    {
        None => Ok(()),
        Some(offset) => Err(format!(
            "line {}: character data outside any element. The system description carries none, \
             so this is either a typo or content this scanner does not model",
            line_of(text, from + offset)
        )),
    }
}

/// A Microkit SDF integer: decimal, or hexadecimal behind `0x`, either of which
/// may carry `_` separators — the description writes addresses that way.
fn parse_int(raw: &str) -> Result<u64, String> {
    let digits: String = raw.chars().filter(|byte| *byte != '_').collect();
    let (body, radix) = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(body) => (body, 16),
        None => (digits.as_str(), 10),
    };
    // `from_str_radix` accepts a leading sign, so `0x+10` would parse as 16.
    // Nothing about a byte count is signed; reject the shape outright.
    let admissible = |character: char| match radix {
        16 => character.is_ascii_hexdigit(),
        _ => character.is_ascii_digit(),
    };
    if body.is_empty() || !body.chars().all(admissible) {
        return Err(
            "is not a Microkit SDF integer (decimal, or hexadecimal behind `0x`, with `_` \
             permitted as a separator)"
                .to_owned(),
        );
    }
    u64::from_str_radix(body, radix)
        .map_err(|_| "does not fit in 64 bits, so it cannot be the extent of anything".to_owned())
}

fn utf8(bytes: &[u8], what: &str) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|error| format!("{what} is not valid UTF-8: {error}"))
}

fn find(text: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= text.len() {
        return None;
    }
    text[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

fn starts_with(text: &[u8], at: usize, prefix: &[u8]) -> bool {
    text.len() >= at + prefix.len() && &text[at..at + prefix.len()] == prefix
}

fn skip_whitespace(text: &[u8], mut at: usize) -> usize {
    while text.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

/// A count and its noun, agreeing in number.
///
/// Worth four lines rather than an `s` in the format string: the description is
/// expected to declare exactly one I/O-port window and to go on declaring
/// exactly one, that being the property [`IO_PORTS`] holds it to — so the
/// passing gate would otherwise report "1 I/O-port windows" on every run for as
/// long as the system is in the shape it is supposed to be in.
fn counted(count: usize, noun: &str) -> String {
    match count {
        1 => format!("1 {noun}"),
        _ => format!("{count} {noun}s"),
    }
}

/// The 1-based line `at` falls on.
fn line_of(text: &[u8], at: usize) -> usize {
    1 + text[..at.min(text.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The description as committed. Every negative test below starts from a
    /// single edit to it, so what each one proves is that *that* edit is
    /// caught — not that some hand-written fragment fails for its own reasons.
    fn committed() -> String {
        let root = crate::util::workspace_root().expect("the workspace root");
        fs::read_to_string(root.join(SYSTEM_DESCRIPTION)).expect("the system description")
    }

    /// The findings for a description with one substring replaced, asserting
    /// the edit actually applied: a `replace` that matched nothing would leave
    /// the committed file, which passes, and the test would prove the opposite
    /// of what it claims.
    fn findings_after(from: &str, to: &str) -> Vec<String> {
        let text = committed();
        assert!(
            text.contains(from),
            "the negative test edits {from:?}, which the description no longer contains"
        );
        let edited = text.replacen(from, to, 1);
        findings(&scan(edited.as_bytes()).expect("the edited description still scans"))
    }

    fn only_finding(findings: &[String]) -> &str {
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one finding: {findings:#?}"
        );
        &findings[0]
    }

    #[test]
    fn the_committed_description_agrees_with_the_constants() {
        // The check the gate runs, against the real file and the real
        // constants. Every other test here is only meaningful because this one
        // holds.
        let root = crate::util::workspace_root().expect("the workspace root");
        check(&root).expect("the committed system description");
    }

    #[test]
    fn a_stack_size_is_never_read_as_a_region_size() {
        // The trap this scanner exists to avoid: `stack_size` ends in `size`,
        // it carries a plausible byte count, and every protection domain has
        // one. A substring search for `size=` finds three of them before it
        // finds a memory region.
        let elements = scan(committed().as_bytes()).unwrap();
        let domains: Vec<&Element> = elements
            .iter()
            .filter(|element| element.tag == "protection_domain")
            .collect();
        assert!(!domains.is_empty(), "the description declares domains");
        for domain in domains {
            assert!(
                domain.attribute("stack_size").is_some(),
                "the trap only exists while the domains carry it"
            );
            assert!(
                domain.attribute("size").is_none(),
                "`stack_size` must not be readable as `size`"
            );
        }
        for region in elements
            .iter()
            .filter(|element| element.tag == "memory_region")
        {
            assert!(region.attribute("size").is_some());
            assert!(region.attribute("stack_size").is_none());
        }
    }

    #[test]
    fn markup_quoted_inside_a_comment_is_not_markup() {
        // The description explains `<end>` and `cached="true"` by quoting them,
        // so a scanner that does not track comments reads the explanation as
        // the thing explained.
        let text = concat!(
            "<system>\n",
            "  <!-- an <end pd=\"forwarder\" notify=\"true\" /> would grant a send capability,\n",
            "       and a <map mr=\"pool0\" perms=\"rw\" /> here would hand the forwarder every\n",
            "       frame in flight -->\n",
            "  <memory_region name=\"pool0\" size=\"0x20000\" />\n",
            "</system>\n"
        );
        let elements = scan(text.as_bytes()).unwrap();
        let tags: Vec<&str> = elements.iter().map(|e| e.tag.as_str()).collect();
        assert_eq!(tags, ["system", "memory_region"]);
        assert_eq!(elements[1].attribute("size"), Some("0x20000"));
    }

    #[test]
    fn a_short_region_is_reported_against_the_constant_it_must_equal() {
        // The defect the whole module exists for: the mapping is truncated and
        // nothing says so until a protection domain reads past the end of it.
        let findings = findings_after(
            "<memory_region name=\"pool0\" size=\"0x20000\"",
            "<memory_region name=\"pool0\" size=\"0x1f000\"",
        );
        let finding = only_finding(&findings);
        assert!(finding.contains("pool0"), "{finding}");
        assert!(finding.contains("0x1f000"), "the file's side: {finding}");
        assert!(
            finding.contains("pd_runtime::POOL_REGION_SIZE"),
            "{finding}"
        );
        assert!(
            finding.contains(&format!("{POOL_REGION_SIZE:#x}")),
            "the code's side: {finding}"
        );
    }

    #[test]
    fn each_split_pipeline_region_is_measured_against_its_own_constant() {
        // Three region types of two distinct sizes, and the two 0x1000 ones are
        // interchangeable by inspection: a rule that named the wrong one of
        // FORWARD_REGION_SIZE and RETURN_REGION_SIZE would still pass today and
        // would stop being true the moment either type grew.
        for (region, size, constant) in [
            ("fwd1", "0x2000", "pd_runtime::FORWARD_REGION_SIZE"),
            ("free1", "0x1000", "pd_runtime::RETURN_REGION_SIZE"),
        ] {
            let findings = findings_after(
                &format!("<memory_region name=\"{region}\" size=\"{size}\""),
                &format!("<memory_region name=\"{region}\" size=\"0x3000\""),
            );
            let finding = only_finding(&findings);
            assert!(finding.contains(constant), "{region}: {finding}");
        }
    }

    #[test]
    fn a_short_virtqueue_or_bar_region_is_reported_too() {
        let vq = findings_after(
            "<memory_region name=\"vq1\" size=\"0x1000\"",
            "<memory_region name=\"vq1\" size=\"0x800\"",
        );
        assert!(
            only_finding(&vq).contains("nic_driver_core::bringup::VQ_REGION_SIZE"),
            "{vq:#?}"
        );
        let bar = findings_after(
            "<memory_region name=\"bar0\" size=\"0x4000\"",
            "<memory_region name=\"bar0\" size=\"0x40000\"",
        );
        assert!(
            only_finding(&bar).contains("nic_driver_core::bringup::BAR_WINDOW_SIZE"),
            "{bar:#?}"
        );
    }

    #[test]
    fn a_short_ecam_page_is_reported_against_the_constant_pci_config_bounds_against() {
        // `PciConfig::new` takes "the mapped 4 KiB ECAM page" as its premise
        // and pds/nic-driver names this file as what guarantees it. Every
        // capability-pointer and BAR offset the driver walks is bounded
        // against PCI_CONFIG_LEN, so a description granting less hands that
        // walk a window shorter than the one it proved itself safe within.
        for ecam in ["ecam0", "ecam1"] {
            let findings = findings_after(
                &format!("<memory_region name=\"{ecam}\" size=\"0x1000\""),
                &format!("<memory_region name=\"{ecam}\" size=\"0x800\""),
            );
            let finding = only_finding(&findings);
            assert!(finding.contains(ecam), "{finding}");
            assert!(finding.contains("virtio::pci::PCI_CONFIG_LEN"), "{finding}");
            assert!(
                finding.contains(&format!("{PCI_CONFIG_LEN:#x}")),
                "the code's side: {finding}"
            );
        }
    }

    #[test]
    fn a_dma_region_mapped_uncached_loses_the_premise_virtio_reasons_from() {
        let findings = findings_after(
            "<map mr=\"vq0\" vaddr=\"0x10_200_000\" perms=\"rw\" cached=\"true\"",
            "<map mr=\"vq0\" vaddr=\"0x10_200_000\" perms=\"rw\" cached=\"false\"",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("vq0") && finding.contains("nic_driver0"),
            "{finding}"
        );
        assert!(finding.contains("cache-coherent"), "{finding}");
    }

    #[test]
    fn one_pipeline_map_of_three_losing_cached_is_still_caught() {
        // fwd0 is mapped into the forwarder and into both drivers — the only
        // region still shared three ways after the split. A rule checked once
        // per region rather than once per map would pass on two correct
        // mappings and one wrong one.
        let findings = findings_after(
            "<map mr=\"fwd0\" vaddr=\"0x2_100_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"tx_fwd_vaddr\"",
            "<map mr=\"fwd0\" vaddr=\"0x2_100_000\" perms=\"rw\" cached=\"false\" setvar_vaddr=\"tx_fwd_vaddr\"",
        );
        assert!(
            only_finding(&findings).contains("nic_driver1"),
            "{findings:#?}"
        );
    }

    #[test]
    fn device_mmio_mapped_cached_is_reported() {
        let findings = findings_after(
            "<map mr=\"ecam0\" vaddr=\"0x10_000_000\" perms=\"rw\" cached=\"false\"",
            "<map mr=\"ecam0\" vaddr=\"0x10_000_000\" perms=\"rw\" cached=\"true\"",
        );
        assert!(
            only_finding(&findings).contains("reaches the cache and not the device"),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_forwarder_end_that_can_send_a_driver_is_reported() {
        // pds/nic-driver's claim that its own `notified` entrypoint is
        // unreachable by capability rested on nobody editing this attribute.
        // The forwarder does now hold one send capability — on the config
        // domain — which is exactly why the rule is keyed on the channel id:
        // these two ends are still granted in one direction only, and losing
        // that is a different edit from granting the third.
        let dropped = findings_after(
            "<end pd=\"forwarder\" id=\"0\" notify=\"false\" />",
            "<end pd=\"forwarder\" id=\"0\" />",
        );
        let finding = only_finding(&dropped);
        assert!(finding.contains("send capability"), "{finding}");
        assert!(
            finding.contains("pds/nic-driver"),
            "the claim is named: {finding}"
        );

        let flipped = findings_after(
            "<end pd=\"forwarder\" id=\"1\" notify=\"false\" />",
            "<end pd=\"forwarder\" id=\"1\" notify=\"true\" />",
        );
        assert!(
            only_finding(&flipped).contains("send capability"),
            "{flipped:#?}"
        );
    }

    #[test]
    fn a_configuration_end_that_cannot_send_is_reported_at_either_end() {
        // The other half of the bidirectional pair, and the half a rule keyed
        // on the domain alone could not have: the forwarder's third end must
        // send where its first two must not. Losing either direction stalls the
        // two-phase commit — the publisher never learns the generation was
        // staged, or the consumer never learns it was released — and the node
        // comes up on generation 0 with no error anywhere.
        for end in [
            "<end pd=\"config\" id=\"0\" notify=\"true\" />",
            "<end pd=\"forwarder\" id=\"2\" notify=\"true\" />",
        ] {
            let findings = findings_after(end, &end.replace("\"true\"", "\"false\""));
            assert!(
                only_finding(&findings).contains("cannot leave it"),
                "{end}: {findings:#?}"
            );
        }
    }

    #[test]
    fn a_handover_region_writable_by_the_domain_that_may_only_read_it_is_reported() {
        // What per-grant perms buy, and the edit no other check in this module
        // can see: both domains map both regions, so the mapper set is
        // unchanged, the cacheability is right, the size is right, and the
        // `<map>` is well formed. Only the authority moved — and with it the
        // property that makes the handover a protocol: a forwarder that could
        // write `cfg` rewrites the table it is about to be judged by, and a
        // publisher that could write `cfgack` forges the acknowledgement
        // releasing its own generation.
        for (region, vaddr, domain) in [
            ("cfg", "0x3_000_000", "forwarder"),
            ("cfgack", "0x3_008_000", "config"),
        ] {
            let findings = findings_after(
                &format!(
                    "<map mr=\"{region}\" vaddr=\"{vaddr}\" perms=\"r\" cached=\"true\" \
                     setvar_vaddr=\"{region}_vaddr\" />"
                ),
                &format!(
                    "<map mr=\"{region}\" vaddr=\"{vaddr}\" perms=\"rw\" cached=\"true\" \
                     setvar_vaddr=\"{region}_vaddr\" />"
                ),
            );
            let finding = only_finding(&findings);
            assert!(
                finding.contains(&format!("{domain:?}")) && finding.contains("\"rw\""),
                "{region}: {finding}"
            );
            assert!(finding.contains("capability change"), "{region}: {finding}");
        }
    }

    /// A grant that exists and that no code can reach: the shape the recorder's
    /// withdrawn `cfg` mapping had, and the one every other check in this module
    /// passes clean.
    #[test]
    fn a_mapping_no_symbol_addresses_is_reported() {
        let findings = findings_after(
            "<map mr=\"clock\" vaddr=\"0x3_009_000\" perms=\"r\" cached=\"true\" \
             setvar_vaddr=\"clock_vaddr\" />",
            "<map mr=\"clock\" vaddr=\"0x3_009_000\" perms=\"r\" cached=\"true\" />",
        );
        let finding = only_finding(&findings);
        assert!(finding.contains("names no setvar_vaddr"), "{finding}");
        assert!(finding.contains("authority with no consumer"), "{finding}");
        assert!(finding.contains("\"clock\""), "{finding}");
    }

    /// The console's `<ioport>` as the description writes it, and the anchor
    /// every I/O-port test edits.
    const COM1_GRANT: &str = "<ioport id=\"0\" addr=\"0x3f8\" size=\"8\" />";

    /// The PCI configuration address/data pair — the port grant the description
    /// names first among the ones it withholds, being a second path to every
    /// device's configuration space beside the ECAM mappings the drivers hold.
    /// Every negative test below moves or duplicates the window onto it, so
    /// what each one proves is that a *plausible* widening fails, not that a
    /// nonsense number does.
    const PCI_CONFIG_PORTS: &str = "0xcf8";

    #[test]
    fn an_io_port_grant_no_rule_names_is_reported() {
        // The shape the console change itself arrived in, on the domain it
        // would matter most: `<ioport>` is authority no `<map>` expresses, so a
        // driver that acquired one would hold a port instruction that executes
        // against whatever decodes the window — and every other check in this
        // module would pass over a well-formed element it does not model.
        let findings = findings_after(
            "<map mr=\"ecam0\" vaddr=\"0x10_000_000\" perms=\"rw\" cached=\"false\" setvar_vaddr=\"ecam_vaddr\" />",
            &format!(
                "<map mr=\"ecam0\" vaddr=\"0x10_000_000\" perms=\"rw\" cached=\"false\" setvar_vaddr=\"ecam_vaddr\" />\n        \
                 <ioport id=\"0\" addr=\"{PCI_CONFIG_PORTS}\" size=\"8\" />"
            ),
        );
        let finding = only_finding(&findings);
        assert!(finding.contains("nic_driver0"), "{finding}");
        assert!(finding.contains("no rule in sysdesc.rs names"), "{finding}");
        assert!(finding.contains("capability change"), "{finding}");
    }

    #[test]
    fn a_widened_or_moved_io_port_window_is_reported_against_the_constant_the_driver_uses() {
        // The two ways one granted window stops being the window that was
        // approved, and neither implies the other. A larger `size` keeps the
        // device and adds ports nobody reviewed; a moved `addr` keeps the count
        // and leaves the device entirely — here for the PCI configuration pair,
        // which is the one the description names as withheld.
        for (attribute, from, to, constant) in [
            ("size", "8", "16", "uart_16550::PORT_COUNT"),
            ("addr", "0x3f8", PCI_CONFIG_PORTS, "uart_16550::COM1_BASE"),
        ] {
            let findings = findings_after(
                COM1_GRANT,
                &COM1_GRANT.replace(
                    &format!("{attribute}=\"{from}\""),
                    &format!("{attribute}=\"{to}\""),
                ),
            );
            let finding = only_finding(&findings);
            assert!(finding.contains(constant), "{attribute}: {finding}");
            assert!(
                finding.contains("capability change"),
                "{attribute}: {finding}"
            );
            // And it says what the approved grant withholds, rather than only
            // which number to type back.
            assert!(
                finding.contains("0xCF8/0xCFC"),
                "the claim is quoted: {finding}"
            );
        }
    }

    #[test]
    fn a_dropped_io_port_grant_is_reported_as_loudly_as_a_widened_one() {
        // The other direction of the same table. A console with no port faults
        // on its first `out`, and takes with it the only device an operator
        // watches a failed boot on — so the silence would be reported by
        // nothing else at all.
        let findings = findings_after(COM1_GRANT, "");
        let finding = only_finding(&findings);
        assert!(
            finding.contains("\"console\"") && finding.contains("no such <ioport>"),
            "{finding}"
        );
    }

    #[test]
    fn one_domain_holding_two_grants_under_one_id_is_reported() {
        // A duplicate leaves the held *set* identical, so the set comparison
        // alone would pass it, and which of the two Microkit installs in the
        // I/O permission bitmap is not something this gate may assume.
        let findings = findings_after(
            COM1_GRANT,
            &format!(
                "{COM1_GRANT}\n        <ioport id=\"0\" addr=\"{PCI_CONFIG_PORTS}\" size=\"8\" />"
            ),
        );
        let joined = findings.join("\n");
        assert!(joined.contains("a second grant under an id"), "{joined}");
    }

    #[test]
    fn every_io_port_rule_names_a_domain_that_exists_and_an_id_once() {
        // The same hazard the region and channel tables carry, for the same
        // reason: `check_io_ports` answers with the first rule matching the
        // pair, so a second row under one id would be a window recorded,
        // believed, and never compared against anything.
        let mut seen: Vec<(&str, &str)> = Vec::new();
        for rule in IO_PORTS {
            assert!(
                DOMAINS.contains(&rule.domain),
                "the I/O-port rule for {:?} names no protection domain",
                rule.domain
            );
            assert!(
                !seen.contains(&(rule.domain, rule.id)),
                "{:?} carries two rules for I/O-port id {:?}, so only the first window is ever \
                 compared",
                rule.domain,
                rule.id
            );
            seen.push((rule.domain, rule.id));
        }
    }

    #[test]
    fn a_console_that_could_write_a_domains_ring_is_reported() {
        // Half of what the split into two regions per ring buys, and the half
        // no mapper set can see: both domains map both halves, the sizes are
        // right and the cacheability is right, so only the authority moved. A
        // console able to store into a slot or advance the cursor that
        // publishes one could attribute a line to a domain that never emitted
        // it — and it is the one domain whose output an operator reads as
        // testimony about the others.
        for (region, vaddr) in [
            ("log_forwarder", "0x4_000_000"),
            ("log_nic_driver0", "0x4_100_000"),
            ("log_nic_driver1", "0x4_200_000"),
            ("log_config", "0x4_300_000"),
        ] {
            let findings = findings_after(
                &format!(
                    "<map mr=\"{region}\" vaddr=\"{vaddr}\" perms=\"r\" cached=\"true\" \
                     setvar_vaddr=\"{region}_vaddr\" />"
                ),
                &format!(
                    "<map mr=\"{region}\" vaddr=\"{vaddr}\" perms=\"rw\" cached=\"true\" \
                     setvar_vaddr=\"{region}_vaddr\" />"
                ),
            );
            let finding = only_finding(&findings);
            assert!(
                finding.contains("\"console\"") && finding.contains("\"rw\""),
                "{region}: {finding}"
            );
            assert!(finding.contains("capability change"), "{region}: {finding}");
        }
    }

    #[test]
    fn a_writer_that_could_forge_its_own_consume_cursor_is_reported() {
        // The other half, in the other direction. A writer able to move the
        // console's consume cursor would reuse slots the console had not
        // rendered, discarding records while its own drop count stayed at zero
        // — silent loss reported as none, which is worse than loss.
        for domain in ["forwarder", "config"] {
            let findings = findings_after(
                &format!(
                    "<map mr=\"log_{domain}_consume\" vaddr=\"0x4_010_000\" perms=\"r\" \
                     cached=\"true\" setvar_vaddr=\"log_consume_vaddr\" />"
                ),
                &format!(
                    "<map mr=\"log_{domain}_consume\" vaddr=\"0x4_010_000\" perms=\"rw\" \
                     cached=\"true\" setvar_vaddr=\"log_consume_vaddr\" />"
                ),
            );
            let finding = only_finding(&findings);
            assert!(
                finding.contains(&format!("{domain:?}")) && finding.contains("\"rw\""),
                "{domain}: {finding}"
            );
        }
    }

    #[test]
    fn a_writer_reaching_another_writers_ring_is_reported() {
        // What the nine ring pairs isolate *between* writers, which is a mapping
        // rather than an authority and so is the one thing about a log region
        // the `withheld` claim has to say. A compromised parser domain that
        // could read a driver's ring would learn what it had said about itself;
        // one that could write it could rewrite or silence it.
        let findings = findings_after(
            "<map mr=\"log_nic_driver0\" vaddr=\"0x4_000_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"log_records_vaddr\" />",
            "<map mr=\"log_nic_driver0\" vaddr=\"0x4_000_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"log_records_vaddr\" />\n        \
             <map mr=\"log_config\" vaddr=\"0x4_400_000\" perms=\"r\" cached=\"true\" setvar_vaddr=\"peer_records_vaddr\" />",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("\"nic_driver0\"") && finding.contains("log_config"),
            "{finding}"
        );
        assert!(
            finding.contains("cannot silence it"),
            "the claim is quoted: {finding}"
        );
    }

    #[test]
    fn each_half_of_a_log_ring_is_measured_against_its_own_constant() {
        // Two region types whose rules are otherwise each other's mirror, and
        // the pair is interchangeable by inspection in exactly the way `fwd`
        // and `free` are: a rule that named the wrong one of
        // LOG_RECORDS_REGION_SIZE and LOG_CONSUME_REGION_SIZE would still be
        // wrong the moment either type grew.
        for (region, size, constant) in [
            ("log_forwarder", "0x5000", "wire::LOG_RECORDS_REGION_SIZE"),
            (
                "log_config_consume",
                "0x1000",
                "wire::LOG_CONSUME_REGION_SIZE",
            ),
        ] {
            let findings = findings_after(
                &format!("<memory_region name=\"{region}\" size=\"{size}\""),
                &format!("<memory_region name=\"{region}\" size=\"0x9000\""),
            );
            let finding = only_finding(&findings);
            assert!(finding.contains(constant), "{region}: {finding}");
        }
    }

    #[test]
    fn a_channel_end_on_the_console_is_reported() {
        // The four channels to the console were removed with the machinery that
        // fed them: a domain that never leaves `init` cannot observe a
        // notification, so a send capability on it is authority granted for
        // nothing. Their absence is a decision, and this is what holds it —
        // re-declaring one lands as an end no rule covers.
        let findings = findings_after(
            "<end pd=\"config\" id=\"0\" notify=\"true\" />",
            "<end pd=\"config\" id=\"0\" notify=\"true\" />\n    </channel>\n    <channel>\n        \
             <end pd=\"config\" id=\"1\" />\n        <end pd=\"console\" id=\"0\" notify=\"false\" />",
        );
        let joined = findings.join("\n");
        assert!(joined.contains("\"console\""), "{joined}");
        assert!(joined.contains("no rule in sysdesc.rs covers"), "{joined}");
    }

    #[test]
    fn a_driver_end_that_cannot_send_is_reported() {
        // The other half of "granted in one direction only": a driver that
        // cannot signal the forwarder forwards nothing.
        let findings = findings_after(
            "<end pd=\"nic_driver0\" id=\"0\" />",
            "<end pd=\"nic_driver0\" id=\"0\" notify=\"false\" />",
        );
        assert!(
            only_finding(&findings).contains("cannot leave it"),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_widened_grant_is_reported() {
        let findings = findings_after(
            "<map mr=\"fwd0\" vaddr=\"0x2_000_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"fwd0_vaddr\"",
            "<map mr=\"fwd0\" vaddr=\"0x2_000_000\" perms=\"rwx\" cached=\"true\" setvar_vaddr=\"fwd0_vaddr\"",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("\"rwx\"") && finding.contains("capability change"),
            "{finding}"
        );
    }

    #[test]
    fn a_return_ring_mapped_into_the_forwarder_is_reported() {
        // The property the region split still establishes, and the one edit
        // that would undo it. The pool grant this test used to be aimed at was
        // given deliberately when routing landed — a domain that rewrites a
        // header must reach the bytes — so what is left to defend is the `free`
        // ring: a forwarder holding one could hand a live DMA target back to be
        // issued a second time while a NIC is still writing it. Nothing about
        // the edit is malformed — it is a well-formed `<map>` with the right
        // perms, the right cacheability and a free vaddr — so no other check in
        // this module can see it, which is why the rule is a mapper set rather
        // than an attribute.
        for (ring, vaddr) in [("free0", "0x2_400_000"), ("free1", "0x2_500_000")] {
            let findings = findings_after(
                "<map mr=\"fwd0\" vaddr=\"0x2_000_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"fwd0_vaddr\" />",
                &format!(
                    "<map mr=\"fwd0\" vaddr=\"0x2_000_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"fwd0_vaddr\" />\n        \
                     <map mr=\"{ring}\" vaddr=\"{vaddr}\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"free_vaddr\" />"
                ),
            );
            let finding = only_finding(&findings);
            assert!(
                finding.contains("\"forwarder\"") && finding.contains(ring),
                "{finding}"
            );
            assert!(finding.contains("capability change"), "{finding}");
            // And it says what the withholding is worth, not merely that the
            // table disagrees.
            assert!(
                finding.contains("forge a return"),
                "the claim is quoted: {finding}"
            );
        }
    }

    #[test]
    fn a_driver_mapping_the_pool_it_receives_into_is_reported() {
        // Port 0 receives into pool0 and is granted its physical address alone;
        // a mapping would be authority with no use, and the DMA target the NIC
        // writes would additionally be reachable from the CPU side of the same
        // domain.
        let findings = findings_after(
            "<map mr=\"pool1\" vaddr=\"0x2_200_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"tx_pool_vaddr\" />",
            "<map mr=\"pool1\" vaddr=\"0x2_200_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"tx_pool_vaddr\" />\n        \
             <map mr=\"pool0\" vaddr=\"0x2_300_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"rx_pool_vaddr\" />",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("\"nic_driver0\"") && finding.contains("pool0"),
            "{finding}"
        );
        assert!(finding.contains("authority with no use"), "{finding}");
    }

    #[test]
    fn a_dropped_grant_is_reported_as_loudly_as_a_widened_one() {
        // The other direction of the same set. A domain that loses a mapping it
        // is written to attach faults on the vaddr at boot, which is the
        // failure this file exists to move to build time.
        let findings = findings_after(
            "<map mr=\"fwd1\" vaddr=\"0x2_100_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"fwd1_vaddr\" />",
            "",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("\"forwarder\"") && finding.contains("fwd1"),
            "{finding}"
        );
        assert!(finding.contains("faults on the vaddr"), "{finding}");
    }

    #[test]
    fn one_region_mapped_twice_into_one_domain_is_reported() {
        // A duplicate leaves the granted *set* identical, so the set comparison
        // alone would pass it. Two mappings of one region in one address space
        // is an alias no `attach_region!` site expects.
        let findings = findings_after(
            "<map mr=\"fwd0\" vaddr=\"0x2_000_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"fwd0_vaddr\" />",
            "<map mr=\"fwd0\" vaddr=\"0x2_000_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"fwd0_vaddr\" />\n        \
             <map mr=\"fwd0\" vaddr=\"0x2_300_000\" perms=\"rw\" cached=\"true\" setvar_vaddr=\"fwd0_alias\" />",
        );
        assert!(
            only_finding(&findings).contains("already maps"),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_domain_no_rule_names_is_reported_once_rather_than_per_grant() {
        // A renamed domain holds eight mappings and a channel end. Reporting it
        // at the declaration keeps the finding readable; reporting it per grant
        // would bury the rename under its own consequences.
        let findings = findings_after(
            "<protection_domain name=\"nic_driver1\"",
            "<protection_domain name=\"nic_driver_b\"",
        );
        let joined = findings.join("\n");
        assert!(joined.contains("\"nic_driver_b\""), "{joined}");
        assert!(
            joined.contains("named by no rule in sysdesc.rs"),
            "{joined}"
        );
        // And the rule set left judging a domain that no longer exists.
        assert!(
            joined.contains("does not declare"),
            "the stale side: {joined}"
        );
    }

    #[test]
    fn every_withheld_claim_withholds_the_region_from_some_domain() {
        // A claim on a rule that grants its region to every domain would read
        // as a defended exclusion and defend nothing — the coverage-shaped
        // failure this module refuses everywhere else.
        for rule in REGIONS.iter().filter(|rule| rule.withheld.is_some()) {
            assert!(
                DOMAINS.iter().any(|domain| rule.grant(domain).is_none()),
                "{} carries a withheld claim and is granted to every domain",
                rule.name
            );
        }
    }

    /// The management port's receive pool is read and never written, and the
    /// perms are the whole of that: a widening to read-write is a capability
    /// change like any other, and the finding quotes what the read-only grant
    /// was worth.
    #[test]
    fn a_domain_widening_the_management_receive_pool_to_write_is_reported() {
        let findings = findings_after(
            "<map mr=\"mgmt_rx_pool\" vaddr=\"0x2_004_000\" perms=\"r\"",
            "<map mr=\"mgmt_rx_pool\" vaddr=\"0x2_004_000\" perms=\"rw\"",
        );
        let finding = only_finding(&findings);
        assert!(finding.contains("mgmt_rx_pool"), "{finding}");
        assert!(finding.contains("\"management\""), "{finding}");
        assert!(
            finding.contains("perms=\"rw\"") && finding.contains("\"r\""),
            "the finding names both the grant and what was asked for: {finding}"
        );
    }

    /// The asymmetry the management domain's grant set rests on: it reads the
    /// configuration and holds no acknowledgement region, because it is not the
    /// consumer of the two-phase commit. A `cfgack` mapping is the edit that
    /// would make it one, and the finding quotes what its absence was worth.
    #[test]
    fn the_management_domain_reaching_the_acknowledgement_region_is_reported() {
        let findings = findings_after(
            "<map mr=\"endpoint\" vaddr=\"0x3_00b_000\" perms=\"r\" cached=\"true\" \
             setvar_vaddr=\"endpoint_vaddr\" />\n        <map mr=\"log_management\"",
            "<map mr=\"endpoint\" vaddr=\"0x3_00b_000\" perms=\"r\" cached=\"true\" \
             setvar_vaddr=\"endpoint_vaddr\" />\n        <map mr=\"cfgack\" vaddr=\"0x3_008_000\" \
             perms=\"rw\" cached=\"true\" setvar_vaddr=\"cfgack_vaddr\" />\n        \
             <map mr=\"log_management\"",
        );
        let finding = only_finding(&findings);
        assert!(finding.contains("cfgack"), "{finding}");
        assert!(finding.contains("\"management\""), "{finding}");
        assert!(
            finding.contains("reads the COMMITTED generation alone"),
            "the finding quotes what withholding it was worth: {finding}"
        );
    }

    /// The calibration's direction is the whole grant: every domain reads it and
    /// exactly one writes it, so a second writer is the finding. Any reader will
    /// do to prove it — the first in the description is the forwarder — because
    /// what is reported is the perms of a named domain against this table.
    #[test]
    fn a_reader_of_the_calibration_that_could_write_it_is_reported() {
        let findings = findings_after(
            "<map mr=\"clock\" vaddr=\"0x3_009_000\" perms=\"r\" cached=\"true\" \
             setvar_vaddr=\"clock_vaddr\" />",
            "<map mr=\"clock\" vaddr=\"0x3_009_000\" perms=\"rw\" cached=\"true\" \
             setvar_vaddr=\"clock_vaddr\" />",
        );
        let finding = only_finding(&findings);
        assert!(finding.contains("clock"), "{finding}");
        assert!(finding.contains("\"forwarder\""), "{finding}");
        assert!(finding.contains("capability change"), "{finding}");
    }

    /// And the other direction: a domain that stopped reading it would stamp no
    /// record, so a vanished grant is a finding exactly as a widened one is.
    #[test]
    fn a_domain_that_stops_reading_the_calibration_is_reported() {
        let findings = findings_after(
            "<map mr=\"clock\" vaddr=\"0x3_009_000\" perms=\"r\" cached=\"true\" \
             setvar_vaddr=\"clock_vaddr\" />\n        <map mr=\"log_forwarder\" \
             vaddr=\"0x4_000_000\" perms=\"r\"",
            "<map mr=\"log_forwarder\" vaddr=\"0x4_000_000\" perms=\"r\"",
        );
        let finding = only_finding(&findings);
        assert!(finding.contains("clock"), "{finding}");
        assert!(finding.contains("console"), "{finding}");
    }

    /// A rule granting its region to nobody is a real shape — a DMA target the
    /// owning driver holds only the physical address of — and this description
    /// happens to hold none today. The rendering is kept covered because the
    /// check is what tells that shape from a rule whose grants were forgotten.
    #[test]
    fn an_empty_grant_set_is_spelled_out_rather_than_printed_as_brackets() {
        let unmapped = RegionRule {
            name: "dma-only",
            size: ExpectedSize {
                rust_name: "pd_runtime::POOL_REGION_SIZE",
                bytes: POOL_REGION_SIZE,
            },
            cacheability: Cacheability::Cached,
            grants: &[],
            withheld: None,
        };
        assert_eq!(unmapped.granted_to(), "no protection domain at all");
        assert!(unmapped.grant("management").is_none());

        // With no claim, the emptiness itself is the finding: an unclaimed empty
        // grant set is what a forgotten one looks like.
        let mut findings = Vec::new();
        check_region_mappers(&unmapped, &[], &mut findings);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let finding = findings.join("");
        assert!(finding.contains("to no protection domain"), "{finding}");
        assert!(finding.contains("record the claim"), "{finding}");

        // With one, a holder is reported against it and the claim is quoted.
        let claimed = RegionRule {
            withheld: Some("nothing with a CPU may reach it"),
            ..unmapped
        };
        let mut findings = Vec::new();
        check_region_mappers(
            &claimed,
            &[("dma-only", String::from("management"))],
            &mut findings,
        );
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let finding = findings.join("");
        assert!(finding.contains("no protection domain at all"), "{finding}");
        assert!(finding.contains("nothing with a CPU"), "{finding}");
    }

    /// The management/dataplane mutual exclusion, in the direction that would
    /// put the routing stage on the management port.
    #[test]
    fn the_forwarder_reaching_a_management_region_is_reported() {
        let findings = findings_after(
            "<map mr=\"cfg\" vaddr=\"0x3_000_000\" perms=\"r\" cached=\"true\" \
             setvar_vaddr=\"cfg_vaddr\" />",
            "<map mr=\"mgmt_rx_fwd\" vaddr=\"0x3_000_000\" perms=\"rw\" cached=\"true\" \
             setvar_vaddr=\"mgmt_vaddr\" />",
        );
        let joined = findings.join("\n");
        assert!(joined.contains("\"forwarder\" maps"), "{joined}");
        assert!(
            joined.contains("isolates the management port from the dataplane"),
            "{joined}"
        );
    }

    #[test]
    fn every_rule_grants_its_region_to_domains_that_exist_and_each_of_them_once() {
        // A grant naming a domain outside DOMAINS could never match a `<map>`,
        // so it would report a dropped grant on every run — or, worse, sit in a
        // rule whose region is undeclared and report nothing at all.
        //
        // Naming one domain twice is the hazard that arrived with perms moving
        // into the grant: `RegionRule::grant` answers with the first row, so a
        // second one carrying different perms would be the narrower authority
        // recorded, believed, and never compared against anything.
        for rule in REGIONS {
            assert!(
                !rule.grants.is_empty() || rule.withheld.is_some(),
                "{} is granted to no domain at all and says nothing about why — the shape a \
                 rule takes when its grants were left out",
                rule.name
            );
            let mut seen: Vec<&str> = Vec::new();
            for grant in rule.grants {
                assert!(
                    DOMAINS.contains(&grant.domain),
                    "{} names {:?}, which is not a protection domain",
                    rule.name,
                    grant.domain
                );
                assert!(
                    !seen.contains(&grant.domain),
                    "{} grants {:?} twice, so only the first perms are ever compared",
                    rule.name,
                    grant.domain
                );
                seen.push(grant.domain);
            }
        }
    }

    #[test]
    fn every_channel_rule_names_a_domain_that_exists_and_an_id_once() {
        // The same hazard on the other keyed table, arrived for the same
        // reason: the key gained an id when the forwarder stopped being granted
        // every channel the same way, and `check_channel_ends` answers with the
        // first row that matches the pair.
        let mut seen: Vec<(&str, &str)> = Vec::new();
        for end in CHANNEL_ENDS {
            assert!(
                DOMAINS.contains(&end.domain),
                "the channel rule for {:?} names no protection domain",
                end.domain
            );
            assert!(
                !seen.contains(&(end.domain, end.id)),
                "{:?} carries two rules for channel id {:?}, so only the first direction is \
                 ever compared",
                end.domain,
                end.id
            );
            seen.push((end.domain, end.id));
        }
    }

    #[test]
    fn a_region_no_rule_names_is_reported_rather_than_skipped() {
        // The case the concurrent split of the pipeline region produces: a new
        // or renamed region whose size nothing here compares. It must fail
        // loudly, because entering the description unmodelled is entering it
        // exempt.
        let findings = findings_after(
            "<memory_region name=\"pool1\" size=\"0x20000\"",
            "<memory_region name=\"pool1_buffers\" size=\"0x20000\"",
        );
        let joined = findings.join("\n");
        assert!(joined.contains("pool1_buffers"), "{joined}");
        assert!(joined.contains("named by no rule"), "{joined}");
        // And the rule left matching nothing is reported as well, so a rename
        // cannot quietly retire the check for the region it replaced.
        assert!(joined.contains("defends nothing"), "{joined}");
    }

    #[test]
    fn a_removed_region_is_reported() {
        let findings = findings_after(
            "<memory_region name=\"vq1\" size=\"0x1000\" phys_addr=\"0x30001000\" />",
            "",
        );
        let joined = findings.join("\n");
        assert!(joined.contains("vq1"), "{joined}");
        assert!(
            joined.contains("defends nothing"),
            "the rule for it: {joined}"
        );
        assert!(
            joined.contains("does not declare"),
            "and the map that still names it: {joined}"
        );
    }

    #[test]
    fn a_duplicate_region_is_reported() {
        let findings = findings_after(
            "<memory_region name=\"vq1\" size=\"0x1000\" phys_addr=\"0x30001000\" />",
            "<memory_region name=\"vq1\" size=\"0x1000\" phys_addr=\"0x30001000\" />\n    \
             <memory_region name=\"vq1\" size=\"0x2000\" phys_addr=\"0x30002000\" />",
        );
        assert!(
            only_finding(&findings).contains("a second <memory_region> is named \"vq1\""),
            "{findings:#?}"
        );
    }

    #[test]
    fn an_element_type_the_check_cannot_judge_is_reported() {
        let findings = findings_after(
            "<program_image path=\"forwarder.elf\" />",
            "<program_image path=\"forwarder.elf\" />\n        <virtual_machine name=\"vm\" />",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("<virtual_machine>") && finding.contains("security change"),
            "{finding}"
        );
    }

    /// An `<irq>` is a modelled tag now, so the stop it used to cause has to be
    /// caused by the table instead: a grant no rule names is a domain the
    /// hardware may enter that nothing compared.
    #[test]
    fn an_interrupt_grant_no_rule_names_is_reported() {
        let findings = findings_after(
            "<program_image path=\"forwarder.elf\" />",
            "<program_image path=\"forwarder.elf\" />\n        \
             <irq id=\"3\" ioapic=\"0\" pin=\"11\" vector=\"1\" trigger=\"edge\" polarity=\"high\" />",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("<irq id=\"3\"> in forwarder")
                && finding.contains("no rule in sysdesc.rs names"),
            "{finding}"
        );
    }

    #[test]
    fn an_interrupt_moved_to_another_input_is_reported() {
        let findings = findings_after("pin=\"23\"", "pin=\"11\"");
        let finding = only_finding(&findings);
        assert!(
            finding.contains("grants pin=11") && finding.contains("lfw_hpet::INTERRUPT_PIN"),
            "{finding}"
        );
    }

    /// The mode decides what the handler owes the device on every interrupt, and
    /// the domain that takes this one holds no path to write the block back.
    #[test]
    fn an_interrupt_turned_level_triggered_is_reported() {
        let findings = findings_after("trigger=\"edge\"", "trigger=\"level\"");
        let finding = only_finding(&findings);
        assert!(finding.contains("\"level\"-triggered"), "{finding}");
    }

    #[test]
    fn a_withdrawn_interrupt_grant_is_reported() {
        let findings = findings_after(
            "        <irq id=\"0\" ioapic=\"0\" pin=\"23\" vector=\"0\" trigger=\"edge\" polarity=\"high\" />\n",
            "",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("declares no such <irq>") && finding.contains("\"clock\""),
            "{finding}"
        );
    }

    /// One notification word, one namespace: an interrupt and a peer's channel
    /// numbered alike are one bit with two meanings, and neither table above can
    /// see it on its own.
    #[test]
    fn an_interrupt_sharing_a_channel_id_with_a_peer_is_reported() {
        let findings = findings_after("<end pd=\"clock\" id=\"1\"", "<end pd=\"clock\" id=\"0\"");
        let joined = findings.join("\n");
        assert!(joined.contains("share one channel id"), "{joined}");
    }

    #[test]
    fn a_renamed_domain_does_not_make_its_channel_rule_pass_over_nothing() {
        let findings = findings_after("<end pd=\"forwarder\" id=\"0\"", "<end pd=\"fwd\" id=\"0\"");
        let joined = findings.join("\n");
        assert!(joined.contains("\"fwd\""), "{joined}");
        assert!(joined.contains("no rule in sysdesc.rs covers"), "{joined}");
    }

    #[test]
    fn a_region_mapped_nowhere_is_reported() {
        let findings = findings_after(
            "<map mr=\"ecam1\" vaddr=\"0x10_000_000\" perms=\"rw\" cached=\"false\" setvar_vaddr=\"ecam_vaddr\" />",
            "",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("\"nic_driver1\"") && finding.contains("ecam1"),
            "{finding}"
        );
        assert!(finding.contains("maps no such region"), "{finding}");
    }

    #[test]
    fn an_unterminated_comment_fails_loudly() {
        let text = "<system>\n  <!-- the rest of this file is now a comment\n  <memory_region \
                    name=\"vq0\" size=\"0x1000\" />\n</system>\n";
        let error = scan(text.as_bytes()).unwrap_err();
        assert!(error.contains("never closed with `-->`"), "{error}");
        assert!(error.contains("line 2"), "{error}");
    }

    #[test]
    fn an_unterminated_attribute_value_fails_loudly() {
        // One unbalanced quote swallows the remainder of the file into a single
        // attribute value, which is the shape in which every element after it
        // silently stops existing.
        let swallowed = scan(b"<system>\n  <memory_region name=\"vq0 />\n</system>\n").unwrap_err();
        assert!(swallowed.contains("never closed"), "{swallowed}");
        assert!(swallowed.contains("line 2"), "{swallowed}");

        // A misplaced quote instead re-pairs them, so `name` reads as
        // `vq0 size=` and the size is gone. It must not be read as a tag that
        // simply has no size — and what names it is the separation rule, which
        // is also what an XML parser objects to first: the re-paired value ends
        // hard against the digits that were meant to be a value of their own.
        let repaired =
            scan(b"<system>\n  <memory_region name=\"vq0 size=\"0x1000\" />\n</system>\n")
                .unwrap_err();
        assert!(
            repaired.contains("straight into what follows"),
            "{repaired}"
        );
        assert!(repaired.contains("line 2"), "{repaired}");
    }

    #[test]
    fn an_unterminated_element_fails_loudly() {
        let unclosed_tag = scan(b"<system>\n  <memory_region name=\"vq0\"\n").unwrap_err();
        assert!(
            unclosed_tag.contains("never closed by `>`"),
            "{unclosed_tag}"
        );

        let unclosed_element = scan(b"<system>\n  <channel>\n").unwrap_err();
        assert!(
            unclosed_element.contains("<channel> is opened"),
            "{unclosed_element}"
        );
        assert!(unclosed_element.contains("line 2"), "{unclosed_element}");

        let mismatched = scan(b"<system>\n  <channel>\n  </system>\n").unwrap_err();
        assert!(mismatched.contains("is still open"), "{mismatched}");

        let unopened = scan(b"</system>\n").unwrap_err();
        assert!(unopened.contains("never opened"), "{unopened}");
    }

    #[test]
    fn malformed_markup_fails_loudly_rather_than_being_skipped() {
        for (text, expected) in [
            (
                "<system><memory_region name size=\"0x1000\" /></system>",
                "is not followed by `=`",
            ),
            (
                "<system><memory_region name=vq0 size=\"0x1000\" /></system>",
                "is not quoted",
            ),
            (
                "<system><memory_region name=\"vq0\" name=\"vq1\" /></system>",
                "twice",
            ),
            (
                "<system><4region /></system>",
                "is not followed by an element name",
            ),
            (
                "<system>stray text</system>",
                "character data outside any element",
            ),
            ("<system><![CDATA[x]]></system>", "does not model"),
            ("<system><?php ?", "never closed with `?>`"),
        ] {
            let error = scan(text.as_bytes()).unwrap_err();
            assert!(error.contains(expected), "{text:?} produced {error:?}");
        }
    }

    #[test]
    fn a_comment_body_carrying_a_double_hyphen_fails_loudly() {
        // The defect that produced this check: a horizontal rule typed into one
        // of the description's comment blocks. Every table above still agreed,
        // the gate printed its passing line, and the Microkit tool then refused
        // the document — so the commit was qualified on the way in and no image
        // could be assembled from it.
        let text = committed().replacen(
            "<!-- ===================================================================",
            "<!-- -------------------------------------------------------------------",
            1,
        );
        let error = scan(text.as_bytes()).unwrap_err();
        assert!(error.contains("carries `--`"), "{error}");
        assert!(error.contains("assembles into no image"), "{error}");

        // A body that merely *ends* in a hyphen is the same rule and is the
        // shape a `find` for the terminator cannot see at all: the first `-->`
        // it lands on starts one byte late.
        let trailing = scan(b"<system><!-- a ---></system>").unwrap_err();
        assert!(trailing.contains("carries `--`"), "{trailing}");

        // And the rule must not swallow the comments the file actually has.
        assert!(scan(b"<system><!-- a - b --><!----><!--->--></system>").is_ok());
    }

    #[test]
    fn a_description_that_is_not_one_document_is_reported() {
        let two = scan(b"<system />\n<system />\n").unwrap_err();
        assert!(two.contains("a second top-level element"), "{two}");
        assert!(two.contains("line 2"), "{two}");

        let none = scan(b"<?xml version=\"1.0\"?>\n<!-- nothing here -->\n").unwrap_err();
        assert!(none.contains("no root element"), "{none}");
    }

    #[test]
    fn an_xml_declaration_anywhere_but_the_first_byte_is_reported() {
        // A space in front of it is enough for a conformant parser, which is
        // exactly the kind of edit a formatter or a paste makes silently.
        for text in [
            &b" <?xml version=\"1.0\"?><system />"[..],
            b"<!-- c --><?xml version=\"1.0\"?><system />",
            b"<system><?XML v?></system>",
        ] {
            let error = scan(text).unwrap_err();
            assert!(error.contains("very first byte"), "{error}");
        }
        assert!(scan(b"<?xml version=\"1.0\"?><system><?php x?></system>").is_ok());
    }

    #[test]
    fn attributes_that_are_not_separated_are_reported() {
        let error = scan(b"<system><map mr=\"cfg\"perms=\"r\" /></system>").unwrap_err();
        assert!(error.contains("straight into what follows"), "{error}");
    }

    #[test]
    fn an_attribute_value_carrying_what_xml_forbids_is_reported() {
        for (value, expected) in [
            ("a<b", "raw `<`"),
            ("a&b", "never reaches a `;`"),
            ("a&nbsp;b", "&nbsp;"),
            ("a&#X41;b", "&#X41;"),
            ("a&#;b", "&#;"),
            ("a\u{1}b", "0x01"),
        ] {
            let text = format!("<system><memory_region name=\"{value}\" /></system>");
            let error = scan(text.as_bytes()).unwrap_err();
            assert!(error.contains(expected), "{value:?} produced {error:?}");
            assert!(error.contains("refuses to read the description"), "{error}");
        }

        // What XML does admit stays admitted, or the check trades one wrong
        // verdict for another.
        assert!(
            scan(b"<system><memory_region name=\"a&amp;&lt;&#65;&#x41;b>c\" /></system>").is_ok()
        );
    }

    #[test]
    fn a_description_that_is_not_utf8_is_reported() {
        let error = scan(b"<system><!-- caf\xe9 --></system>").unwrap_err();
        assert!(error.contains("not valid UTF-8"), "{error}");
    }

    #[test]
    fn a_size_that_is_not_a_number_is_reported_rather_than_treated_as_zero() {
        for size in [
            "",
            "0x",
            "0x+10",
            "64KiB",
            "0xzz",
            "1.5",
            "-16",
            "0x1_0000_0000_0000_0000",
        ] {
            let elements = scan(
                format!("<system><memory_region name=\"vq0\" size=\"{size}\" /></system>")
                    .as_bytes(),
            )
            .unwrap();
            let mut findings = Vec::new();
            check_regions(&elements, &mut findings);
            assert!(
                findings.iter().any(|finding| finding.contains("size=")),
                "size={size:?} produced {findings:#?}"
            );
        }
    }

    #[test]
    fn a_passing_gate_counts_one_window_in_the_singular() {
        assert_eq!(counted(1, "I/O-port window"), "1 I/O-port window");
        assert_eq!(counted(0, "memory region"), "0 memory regions");
        assert_eq!(counted(22, "memory region"), "22 memory regions");
    }

    #[test]
    fn integers_are_read_in_every_shape_the_description_writes_them() {
        assert_eq!(parse_int("0x20000"), Ok(0x20000));
        assert_eq!(parse_int("0X1000"), Ok(0x1000));
        assert_eq!(parse_int("0x2_100_000"), Ok(0x2_100_000));
        assert_eq!(parse_int("4096"), Ok(4096));
        assert_eq!(parse_int("1_024"), Ok(1024));
        assert_eq!(parse_int("0"), Ok(0));
    }

    #[test]
    fn an_attribute_is_read_from_the_element_that_carries_it() {
        // Nesting is what keeps a `<map>`'s finding able to say which domain
        // made the grant, and what stops an attribute of one element being
        // attributed to its neighbour.
        let elements = scan(committed().as_bytes()).unwrap();
        let owners = |region| -> Vec<String> {
            elements
                .iter()
                .filter(|element| element.tag == "map" && element.attribute("mr") == Some(region))
                .map(Element::owner)
                .collect()
        };
        assert_eq!(owners("fwd0"), ["forwarder", "nic_driver0", "nic_driver1"]);
        // And the grant the split established, read straight off the file
        // rather than off this module's own table: each pool reaches the
        // forwarder and the driver that transmits out of it, and neither
        // `free` ring reaches the forwarder at all.
        assert_eq!(owners("pool0"), ["forwarder", "nic_driver1"]);
        assert_eq!(owners("pool1"), ["forwarder", "nic_driver0"]);
        assert_eq!(owners("free0"), ["nic_driver0", "nic_driver1"]);
        assert_eq!(owners("free1"), ["nic_driver0", "nic_driver1"]);
    }

    /// A description holding exactly the receive-pipeline mappings named, so the
    /// port-driver check can be driven one shape at a time rather than by editing
    /// the committed file into something that trips five other rules at once.
    fn receive_pipelines(mappings: &[(&str, &str)]) -> Vec<String> {
        let mut text = String::from("<system>");
        for (domain, region) in mappings {
            text.push_str(&format!(
                "<protection_domain name=\"{domain}\">\
                 <map mr=\"{region}\" vaddr=\"0x2_000_000\" perms=\"rw\" cached=\"true\" \
                 setvar_vaddr=\"rx_fwd_vaddr\" />\
                 </protection_domain>"
            ));
        }
        text.push_str("</system>");
        let elements = scan(text.as_bytes()).expect("the synthetic description scans");
        let mut findings = Vec::new();
        check_port_drivers(&elements, &mut findings);
        findings
    }

    /// The committed file, through this check alone: every port is driven by the
    /// domain `lfw_metrics` attributes it to, so the join key is one word on both
    /// sides. This is the positive half of the enforcer.
    #[test]
    fn every_port_is_driven_by_the_domain_the_metric_surface_attributes_it_to() {
        let elements = scan(committed().as_bytes()).expect("the description scans");
        let mut findings = Vec::new();
        check_port_drivers(&elements, &mut findings);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    /// The finding that matters: port 0's pipeline consumed by another domain. It
    /// is invisible in the file — one symbol on one line — and it would point
    /// every one of port 0's counter series at port 1's addressing.
    #[test]
    fn a_port_driven_by_another_domain_is_reported_against_the_metric_surface() {
        let findings = receive_pipelines(&[
            ("nic_driver1", "fwd0"),
            ("nic_driver0", "fwd1"),
            ("nic_driver2", "mgmt_rx_fwd"),
        ]);
        assert_eq!(findings.len(), 2, "{findings:#?}");
        let joined = findings.join("\n");
        assert!(
            joined.contains("lfw_metrics::PORT_DOMAINS"),
            "the finding names the constant it disagrees with: {joined}"
        );
        assert!(
            joined.contains("another port's addressing"),
            "and what the disagreement costs a scraper: {joined}"
        );
    }

    /// A port nothing drives, which is the shape of a dropped mapping: the
    /// constant still attributes it to a domain, and that identity would be joined
    /// to counters nobody publishes.
    #[test]
    fn a_port_no_domain_drives_is_reported() {
        let findings =
            receive_pipelines(&[("nic_driver1", "fwd1"), ("nic_driver2", "mgmt_rx_fwd")]);
        let finding = only_finding(&findings);
        assert!(finding.contains("fwd0"), "{finding}");
        assert!(finding.contains("nic_driver0"), "{finding}");
        assert!(finding.contains("port 0"), "{finding}");
    }

    /// Two consumers on one pipeline: which of them drives the port is then not
    /// stated at all, and a pipeline admits exactly one consumer.
    #[test]
    fn two_domains_consuming_one_pipeline_is_reported() {
        let findings = receive_pipelines(&[
            ("nic_driver0", "fwd0"),
            ("console", "fwd0"),
            ("nic_driver1", "fwd1"),
            ("nic_driver2", "mgmt_rx_fwd"),
        ]);
        let finding = only_finding(&findings);
        assert!(finding.contains("2 domains map"), "{finding}");
        assert!(finding.contains("exactly one consumer"), "{finding}");
    }

    /// A fourth port, which is how a port enters this system with its attribution
    /// compared against nothing.
    #[test]
    fn a_receive_pipeline_no_rule_names_is_reported() {
        let findings = receive_pipelines(&[
            ("nic_driver0", "fwd0"),
            ("nic_driver1", "fwd1"),
            ("nic_driver2", "mgmt_rx_fwd"),
            ("clock", "fwd2"),
        ]);
        let finding = only_finding(&findings);
        assert!(finding.contains("fwd2"), "{finding}");
        assert!(finding.contains("PORT_DOMAINS"), "{finding}");
    }
}
