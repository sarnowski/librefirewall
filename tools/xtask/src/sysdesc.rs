//! The Microkit system description read back into Rust and held to the
//! constants the protection domains compile against.
//!
//! `systems/qemu-x86_64/librefirewall.system` is consumed by the Microkit tool
//! and by nothing else, so every fact a crate compiles against it — a region's
//! extent, its cacheability, the perms it is granted under, *which domains map
//! it at all*, the direction a notification channel is granted in — was a
//! precondition delegated to a file no build step ever read (DOC-7). A
//! disagreement surfaced as a truncated mapping, a device register written
//! through a cached mapping, a domain reaching bytes it was meant never to
//! reach, or a missing signal — at boot, on the one path with no shell and no
//! operator (CONCEPT §11). This module is the enforcer those preconditions
//! name.
//!
//! # No adversary, and that is the point
//!
//! Nothing here reads hostile input: the file is source-controlled and is
//! edited by the same people who edit the constants it must agree with, so
//! CON-2 names no CONCEPT §7.1 adversary for this path. What it defends against
//! is the ordinary edit that moves one side and not the other — which is why
//! [`REGIONS`], [`DOMAINS`], [`CHANNEL_ENDS`] and [`MODELLED_TAGS`] are
//! *exhaustive* rather than best-effort. A region, a domain, a channel end, or
//! an element type this module does not name is a finding, not a silent skip: a
//! region nothing claims is a grant nothing compares, and it would enter the
//! description already exempt from the check that exists to judge it.
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
//! # Why the scanner is a scanner and not a substring search
//!
//! The file is written to be read by people, and two of its habits defeat the
//! obvious approach outright:
//!
//! * Every `<protection_domain>` carries `stack_size="0x4000"`. A search for
//!   `size=` matches it, and a checker built that way compares a stack against
//!   a memory region. Attribute names here are lexed whole and read from the
//!   element that carries them, so `stack_size` and `size` are two names and a
//!   `<protection_domain>` is not a `<memory_region>`.
//! * The file's comment blocks quote the very markup they explain — an `<end>`,
//!   a `cached="true"` — because that is how you explain it. Anything inside
//!   `<!-- -->` is markup to a substring search and to nothing else.
//!
//! Everything the scanner cannot classify stops the gate and names itself
//! (ENG-12): an unterminated comment, an unterminated attribute value, an
//! unterminated element, character data outside markup, an element type this
//! module does not model. A cross-check that passes on a file it did not
//! understand is worse than no cross-check, because it reports the agreement it
//! never established.

use std::{fs, path::Path};

use nic_driver_core::bringup::{BAR_WINDOW_SIZE, VQ_REGION_SIZE};
use pd_runtime::{FORWARD_REGION_SIZE, POOL_REGION_SIZE, RETURN_REGION_SIZE};
use virtio::pci::PCI_CONFIG_LEN;
use wire::{CONFIG_ACK_REGION_SIZE, CONFIG_REGION_SIZE};

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
    /// read (ENG-1).
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

    /// The domains this rule grants the region to, for a finding that has to
    /// name the set the description departed from.
    fn granted_to(&self) -> Vec<&'static str> {
        self.grants.iter().map(|grant| grant.domain).collect()
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
/// grant that was decided and approved rather than acquired (ENG-1, SCM-6).
/// What the region split still establishes is [`RETURN_WITHHELD`], and that is
/// the load-bearing one.
const POOL_WITHHELD: &str = "the receiving driver maps no pool of its own. It hands that pool's \
     physical address to its NIC as a DMA target and dereferences no byte of it, so a mapping \
     would be authority with no use (pds/nic-driver's crate header) — and the DMA target the \
     device writes would additionally become reachable from the CPU side of the same domain. The \
     forwarder's own pool mapping is not an exclusion this rule defends: it is granted, because a \
     domain that rewrites a header must reach the bytes";

/// As [`POOL_WITHHELD`], for the return rings — the exclusion the forwarder's
/// isolation now rests on entirely.
const RETURN_WITHHELD: &str = "the forwarder maps no return ring. It is a region of its own \
     rather than a third field beside `ForwardRings` precisely so that it can be withheld \
     (pd_runtime's `ReturnRing`: \"what denies the forwarder the ability to forge a return — the \
     one move that would put a live buffer back on an owner's free stack\"), and a forwarder that \
     could produce on it would be a second producer on a ring that admits exactly one. This is \
     what a compromised forwarder is still unable to do: it can corrupt a frame in flight, and it \
     cannot hand a live DMA target back to be issued a second time";

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
    // The configuration handover, and the one place in this description where
    // what a rule withholds is an authority rather than a mapping: both domains
    // map both regions, and each may write exactly the one it speaks in. That
    // is why a rule's perms are per grant. A `cfg` the forwarder could write
    // would let it rewrite the table it is about to be held to and leave the
    // publisher reporting a generation nobody runs; a `cfgack` the config
    // domain could write would let it forge the acknowledgement that releases
    // its own generation, which is the whole of what the second phase is for.
    // Neither exclusion — no driver maps either region — is claimed anywhere,
    // and a driver has no more use for a configuration image than for a
    // parser, so `withheld` is None and the perms carry the argument.
    RegionRule {
        name: "cfg",
        size: ExpectedSize {
            rust_name: "wire::CONFIG_REGION_SIZE",
            bytes: CONFIG_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_write("config"), read_only("forwarder")],
        withheld: None,
    },
    RegionRule {
        name: "cfgack",
        size: ExpectedSize {
            rust_name: "wire::CONFIG_ACK_REGION_SIZE",
            bytes: CONFIG_ACK_REGION_SIZE,
        },
        cacheability: Cacheability::Cached,
        grants: &[read_only("config"), read_write("forwarder")],
        withheld: None,
    },
];

/// Every protection domain the description may declare. Exhaustive in both
/// directions like the rest: the domain names are what [`RegionRule::mappers`]
/// and [`CHANNEL_ENDS`] are written in, so a domain renamed here and not there
/// would leave both tables judging a domain that no longer exists while the one
/// that replaced it is judged by nothing.
const DOMAINS: &[&str] = &["forwarder", "config", "nic_driver0", "nic_driver1"];

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
     one end this domain may send on, and it was granted deliberately (ENG-1, SCM-6); these two \
     were not";

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
];

/// Every element type this module knows how to judge. An element outside it
/// stops the gate rather than being skipped: `<irq>`, `<virtual_machine>` and
/// `<vcpu>` are all authority grants, and one arriving unnoticed is precisely
/// the capability change ENG-1 says must be looked at.
const MODELLED_TAGS: &[&str] = &[
    "system",
    "memory_region",
    "protection_domain",
    "program_image",
    "map",
    "setvar",
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
        println!(
            "sysdesc: {} declares {} memory regions granted by {} mappings and {} channel ends, \
             each sized, mapped and withheld as the code that maps it requires",
            path.display(),
            elements.iter().filter(|e| e.tag == "memory_region").count(),
            elements.iter().filter(|e| e.tag == "map").count(),
            elements.iter().filter(|e| e.tag == "end").count(),
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
    check_channel_ends(elements, &mut findings);
    findings
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
                 (MODELLED_TAGS), and treat the grant itself as the security change it is \
                 (ENG-1, SCM-6)",
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

    if rule.grants.is_empty() {
        findings.push(format!(
            "sysdesc.rs grants <memory_region name={:?}> to no protection domain, so whichever \
             domains map it are compared against nothing. Name them in `grants` — the empty set \
             says the region is reachable by nobody, which is not what a declared region is for",
            rule.name
        ));
        return;
    }

    let granted_to = rule.granted_to();
    for domain in &holders {
        if rule.grant(domain).is_none() {
            let mut finding = format!(
                "{domain:?} maps <memory_region name={:?}>, which sysdesc.rs grants to \
                 {granted_to:?} and to nothing else. A domain reaching a region it was withheld \
                 is a capability change, reviewed and approved rather than merged (ENG-1, SCM-6)",
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
         and approved rather than merged (ENG-1, SCM-6); record the new grant here once it is",
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

        // Microkit 2.3.0 §7.6: `notify` "indicates that the protection domain
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
    let mut elements = Vec::new();
    let mut open: Vec<Open> = Vec::new();
    let mut at = 0;

    while at < text.len() {
        let Some(start) = find(text, at, b"<") else {
            reject_character_data(text, at, text.len())?;
            break;
        };
        reject_character_data(text, at, start)?;
        at = start;

        if starts_with(text, at, b"<!--") {
            let end = find(text, at + 4, b"-->").ok_or_else(|| {
                format!(
                    "line {}: an XML comment opens here and is never closed with `-->`, so \
                     everything after it was about to be read as markup",
                    line_of(text, at)
                )
            })?;
            at = end + 3;
        } else if starts_with(text, at, b"<?") {
            let end = find(text, at + 2, b"?>").ok_or_else(|| {
                format!(
                    "line {}: a processing instruction opens here and is never closed with `?>`",
                    line_of(text, at)
                )
            })?;
            at = end + 2;
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
            at = open_element(text, at, &mut open, &mut elements)?;
        }
    }

    match open.last() {
        None => Ok(elements),
        Some(unclosed) => Err(format!(
            "line {}: <{}> is opened here and never closed",
            unclosed.line, unclosed.tag
        )),
    }
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
    loop {
        at = skip_whitespace(text, at);
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

        if attributes.iter().any(|(seen, _)| *seen == name) {
            return Err(format!(
                "line {line}: <{tag}> carries `{name}` twice, and which of the two Microkit \
                 honours is not something this gate may assume"
            ));
        }
        attributes.push((name, value));
        at = end + 1;
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
            ("cfgack", "0x3_001_000", "config"),
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
            assert!(finding.contains("ENG-1"), "{region}: {finding}");
        }
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
            finding.contains("\"rwx\"") && finding.contains("ENG-1"),
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
            assert!(finding.contains("ENG-1"), "{finding}");
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
                !rule.grants.is_empty(),
                "{} is granted to no domain at all",
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
            "<program_image path=\"forwarder.elf\" />\n        <irq irq=\"11\" id=\"3\" />",
        );
        let finding = only_finding(&findings);
        assert!(
            finding.contains("<irq>") && finding.contains("ENG-1"),
            "{finding}"
        );
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
        // simply has no size.
        let repaired =
            scan(b"<system>\n  <memory_region name=\"vq0 size=\"0x1000\" />\n</system>\n")
                .unwrap_err();
        assert!(
            repaired.contains("neither an attribute name nor the end of the tag"),
            "{repaired}"
        );
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
}
