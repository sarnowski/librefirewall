//! Where the three surfaces have to agree: the two recordings, the exposition,
//! and the frames the harness itself put on the wire.
//!
//! # Why this is not a fourth smoke check
//!
//! [`crate::metrics_contract`] judges the exposition and
//! [`crate::recording_contract`] judges a recording, each on its own terms and
//! each alone. Both can pass over a node that is quietly wrong, because the
//! failures worth catching here are not properties of one surface but
//! *disagreements between them*: a sink that silently drops a record still
//! answers a well-formed pcapng file; a counter that double-counts still
//! renders a valid exposition; a tap that loses an observation leaves both
//! surfaces internally consistent. None of the three notices. What notices is
//! holding them to each other and to the bytes the harness knows it injected,
//! which no surface has any way to agree with by construction (TEST-13).
//!
//! # Why a module of its own
//!
//! It is neither of the two it joins. Stated inside `recording_contract` it
//! would make that module a reader of Prometheus exposition; stated inside
//! `metrics_contract` it would make that one a reader of pcapng. Each stays
//! about one surface, and the agreement between them is this.
//!
//! # The judgement is a pure function
//!
//! [`judge`] takes parsed inputs and returns a verdict — no HTTP, no disk, no
//! QEMU — so every way the surfaces can disagree is exercised by a unit test
//! against synthetic recordings rather than by a ten-minute boot.
//!
//! # No adversary
//!
//! Build orchestration on the host side of an emulator (CON-2 names no CONCEPT
//! §7.1 adversary for it). The guest composes the recordings — that is the
//! point — and every walk over them is bounded by the body's own length
//! (ENG-4), refuses a malformed file by name rather than indexing off its end
//! (ENG-5), and is performed by [`crate::recording_contract::parse`] before a
//! byte reaches this module.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::recording_contract::{Packet, Parsed};

/// One frame the harness put on a dataplane port, as the contract compares
/// against it.
///
/// Owned here rather than in [`crate::forward_harness`] so the judgement below
/// depends on nothing that needs QEMU to construct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Injected {
    /// The probe that put it there, which is what names it in a verdict.
    pub name: &'static str,
    pub frame: Vec<u8>,
    /// Whether the appliance's tap must have observed this frame.
    ///
    /// Not every injected frame is one the recorder can be held to. The tap is
    /// driven from the forwarder's routing decision, and a frame the router's
    /// parser cannot read is discarded before any decision exists — see
    /// `Routed::Discarded` and its `observed` in
    /// `crates/pd-runtime/src/lib.rs`, which is where a frame stops producing
    /// an observation. So a probe that is not IPv4 at all is deliberately
    /// absent from both recordings, and demanding it would be asserting a
    /// contract the appliance does not have.
    pub observed: bool,
}

/// One recording as this contract sees it: which it is, what it declared, and
/// what the appliance's own metrics say it put there.
pub struct Surface<'a> {
    /// The request target it was pulled from, which names it in every verdict.
    pub target: &'static str,
    /// The sink's snap length as the build configures it. The recording states
    /// its own in every Interface Description Block, and the two are compared:
    /// that is what makes the two recordings demonstrably different files
    /// rather than one served twice.
    pub snap_len: u32,
    pub parsed: &'a Parsed,
    /// `librefirewall_recording_records_total` for this sink, read out of the
    /// exposition the same boot answered.
    pub published_records: u64,
}

/// What the harness knows independently of anything the appliance said.
pub struct Wire<'a> {
    pub injected: &'a [Injected],
    /// Dataplane ports the configuration document configures. Every recorded
    /// interface must be one of them and every packet must name one.
    pub ports: usize,
}

/// The counts one surface contributed, for the evidence a passing run leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counted {
    pub target: &'static str,
    pub packets: usize,
    pub published_records: u64,
    pub interfaces: usize,
    pub declared_snap_len: u32,
    pub longest_capture: usize,
}

/// What the run was found to hold, once every surface agreed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agreement {
    pub counted: Vec<Counted>,
    /// Probes that had to appear, and did.
    pub probes_matched: usize,
    /// Packet blocks paired 1:1 across the two recordings by `epb_packetid`.
    pub paired: usize,
}

impl Agreement {
    /// The counts from each surface side by side, which is what makes a run log
    /// useful to somebody debugging a later change rather than a record that
    /// something passed.
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut lines = vec![String::from(
            "  the three surfaces, held to each other and to the wire:",
        )];
        for counted in &self.counted {
            let mut line = String::new();
            let _ = write!(
                line,
                "    {}: {} packet block(s); the recorder publishes {} record(s) for this sink; \
                 {} interface block(s) declaring a snap length of {}; longest capture {}",
                counted.target,
                counted.packets,
                counted.published_records,
                counted.interfaces,
                counted.declared_snap_len,
                counted.longest_capture,
            );
            lines.push(line);
        }
        let mut line = String::new();
        let _ = write!(
            line,
            "    {} packet block(s) paired across both recordings by epb_packetid; {} distinct \
             injected probe(s) found byte-identically in the capture",
            self.paired, self.probes_matched,
        );
        lines.push(line);
        lines.join("\n")
    }
}

/// Hold the two recordings, the exposition and the wire to each other.
///
/// Every disagreement found is reported, not only the first: a run that has to
/// be repeated to see the second finding is a run that costs ten minutes to
/// learn one fact.
///
/// # Errors
/// The verdict, naming the surface, both numbers, and — for a packet that
/// matches nothing injected — the packet id and the offset it first differs at.
pub fn judge(log: &Surface, capture: &Surface, wire: &Wire) -> Result<Agreement, String> {
    let mut found = Vec::new();
    found.extend(pairing_differences(log, capture));
    for surface in [log, capture] {
        found.extend(published_differences(surface));
        found.extend(clamping_differences(surface));
        found.extend(interface_differences(surface, wire));
        found.extend(fabrication_differences(surface, wire));
    }
    found.extend(distinctness_differences(log, capture));
    let probes_matched = match presence_differences(capture, wire) {
        Ok(matched) => matched,
        Err(differences) => {
            found.extend(differences);
            0
        }
    };
    if !found.is_empty() {
        return Err(format!(
            "the recordings, the exposition and the wire do not agree in {} respect(s):\n{}",
            found.len(),
            found
                .iter()
                .map(|difference| format!("    - {difference}"))
                .collect::<Vec<String>>()
                .join("\n")
        ));
    }
    Ok(Agreement {
        counted: [log, capture].map(count).to_vec(),
        probes_matched,
        paired: log.parsed.packets.len(),
    })
}

fn count(surface: &Surface) -> Counted {
    Counted {
        target: surface.target,
        packets: surface.parsed.packets.len(),
        published_records: surface.published_records,
        interfaces: surface.parsed.interfaces.len(),
        declared_snap_len: surface
            .parsed
            .interfaces
            .first()
            .map_or(0, |interface| interface.snap_len),
        longest_capture: surface.parsed.longest_capture(),
    }
}

/// The two recordings hold the same observations: the same number of packet
/// blocks, and every block in one paired with a block in the other by
/// `epb_packetid`.
///
/// This is the assertion that catches a sink silently dropping a record. Both
/// sinks are offered every tap record and the pass stops until both have taken
/// it (`crates/recorder/src/deck.rs`), so the two rings hold the same
/// identities or one of them lost something — and a lost record is invisible in
/// the recording that lost it, which still parses and still counts up.
fn pairing_differences(log: &Surface, capture: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    if log.parsed.packets.len() != capture.parsed.packets.len() {
        found.push(format!(
            "{} holds {} packet block(s) and {} holds {}; both sinks are offered every tap \
             record, so a difference is one of them having lost observations the other kept",
            log.target,
            log.parsed.packets.len(),
            capture.target,
            capture.parsed.packets.len(),
        ));
    }
    let left = identities(log);
    let right = identities(capture);
    for (target, other, mine, theirs) in [
        (log.target, capture.target, &left, &right),
        (capture.target, log.target, &right, &left),
    ] {
        let unpaired: Vec<String> = mine
            .iter()
            .filter(|(id, count)| theirs.get(*id) != Some(count))
            .map(|(id, count)| {
                format!(
                    "{id} ({count}\u{d7} here, {}\u{d7} there)",
                    unpaired_count(theirs, *id)
                )
            })
            .take(REPORTED)
            .collect();
        if !unpaired.is_empty() {
            found.push(format!(
                "{target} carries packet id(s) {other} does not pair: {}",
                unpaired.join(", ")
            ));
        }
    }
    let nameless = |surface: &Surface| {
        surface
            .parsed
            .packets
            .iter()
            .filter(|packet| packet.packet_id.is_none())
            .count()
    };
    for surface in [log, capture] {
        let without = nameless(surface);
        if without != 0 {
            found.push(format!(
                "{} holds {without} packet block(s) with no epb_packetid, which nothing can pair \
                 across the two recordings",
                surface.target
            ));
        }
    }
    found
}

fn unpaired_count(counts: &BTreeMap<u64, usize>, id: u64) -> usize {
    counts.get(&id).copied().unwrap_or(0)
}

/// How many times each `epb_packetid` appears. A multiset rather than a set: an
/// identity is meant to be unique, so a duplicate is itself a disagreement and
/// must not be collapsed into agreement.
fn identities(surface: &Surface) -> BTreeMap<u64, usize> {
    let mut counts = BTreeMap::new();
    for packet in &surface.parsed.packets {
        if let Some(id) = packet.packet_id {
            *counts.entry(id).or_insert(0) += 1;
        }
    }
    counts
}

/// A recording may not hold more packet blocks than the recorder says it
/// encoded for that sink.
///
/// **An inequality, and deliberately.** The two numbers are taken at different
/// instants and mean subtly different things, and only one direction is a
/// finding:
///
/// * the metric is read from a scrape taken *before* the download and counts
///   records **encoded**, while the recording is read off the medium and holds
///   records **flushed** — the recorder's staging buffer legitimately sits
///   between the two;
/// * a ring that wrapped has evicted records the counter still counts.
///
/// Both make the recording hold *fewer*, so an exact equality would be a
/// statement that is quietly wrong whenever either happens. Nothing legitimate
/// makes it hold *more* — that direction is a recorder answering blocks it
/// never encoded, which is exactly what this catches.
fn published_differences(surface: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    let held = surface.parsed.packets.len() as u64;
    if held > surface.published_records {
        found.push(format!(
            "{} answers {held} packet block(s) and the recorder publishes \
             librefirewall_recording_records_total for this sink as {}; a recording cannot hold \
             observations the recorder never encoded",
            surface.target, surface.published_records,
        ));
    }
    if surface.published_records == 0 {
        found.push(format!(
            "the recorder publishes no encoded record at all for {}, so the count the recording \
             is compared against proves nothing about either",
            surface.target
        ));
    }
    found
}

/// Every packet block keeps exactly what its sink's snap length allows: the
/// whole frame where it fits, and the snap length where it does not.
///
/// Stated as the clamping law rather than as "something was truncated", because
/// the law holds at every frame size and is what a sink breaks when it retains
/// more than it declared. The original length is never clamped — it is the
/// frame's length on the wire — so a sink that wrote the captured length into
/// both fields fails here.
fn clamping_differences(surface: &Surface) -> Vec<String> {
    let snap = surface.snap_len as usize;
    let mut found: Vec<String> = Vec::new();
    for packet in &surface.parsed.packets {
        let owed = (packet.original_len as usize).min(snap);
        if packet.captured.len() != owed {
            found.push(format!(
                "{}: {} keeps {} captured byte(s) of a {}-byte frame at a snap length of {snap}, \
                 and a sink keeps the whole frame or the snap length, whichever is smaller ({owed})",
                surface.target,
                name(packet),
                packet.captured.len(),
                packet.original_len,
            ));
        }
        if found.len() >= REPORTED {
            break;
        }
    }
    found
}

/// The two recordings declare different snap lengths, so they are two
/// recordings of the same traffic rather than one served under two names.
///
/// The declaration is read out of each file's own Interface Description Blocks,
/// not from the constants that configured the sinks: a recorder wired to serve
/// one ring under both targets answers two byte-identical files, and the only
/// thing that tells them apart is what they say about themselves.
///
/// This is the check that stands in for observing the log sink actually cut a
/// frame short. It cannot be observed at the probe sizes this bench injects —
/// every probe is well under the log sink's snap length — so the clamp never
/// bites and an assertion that some capture was truncated would be vacuous
/// here. What is not vacuous is that the two files declare the two different
/// limits the build gave them.
fn distinctness_differences(log: &Surface, capture: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    let declared = |surface: &Surface| {
        surface
            .parsed
            .interfaces
            .first()
            .map(|interface| interface.snap_len)
    };
    if let (Some(left), Some(right)) = (declared(log), declared(capture))
        && left == right
    {
        found.push(format!(
            "{} and {} both declare a snap length of {left}, so nothing in the two files \
             distinguishes them and one ring served under both names would read as two \
             recordings",
            log.target, capture.target,
        ));
    }
    found
}

/// Every interface a recording describes is a port the configuration document
/// configures, and every packet names one of them.
///
/// The count comes from the document, so an image built from the alternate
/// document is judged against that document's port set. The *name* is the port
/// index and not the document's interface id, because the recorder compiles its
/// interface names in rather than reading the configuration region — see
/// `interface_names` in `pds/recorder/src/main.rs`, which says so and says why.
/// Until it reads the document, this assertion can hold the recording to the
/// number of ports and to their indices and no further; the identity half of
/// the same idea is `crate::metrics_contract`'s interface info family, which
/// does compare against the document field by field.
fn interface_differences(surface: &Surface, wire: &Wire) -> Vec<String> {
    let mut found = Vec::new();
    // A section's interface table restarts at zero, so the flat list holds one
    // table per section and each must be the whole port set.
    let sections = surface.parsed.sections.max(1);
    let expected = wire.ports.saturating_mul(sections);
    if surface.parsed.interfaces.len() != expected {
        found.push(format!(
            "{} declares {} interface block(s) across {sections} section(s) and the \
             configuration document configures {} dataplane port(s), so a section's prologue \
             does not describe every port a packet in it can name",
            surface.target,
            surface.parsed.interfaces.len(),
            wire.ports,
        ));
    }
    for (at, interface) in surface.parsed.interfaces.iter().enumerate() {
        let port = at % wire.ports.max(1);
        let owed = format!("port{port}");
        if interface.name != owed {
            found.push(format!(
                "{}: interface block {at} is named {:?} and the port it describes is {owed}",
                surface.target, interface.name,
            ));
        }
        if interface.snap_len != surface.snap_len {
            found.push(format!(
                "{}: interface block {at} declares a snap length of {} and this sink keeps {}",
                surface.target, interface.snap_len, surface.snap_len,
            ));
        }
        if found.len() >= REPORTED {
            break;
        }
    }
    let stray: Vec<String> = surface
        .parsed
        .packets
        .iter()
        .filter(|packet| packet.interface_id as usize >= wire.ports)
        .map(|packet| format!("{} on interface {}", name(packet), packet.interface_id))
        .take(REPORTED)
        .collect();
    if !stray.is_empty() {
        found.push(format!(
            "{} holds packet block(s) naming an interface outside the document's {} port(s): {}",
            surface.target,
            wire.ports,
            stray.join(", ")
        ));
    }
    found
}

/// Every distinct probe the harness injected appears in the capture, byte for
/// byte.
///
/// **At least once, not exactly once, and deliberately.** An endpoint here is a
/// station and retransmits a probe it has not seen delivered
/// (`crate::forward_harness`'s re-injection), so the multiplicity of a probe in
/// the recording is a function of how long the appliance took to boot. What is
/// not a function of timing is that each one is there at all.
///
/// Compared against the bytes the harness built from the configuration document
/// rather than against a literal, so the assertion restates nothing the probes
/// already say and an image built from the other document is judged against the
/// probes that bench produced.
///
/// # Errors
/// One difference per probe that is missing, naming the probe.
fn presence_differences(capture: &Surface, wire: &Wire) -> Result<usize, Vec<String>> {
    let mut missing = Vec::new();
    let mut matched = 0;
    for injected in wire.injected.iter().filter(|injected| injected.observed) {
        let found = capture.parsed.packets.iter().any(|packet| {
            packet.captured == injected.frame
                && packet.original_len as usize == injected.frame.len()
        });
        if found {
            matched += 1;
        } else {
            missing.push(format!(
                "the capture holds no packet block carrying probe {}'s {} injected byte(s), and \
                 the appliance reached a routing decision on it, so an observation of it is \
                 owed{}",
                injected.name,
                injected.frame.len(),
                nearest(&capture.parsed.packets, &injected.frame),
            ));
        }
    }
    if missing.is_empty() {
        Ok(matched)
    } else {
        Err(missing)
    }
}

/// No packet block carries bytes the harness did not inject.
///
/// The direction that catches fabrication, and the one an "every probe is
/// present" assertion alone misses entirely: a recorder that answered every
/// probe *and* twenty blocks of its own invention would satisfy the presence
/// check completely.
///
/// A prefix rather than an equality, because a sink whose snap length is
/// shorter than the frame keeps the frame's first bytes and nothing else. The
/// original length is compared too, so a truncated block still has to claim the
/// whole frame's length on the wire.
fn fabrication_differences(surface: &Surface, wire: &Wire) -> Vec<String> {
    let mut found = Vec::new();
    for packet in &surface.parsed.packets {
        let known = wire.injected.iter().any(|injected| {
            injected.frame.starts_with(&packet.captured)
                && injected.frame.len() == packet.original_len as usize
        });
        if !known {
            found.push(format!(
                "{}: {} carries {} captured byte(s) of a claimed {}-byte frame that is no prefix \
                 of anything the harness injected{}",
                surface.target,
                name(packet),
                packet.captured.len(),
                packet.original_len,
                nearest_injected(wire, packet),
            ));
        }
        if found.len() >= REPORTED {
            break;
        }
    }
    found
}

/// How many differences of one kind a verdict prints before it stops.
///
/// A recording holds thousands of blocks and a systematic fault breaks every
/// one of them; the first few name the fault, and the rest only bury it.
const REPORTED: usize = 5;

/// A packet block as a verdict names it: by the identity a reader relates it
/// by, and by its position where it has none.
fn name(packet: &Packet) -> String {
    match packet.packet_id {
        Some(id) => format!("packet id {id}"),
        None => String::from("a packet block with no epb_packetid"),
    }
}

/// The closest injected frame to a block that matched none, and where the two
/// part company — so a mismatch is read as "the router rewrote a byte" rather
/// than as "something did not match".
fn nearest_injected(wire: &Wire, packet: &Packet) -> String {
    let Some(injected) = closest(
        wire.injected.iter(),
        |injected| &injected.frame,
        &packet.captured,
    ) else {
        return String::new();
    };
    format!(
        "; the nearest is probe {} ({} injected byte(s)), {}",
        injected.name,
        injected.frame.len(),
        byte_difference(&injected.frame, &packet.captured)
    )
}

/// The closest recorded block to a probe nothing matched, on the same terms.
fn nearest(packets: &[Packet], frame: &[u8]) -> String {
    let Some(packet) = closest(packets.iter(), |packet| &packet.captured, frame) else {
        return String::new();
    };
    format!(
        "; the nearest block is {}, {}",
        name(packet),
        byte_difference(frame, &packet.captured)
    )
}

/// Which candidate's bytes agree with `bytes` for longest. A verdict has to
/// name one, and the one that agrees furthest is the one whose difference is
/// worth reading.
fn closest<'a, T>(
    candidates: impl Iterator<Item = &'a T>,
    bytes_of: impl Fn(&'a T) -> &'a [u8],
    bytes: &[u8],
) -> Option<&'a T>
where
    T: 'a,
{
    candidates.max_by_key(|candidate| {
        bytes_of(candidate)
            .iter()
            .zip(bytes)
            .take_while(|(left, right)| left == right)
            .count()
    })
}

/// Describe how two byte strings differ without printing either: the lengths,
/// and the offset where they part company.
///
/// The same shape as `crate::forward_harness`'s renderer of the same name, for
/// the same reason: a hex dump says the bytes were wrong, and an offset says
/// *which field* was.
fn byte_difference(expected: &[u8], observed: &[u8]) -> String {
    match expected
        .iter()
        .zip(observed)
        .position(|(left, right)| left != right)
    {
        Some(offset) => format!(
            "{} byte(s) differing from the expected {} at offset {offset}",
            observed.len(),
            expected.len()
        ),
        None => format!(
            "{} byte(s) against the expected {}, agreeing as far as the shorter runs",
            observed.len(),
            expected.len()
        ),
    }
}

#[cfg(test)]
mod tests;
