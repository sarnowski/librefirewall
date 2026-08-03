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
//! which no surface has any way to agree with by construction.
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
//! Build orchestration on the host side of an emulator; no threat-model
//! adversary is named for it. The guest composes the recordings — that is the
//! point — and every walk over them is bounded by the body's own length,
//! refuses a malformed file by name rather than indexing off its end,
//! and is performed by [`crate::recording_contract::parse`] before a
//! byte reaches this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::recording_contract::{
    ANNOTATION_VERSION, Annotation, CLASSIFICATION_ESTABLISHED, CLASSIFICATION_NEW,
    EVENT_FLOW_ADVANCED, EVENT_FLOW_CLOSED, EVENT_FLOW_OPENED, EVENT_FLOW_REVOKED,
    EVENT_POLICY_DENIED, FLAGS_INBOUND, Packet, Parsed, STATE_CLOSED, STATE_TIME_WAIT,
    VERDICT_DROPPED, VERDICT_FORWARDED, VERDICT_KIND, VERDICT_REVOKED, classification_name,
    event_name,
};

/// One frame the harness put on a dataplane port, as the contract compares
/// against it.
///
/// Owned here rather than in [`crate::forward_harness`] so the judgement below
/// depends on nothing that needs QEMU to construct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Injected {
    /// The probe that put it there, which is what names it in a verdict.
    ///
    /// Owned rather than borrowed for the reason the harness's own probe names
    /// are: a probe set that floods the appliance names one probe per five-tuple
    /// it puts on the wire, and those names are derived rather than written out.
    pub name: String,
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
    /// The verdict every capture block carrying this probe's bytes must state:
    /// forwarded for a probe the harness watched come out the far side, dropped
    /// for one it watched never arrive.
    ///
    /// This is the half of the evidence no surface can agree with by
    /// construction. The harness observed each probe's fate *on the wire*, with
    /// two host sockets and no help from the appliance, so a recording whose
    /// annotation disagrees is one that misdescribes what the appliance did.
    pub verdict: u8,
    /// The lifecycle or policy event a record of this probe must name, where the
    /// probe must cause one.
    ///
    /// `None` for a probe the connection history is not about — an admission or
    /// routing refusal, or traffic on a conversation already accounted for. Where
    /// it is `Some`, the log recording must hold a record of this probe carrying
    /// exactly that event.
    pub event: Option<u8>,
}

/// The rules the document declares, in the order that is their position on the
/// dataplane, each with what `librefirewall_rule_hits_total` reports for it.
///
/// Position is what a recording carries and the id is what the counter is
/// labelled with, so this is the join between them — and without it a rule named
/// in a record is a number nothing corroborates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredRule {
    pub id: String,
    /// `None` where the exposition carries no series under that id, which is a
    /// finding rather than a rule that has stayed at zero.
    pub hits: Option<u64>,
}

/// What the appliance's own exposition says about the decisions the recordings
/// describe.
///
/// Read out of the same boot's scrape and passed in rather than fetched here, so
/// [`judge`] stays a pure function of parsed inputs.
pub struct Published {
    /// Frames the two pipelines put on an egress ring under a forwarding verdict.
    pub forwarded_frames: u64,
    /// `librefirewall_route_drops_total` per reason name, summed over the
    /// pipelines. Absent where the family carries no series under that name.
    pub drop_reasons: BTreeMap<String, Option<u64>>,
    pub rules: Vec<DeclaredRule>,
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
    /// Probes whose lifecycle or policy event had to be in the connection
    /// history, and was.
    pub events_matched: usize,
    /// How many records the connection history holds per event, which is what
    /// makes the log legible as a log in a run report.
    pub events: BTreeMap<&'static str, usize>,
    /// Records of the connection history, every one of which the capture pairs.
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
            "    {} connection-history record(s), every one paired into the capture by \
             epb_packetid; {} distinct injected probe(s) found byte-identically in the capture, \
             and {} whose lifecycle or policy event is on the packet that caused it",
            self.paired, self.probes_matched, self.events_matched,
        );
        lines.push(line);
        let mut line = String::from("    the connection history holds:");
        for (event, records) in &self.events {
            let _ = write!(line, " {records}\u{d7} {event};");
        }
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
pub fn judge(
    log: &Surface,
    capture: &Surface,
    wire: &Wire,
    published: &Published,
) -> Result<Agreement, String> {
    let mut found = Vec::new();
    found.extend(selection_differences(log, capture));
    for surface in [log, capture] {
        found.extend(published_differences(surface));
        found.extend(clamping_differences(surface));
        found.extend(interface_differences(surface, wire));
        found.extend(fabrication_differences(surface, wire));
        found.extend(annotation_differences(surface));
        found.extend(exposition_differences(surface, published));
    }
    found.extend(distinctness_differences(log, capture));
    found.extend(lifecycle_differences(log));
    found.extend(verdict_differences(capture, wire));
    found.extend(rule_differences(capture, published));
    let probes_matched = match presence_differences(capture, wire) {
        Ok(matched) => matched,
        Err(differences) => {
            found.extend(differences);
            0
        }
    };
    let events_matched = match event_differences(log, wire) {
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
        events_matched,
        events: events(log),
        paired: log.parsed.packets.len(),
    })
}

/// Every event the connection history holds, with how many records carry it.
fn events(log: &Surface) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for packet in &log.parsed.packets {
        if let Some(annotation) = packet.annotation {
            *counts.entry(event_name(annotation.event)).or_insert(0) += 1;
        }
    }
    counts
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

/// **The two recordings differ by selection, and this is that law.** The
/// connection history holds an observation exactly where it carries a lifecycle
/// or policy event; the capture holds every observation **of a frame**. So the
/// log's frame observations are a subset of the capture's, and no record of the
/// log names no event.
///
/// The selection is what makes the two files different *artifacts* rather than one
/// truncated twice. Both directions are findings and they catch different faults:
/// a log record of a frame that the capture does not pair is a connection history
/// describing traffic that never crossed the appliance, and a log record with no
/// event is a sink that stopped selecting and went back to being a truncated
/// capture.
///
/// **The one record that is in the log and never in the capture** is the flow a
/// policy commit ended: a capture is the frames themselves with the verdict on
/// each, and that conversation was ended on no wire. It is therefore excluded from
/// both halves of the subset law — counted out of the totals and not owed a pairing
/// — while the honesty of what it *does* claim is [`annotation_laws`]'.
fn selection_differences(log: &Surface, capture: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    let framed = |surface: &Surface| {
        surface
            .parsed
            .packets
            .iter()
            .filter(|packet| {
                packet
                    .annotation
                    .is_none_or(|annotation| !annotation.is_revocation())
            })
            .count()
    };
    if framed(log) > framed(capture) {
        found.push(format!(
            "{} holds {} record(s) of a frame and {} holds {}; the connection history is a \
             selection of the frame observations the capture holds, so it can never hold more",
            log.target,
            framed(log),
            capture.target,
            framed(capture),
        ));
    }
    let paired = identities(capture);
    let unpaired: Vec<String> = identities(log)
        .iter()
        .filter(|(id, count)| unpaired_count(&paired, **id) < **count)
        .map(|(id, count)| {
            format!(
                "{id} ({count}\u{d7} here, {}\u{d7} there)",
                unpaired_count(&paired, *id)
            )
        })
        .take(REPORTED)
        .collect();
    if !unpaired.is_empty() {
        found.push(format!(
            "{} carries packet id(s) {} does not pair: {}. Every frame observation the connection \
             history selects was offered to the capture too, so an unpaired one describes traffic \
             no packet of the capture accounts for",
            log.target,
            capture.target,
            unpaired.join(", ")
        ));
    }
    let eventless: Vec<String> = log
        .parsed
        .packets
        .iter()
        .filter(|packet| {
            packet
                .annotation
                .is_none_or(|annotation| annotation.event == 0)
        })
        .map(name)
        .take(REPORTED)
        .collect();
    if !eventless.is_empty() {
        found.push(format!(
            "{} holds {} record(s) naming no lifecycle or policy event: {}. A connection history \
             that records a packet for its own sake has the packet rate rather than the admission \
             rate, which is what a flood evicts it with",
            log.target,
            eventless.len(),
            eventless.join(", ")
        ));
    }
    for surface in [log, capture] {
        let without = surface
            .parsed
            .packets
            .iter()
            .filter(|packet| packet.packet_id.is_none())
            .count();
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

/// Every record carries an annotation, and every relation the annotation's own
/// fields must stand in holds.
///
/// These are the promises a reader of either file relies on, so each is checked
/// on the bytes rather than trusted from the producer: a reader that folds records
/// by flow identity needs a classification to know the identity means anything, a
/// reader asking how a conversation ended needs the close to name a state a flow
/// does not leave, and a reader crediting a rule needs the rule to appear only on
/// a decision the filter actually took.
fn annotation_differences(surface: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    for packet in &surface.parsed.packets {
        let Some(annotation) = packet.annotation else {
            found.push(format!(
                "{}: {} carries no PEN-tagged annotation, so the record says what the bytes were \
                 and not what the appliance decided",
                surface.target,
                name(packet)
            ));
            if found.len() >= REPORTED {
                break;
            }
            continue;
        };
        found.extend(annotation_laws(surface, packet, annotation));
        if found.len() >= REPORTED {
            break;
        }
    }
    found
}

/// The laws one annotation must satisfy, each as its own difference.
fn annotation_laws(surface: &Surface, packet: &Packet, annotation: Annotation) -> Vec<String> {
    let mut found = Vec::new();
    let at = |clause: &str| format!("{}: {}: {clause}", surface.target, name(packet));
    if annotation.version != ANNOTATION_VERSION {
        found.push(at(&format!(
            "the annotation declares layout version {} and this build writes {ANNOTATION_VERSION}",
            annotation.version
        )));
    }
    match annotation.verdict {
        VERDICT_FORWARDED if annotation.drop_reason != 0 => found.push(at(&format!(
            "a forwarded frame carrying drop reason {}",
            annotation.drop_reason
        ))),
        VERDICT_DROPPED if annotation.drop_reason == 0 => {
            found.push(at("a dropped frame naming no reason"));
        }
        VERDICT_REVOKED if annotation.drop_reason != 0 => found.push(at(&format!(
            "a revoked flow carrying drop reason {}, and no frame was dropped",
            annotation.drop_reason
        ))),
        VERDICT_FORWARDED | VERDICT_DROPPED | VERDICT_REVOKED => {}
        other => found.push(at(&format!("a verdict octet of {other}"))),
    }
    // **The one record that is about a flow and about no frame, held to claiming
    // none.** Both directions, because the pair is what keeps the connection
    // history honest about the one way a conversation ends that no packet caused:
    // without the second half a record about no packet would be readable as a
    // record about one.
    if annotation.is_revocation() != (annotation.event == EVENT_FLOW_REVOKED) {
        found.push(at(&format!(
            "verdict {} beside {}; a flow the appliance ended is one fact written twice and \
             either half alone is a record that says something else",
            annotation.verdict,
            event_name(annotation.event)
        )));
    }
    if annotation.is_revocation() {
        if packet.original_len != 0 || !packet.captured.is_empty() {
            found.push(at(&format!(
                "a flow the appliance ended, in a block claiming {} wire byte(s) and {} captured: \
                 there was no frame, and a record that claimed one would be a fabricated cause \
                 in an artifact that is evidence",
                packet.original_len,
                packet.captured.len()
            )));
        }
        if packet.flags.is_some() {
            found.push(at(
                "a flow the appliance ended, carrying epb_flags: a direction is a property of a \
                 packet on a wire and there was none",
            ));
        }
        if annotation.classification != 0 {
            found.push(at(&format!(
                "a flow the appliance ended, classified {}: a classification is a statement \
                 about a packet",
                classification_name(annotation.classification)
            )));
        }
    } else {
        if packet.original_len == 0 {
            found.push(at(
                "a frame of no wire length, which no packet the pipeline reached a verdict on can \
                 be",
            ));
        }
        // Every observation of a frame is taken on the port it arrived on, so
        // there is never a second one to relate it to and the direction is always
        // inbound. Checked rather than assumed, because it is the field the record
        // that is about no frame is told from one that is.
        if packet.flags != Some(FLAGS_INBOUND) {
            found.push(at(&format!(
                "epb_flags reads {:?} and every observation of a frame is taken inbound, on the \
                 port the frame arrived on",
                packet.flags
            )));
        }
    }
    // `epb_verdict` and the annotation are two statements of one decision, and a
    // reader that knows only the standard option relies on the first.
    let expected = std::vec![VERDICT_KIND, annotation.verdict];
    if packet.verdict.as_deref() != Some(expected.as_slice()) {
        found.push(at(&format!(
            "epb_verdict reads {:?} and the annotation says {}, so the standard option and the \
             annotation disagree about one decision",
            packet.verdict, annotation.verdict
        )));
    }
    if u32::from(annotation.interface_id) != packet.interface_id {
        found.push(at(&format!(
            "the annotation names interface {} and the block names {}",
            annotation.interface_id, packet.interface_id
        )));
    }
    let names_a_flow = matches!(
        annotation.event,
        EVENT_FLOW_OPENED | EVENT_FLOW_ADVANCED | EVENT_FLOW_CLOSED | EVENT_FLOW_REVOKED
    );
    if names_a_flow && !annotation.names_a_flow() {
        found.push(at(&format!(
            "{} names no flow, so nothing says which conversation it is about",
            event_name(annotation.event)
        )));
    }
    if annotation.event == EVENT_FLOW_CLOSED
        && !matches!(annotation.flow_state, STATE_TIME_WAIT | STATE_CLOSED)
    {
        found.push(at(&format!(
            "a close naming flow state {}, which is one a conversation leaves, so the record says \
             one ended and does not say how",
            annotation.flow_state
        )));
    }
    if annotation.names_a_flow() && annotation.flow_state == 0 {
        found.push(at("a classified flow in no state"));
    }
    if !annotation.names_a_flow() && (annotation.flow_slot != 0 || annotation.flow_generation != 0)
    {
        found.push(at("a flow identity with no classification to interpret it"));
    }
    if annotation.is_revocation() && annotation.flow_state == 0 {
        found.push(at(
            "a flow the appliance ended, in no state: the state it was in when the commit \
             reached it is the whole of what the record says about the conversation",
        ));
    }
    // **The reply's law.** A conversation is opened by exactly one packet and
    // advanced by the ones after it, so an advance or a close is `established` and
    // an opening is `new` — and the rule law below then says an advance names no
    // rule, which together are the whole of "a reply is carried by the flow and
    // not by a rule" as a statement about the bytes on the medium.
    let owed = match annotation.event {
        EVENT_FLOW_OPENED => Some(CLASSIFICATION_NEW),
        EVENT_FLOW_ADVANCED | EVENT_FLOW_CLOSED => Some(CLASSIFICATION_ESTABLISHED),
        _ => None,
    };
    if let Some(owed) = owed
        && annotation.classification != owed
    {
        found.push(at(&format!(
            "{} on a flow classified {}, and only a {} classification reaches that event",
            event_name(annotation.event),
            classification_name(annotation.classification),
            classification_name(owed),
        )));
    }
    let names_a_rule = matches!(annotation.event, EVENT_FLOW_OPENED | EVENT_POLICY_DENIED);
    if names_a_rule != annotation.rule_position().is_some() {
        found.push(at(&format!(
            "{} and rule {:?}; the filter is consulted once per conversation and its two outcomes \
             are the whole of when a rule may appear",
            event_name(annotation.event),
            annotation.rule_position()
        )));
    }
    found
}

/// A conversation the connection history says ended is one it also says began,
/// and by the same identity.
///
/// This is the fold a reader performs, asserted: an open and a close are two
/// records and what makes them one conversation is the (slot, generation) pair
/// they share. A close with no matching open would be a history describing the
/// end of something it never saw start — which is exactly the merge a bare slot
/// index would produce, and what the generation exists to make impossible.
///
/// Order matters and is checked: the open must sit ahead of the close in the
/// file, because the ring is append-only and a close recorded first is a record
/// out of the order the appliance made them in.
fn lifecycle_differences(log: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    let mut opened: BTreeSet<(u32, u32)> = BTreeSet::new();
    for packet in &log.parsed.packets {
        let Some(annotation) = packet.annotation else {
            continue;
        };
        match annotation.event {
            EVENT_FLOW_OPENED => {
                opened.insert(annotation.identity());
            }
            EVENT_FLOW_CLOSED if !opened.contains(&annotation.identity()) => {
                found.push(format!(
                    "{}: {} closes the conversation at slot {} generation {} and no earlier \
                     record opens it, so the history describes the end of something it never saw \
                     begin",
                    log.target,
                    name(packet),
                    annotation.flow_slot,
                    annotation.flow_generation,
                ));
            }
            _ => {}
        }
        if found.len() >= REPORTED {
            break;
        }
    }
    found
}

/// Every capture record of an injected probe states the verdict the harness
/// watched that probe earn on the wire.
///
/// **This is the bullet no surface can satisfy by construction.** Two host
/// sockets observed whether each probe came out the far side, with no help from
/// the appliance, so a record whose annotation says otherwise is a recording that
/// misdescribes what the appliance did — and neither file nor the exposition would
/// notice on its own.
fn verdict_differences(capture: &Surface, wire: &Wire) -> Vec<String> {
    let mut found = Vec::new();
    for injected in wire.injected.iter().filter(|injected| injected.observed) {
        for packet in capture
            .parsed
            .packets
            .iter()
            .filter(|packet| carries(packet, injected))
        {
            let Some(annotation) = packet.annotation else {
                continue;
            };
            if annotation.verdict != injected.verdict {
                found.push(format!(
                    "{}: {} carries probe {}'s bytes under verdict {} and the harness observed it \
                     {} on the wire",
                    capture.target,
                    name(packet),
                    injected.name,
                    annotation.verdict,
                    if injected.verdict == VERDICT_FORWARDED {
                        "come back on the far port"
                    } else {
                        "never arrive anywhere"
                    },
                ));
            }
            if found.len() >= REPORTED {
                return found;
            }
        }
    }
    found
}

/// Every event the probes oblige the appliance to have recorded is in the
/// connection history, on the packet that caused it.
///
/// Anchoring is the whole assertion: a record is paired to its probe by the
/// *bytes it retained*, so an event beside the traffic rather than on it would
/// match nothing here. The multiplicity is not asserted — a probe is re-injected
/// until its delivery is observed, so how many records an event has is a function
/// of how long the appliance took to boot — but that each event happened, on the
/// frame that had to cause it, is not.
///
/// # Errors
/// One difference per probe whose event is missing, naming the probe, the event
/// it owes and the events records of it do carry.
fn event_differences(log: &Surface, wire: &Wire) -> Result<usize, Vec<String>> {
    let mut missing = Vec::new();
    let mut matched = 0;
    for injected in wire.injected.iter() {
        let Some(owed) = injected.event else { continue };
        let carried: BTreeSet<&'static str> = log
            .parsed
            .packets
            .iter()
            .filter(|packet| carries(packet, injected))
            .filter_map(|packet| packet.annotation)
            .map(|annotation| event_name(annotation.event))
            .collect();
        if carried.contains(event_name(owed)) {
            matched += 1;
        } else {
            missing.push(format!(
                "{} holds no record of probe {} naming {}; records of it carry [{}]",
                log.target,
                injected.name,
                event_name(owed),
                carried.into_iter().collect::<Vec<&str>>().join(", ")
            ));
        }
    }
    if missing.is_empty() {
        Ok(matched)
    } else {
        Err(missing)
    }
}

/// Whether this record retained `injected`'s bytes.
///
/// A prefix, because a sink whose snap length is shorter than the frame keeps the
/// frame's first bytes and nothing else — and the claimed wire length is compared
/// too, so a truncated record still has to state the whole frame's length. An
/// empty capture is no prefix at all: every slice starts with nothing.
fn carries(packet: &Packet, injected: &Injected) -> bool {
    !packet.captured.is_empty()
        && injected.frame.starts_with(&packet.captured)
        && injected.frame.len() == packet.original_len as usize
}

/// A rule named in a record is a rule the exposition credits with a hit.
///
/// The join is the position: a recording carries the rule's place in the running
/// generation and the counter is labelled with the id an operator wrote, so a
/// position past the document's rules is a record naming a rule nobody declared,
/// and a declared rule with no hit is a record crediting a rule that never ran.
fn rule_differences(capture: &Surface, published: &Published) -> Vec<String> {
    let mut found = Vec::new();
    let named: BTreeSet<u16> = capture
        .parsed
        .packets
        .iter()
        .filter_map(|packet| packet.annotation)
        .filter_map(|annotation| annotation.rule_position())
        .collect();
    for position in named {
        match published.rules.get(position as usize) {
            None => found.push(format!(
                "{} holds a record naming the rule at position {position} and the document \
                 declares {} rule(s), so the record names a rule no operator wrote",
                capture.target,
                published.rules.len()
            )),
            Some(rule) => match rule.hits {
                None => found.push(format!(
                    "{} holds a record naming the rule at position {position}, which the document \
                     calls {:?}, and librefirewall_rule_hits_total carries no series for it",
                    capture.target, rule.id
                )),
                Some(0) => found.push(format!(
                    "{} holds a record naming rule {:?} and the appliance credits it with no hit, \
                     so the two accounts of one match disagree",
                    capture.target, rule.id
                )),
                Some(_) => {}
            },
        }
        if found.len() >= REPORTED {
            break;
        }
    }
    found
}

/// Every decision a recording states is one the exposition counted too, and at
/// least as often.
///
/// **An inequality, in one direction, and for [`published_differences`]'s
/// reason.** The scrape is taken before the download and counts decisions the
/// appliance *reached*, while a recording holds records it *flushed* out of a ring
/// that may have wrapped — so a recording legitimately holds fewer. Nothing
/// legitimate makes it hold more: that direction is a recording describing
/// decisions the appliance never counted, which is what this catches.
fn exposition_differences(surface: &Surface, published: &Published) -> Vec<String> {
    let mut found = Vec::new();
    let mut forwarded = 0u64;
    let mut per_reason: BTreeMap<u8, u64> = BTreeMap::new();
    for annotation in surface
        .parsed
        .packets
        .iter()
        .filter_map(|packet| packet.annotation)
    {
        if annotation.verdict == VERDICT_FORWARDED {
            forwarded = forwarded.saturating_add(1);
        } else if !annotation.is_revocation() {
            // A conversation the appliance ended refused no frame, so it is
            // attributable to no drop reason and belongs in neither total: the
            // series it *is* attributable to is `librefirewall_flow_lifecycle_total`,
            // which the revocation contract reads.
            *per_reason.entry(annotation.drop_reason).or_insert(0) += 1;
        }
    }
    if forwarded > published.forwarded_frames {
        found.push(format!(
            "{} holds {forwarded} record(s) stating a forwarded frame and \
             librefirewall_forwarded_frames_total sums to {}; a recording cannot describe \
             forwarding the appliance never counted",
            surface.target, published.forwarded_frames
        ));
    }
    for (reason, records) in per_reason {
        let Some(name) = DROP_REASONS.get(usize::from(reason).wrapping_sub(1)) else {
            found.push(format!(
                "{} holds {records} record(s) naming drop reason {reason}, which is outside the \
                 {} this build's vocabulary declares",
                surface.target,
                DROP_REASONS.len()
            ));
            continue;
        };
        match published.drop_reasons.get(*name) {
            None | Some(None) => found.push(format!(
                "{} holds {records} record(s) refused as {name:?} and \
                 librefirewall_route_drops_total carries no series under that reason",
                surface.target
            )),
            Some(Some(counted)) if *counted < records => found.push(format!(
                "{} holds {records} record(s) refused as {name:?} and the appliance counted \
                 {counted}; a recording cannot describe refusals the appliance never made",
                surface.target
            )),
            Some(Some(_)) => {}
        }
        if found.len() >= REPORTED {
            break;
        }
    }
    found
}

/// The drop reasons this build's tap ABI encodes, in the order it encodes them —
/// the annotation carries the position and the exposition carries the name, so
/// this list is what relates the two.
///
/// Restated as strings rather than imported, on this module's own terms: a
/// harness that shared the vocabulary's own array could not tell a renamed
/// variant from a correct file. The names themselves are held to the code by
/// [`crate::reference_contract`], which reads them off the metrics chapter.
pub const DROP_REASONS: [&str; 25] = [
    "unconfigured_ingress_port",
    "interface_disabled",
    "not_addressed_to_us",
    "vlan_tagged",
    "martian_source",
    "unroutable_destination",
    "addressed_to_this_router",
    "ttl_expired",
    "no_route",
    "egress_is_ingress",
    "no_neighbour",
    "flow_unsupported_protocol",
    "flow_fragment",
    "flow_malformed",
    "flow_invalid_flags",
    "flow_mid_stream",
    "flow_invalid_state",
    "flow_out_of_window",
    "flow_no_such_flow",
    "flow_quoted_invalid",
    "flow_unsupported_icmp",
    "flow_table_full",
    "flow_bucket_full",
    "policy_denied",
    "no_policy_match",
];

/// How many times each `epb_packetid` appears. A multiset rather than a set: an
/// identity is meant to be unique, so a duplicate is itself a disagreement and
/// must not be collapsed into agreement.
fn identities(surface: &Surface) -> BTreeMap<u64, usize> {
    let mut counts = BTreeMap::new();
    for packet in &surface.parsed.packets {
        // The record about no frame is left out: it is offered to the connection
        // history alone, so pairing it against the capture would report the
        // selection working as a selection that failed.
        if packet
            .annotation
            .is_some_and(|annotation| annotation.is_revocation())
        {
            continue;
        }
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

/// The two recordings declare different snap lengths, which is the secondary
/// way one file tells itself apart from the other — the primary being what each
/// selects, which [`selection_differences`] states.
///
/// The declaration is read out of each file's own Interface Description Blocks,
/// not from the constants that configured the sinks: a recorder wired to serve
/// one ring under both targets answers two byte-identical files, and the only
/// thing that tells them apart is what they say about themselves.
///
/// The clamp itself is not observable at the probe sizes this bench injects —
/// every probe is well under the connection history's snap length — so an
/// assertion that some record was truncated would be vacuous here. What is not
/// vacuous is that the two files declare the two different limits the build gave
/// them.
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
/// index and not the document's interface id, because the recorder composes its
/// interface names itself — `interface_names` in `pds/recorder/src/main.rs` —
/// and maps no configuration region to read them out of. Until it does, this
/// assertion can hold the recording to the number of ports and to their indices
/// and no further; the identity half of the same idea is
/// `crate::metrics_contract`'s interface info family, which does compare against
/// the document field by field.
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
            // The whole frame, byte for byte: the capture's snap length holds
            // every probe this bench injects, so a prefix would let a truncated
            // record satisfy this and hide a sink that stopped keeping content.
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
///
/// An *empty* prefix is no prefix at all, and the check says so: every slice
/// starts with nothing, so a zero-length capture would otherwise match the first
/// injected frame of the right claimed length and pass — a fabricated block that
/// retained no byte being exactly the one this direction exists to catch.
///
/// The one block this cannot be about is the one that is about no frame — a
/// conversation a policy commit ended. It carries no bytes because there were
/// none, so there is nothing here to compare it against; what it claims is held to
/// its own laws in [`annotation_laws`], which refuse it exactly if it claims a
/// frame.
fn fabrication_differences(surface: &Surface, wire: &Wire) -> Vec<String> {
    let mut found = Vec::new();
    for packet in &surface.parsed.packets {
        if packet
            .annotation
            .is_some_and(|annotation| annotation.is_revocation())
        {
            continue;
        }
        let known = wire
            .injected
            .iter()
            .any(|injected| carries(packet, injected));
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
