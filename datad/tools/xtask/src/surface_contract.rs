//! Where the surfaces have to agree: the two recordings, the policy the image
//! was built from, and the frames the harness itself put on the wire.
//!
//! # Why this is not a third smoke check
//!
//! [`crate::recording_contract`] judges a recording on its own terms and alone,
//! and can pass over a node that is quietly wrong, because the failures worth
//! catching here are not properties of one surface but *disagreements between
//! them*: a sink that silently drops a record still answers a well-formed
//! pcapng file; a tap that loses an observation leaves both recordings
//! internally consistent. Neither notices. What notices is holding them to each
//! other, to the document the image was built from, and to the bytes the
//! harness knows it injected — none of which a recording has any way to agree
//! with by construction.
//!
//! # Why a module of its own
//!
//! It is not the module it joins. Stated inside `recording_contract` it would
//! make that module a reader of the harness's own wire and of the policy in
//! force. That one stays about one file; the agreement between two files, a
//! document and a probe set is this.
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

use crate::forward_harness::PolicyWitness;
use crate::recording_contract::{
    ANNOTATION_VERSION, Annotation, CLASSIFICATION_ESTABLISHED, CLASSIFICATION_NEW,
    EVENT_FLOW_ADVANCED, EVENT_FLOW_CLOSED, EVENT_FLOW_OPENED, EVENT_FLOW_REVOKED,
    EVENT_POLICY_DENIED, EVENT_POLICY_NO_MATCH, FLAGS_INBOUND, Packet, Parsed, STATE_CLOSED,
    STATE_TIME_WAIT, VERDICT_DROPPED, VERDICT_FORWARDED, VERDICT_KIND, VERDICT_REVOKED,
    classification_name, event_name,
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

/// The policy in force while this boot ran, and what its probe set obliges the
/// filter to have decided.
///
/// **This is what a rule annotation is held to, and the whole of it.** The
/// per-rule hit family that used to corroborate one — a position joined to
/// `librefirewall_rule_hits_total` under the id an operator wrote — could only
/// say that two of the appliance's own totals agreed, and it has no place in a
/// metric reading either: its labels are the running document's text rather than
/// a closed catalogue, so the block sits past the forwarder's named table and a
/// snapshot cannot reach it. What the harness *arranged* is what remains, and it
/// is the stronger statement: it chose which port each probe carried, so it
/// knows which of the policy's two rules each probe was owed by, and it knows
/// which probes fell past every rule. A denial credited to the *accepting* rule
/// moved that rule's hits and the denial counter together, so the pair agreed
/// and the join passed — while [`policy_differences`] fails on the first
/// misattributed record.
pub struct Policy<'a> {
    /// The rule ids the document declares, in the order the filter decides them
    /// — which is the position a record names.
    pub declared: &'a [String],
    /// What the probes oblige, out of the harness that chose them.
    pub witness: PolicyWitness,
}

impl Policy<'_> {
    /// Where a rule sits in the running document, or `None` for an id it does
    /// not declare.
    fn position_of(&self, id: &str) -> Option<u16> {
        self.declared
            .iter()
            .position(|declared| declared == id)
            .and_then(|at| u16::try_from(at).ok())
    }
}

/// One recording as this contract sees it: which it is, what it declared, and
/// what the appliance's own metrics say it put there.
pub struct Surface<'a> {
    /// Which recording this is, as a verdict names it.
    pub recording: &'static str,
    /// The sink's snap length as the build configures it. The recording states
    /// its own in every Interface Description Block, and the two are compared:
    /// that is what makes the two recordings demonstrably different files
    /// rather than one served twice.
    pub snap_len: u32,
    pub parsed: &'a Parsed,
    /// What this recording's extent already held when the boot started, read
    /// off the disk image before QEMU was spawned, or `None` on a medium this
    /// boot made itself.
    ///
    /// **A recording outlives the node and this boot's witness does not.** A
    /// boot that resumed one answers earlier boots' records out of the same
    /// extent, and those were written under a policy and an ownership this
    /// boot's witness does not describe — so every law stated against the
    /// witness is stated over the records past what was carried, and the
    /// arithmetic that separates them is exact rather than approximate.
    pub carried: Option<&'a Parsed>,
}

impl Surface<'_> {
    fn inherited_packets(&self) -> u64 {
        self.carried
            .map_or(0, |carried| carried.packets.len() as u64)
    }

    /// The records **this boot** wrote, the medium's earlier ones skipped.
    ///
    /// What the medium held is a prefix of what the extent now answers — a boot
    /// that resumed appended at the byte its predecessor stopped on — so the
    /// records past it are exactly this boot's. Every statement made against
    /// [`Policy::witness`] is stated over these and no others: the witness
    /// describes the policy and the ownership *this* boot ran under, and a
    /// previous boot may have run under neither.
    fn own_packets(&self) -> impl Iterator<Item = &Packet> {
        self.parsed
            .packets
            .iter()
            .skip(self.carried.map_or(0, |carried| carried.packets.len()))
    }
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
    /// How many of them were on the medium before this boot, which is what no
    /// law stated against this boot's witness is an account of.
    pub inherited: u64,
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
    /// Which rule each of this boot's capture records credited, with the id the
    /// document gave that position and how many records named it.
    ///
    /// The attribution itself, in the run log, and the only per-rule account
    /// there is: a total says a rule matched some number of times and cannot say
    /// which records made it up, while this says which position each record
    /// credited — which is the quantity a misattribution moves.
    pub rule_positions: BTreeMap<u16, (String, usize)>,
}

impl Agreement {
    /// The counts from each surface side by side, which is what makes a run log
    /// useful to somebody debugging a later change rather than a record that
    /// something passed.
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut lines = vec![String::from(
            "  the two recordings, held to each other, to the policy and to the wire:",
        )];
        for counted in &self.counted {
            let mut line = String::new();
            let _ = write!(
                line,
                "    {}: {} packet block(s){}; {} interface block(s) declaring a snap length of \
                 {}; longest capture {}",
                counted.target,
                counted.packets,
                match counted.inherited {
                    0 => String::new(),
                    inherited => format!(
                        " of which {inherited} were on the medium before this boot, so {} are \
                         this boot's",
                        (counted.packets as u64).saturating_sub(inherited)
                    ),
                },
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
        let mut line =
            String::from("    this boot's capture records credit the policy's rules by position:");
        if self.rule_positions.is_empty() {
            line.push_str(" none, no record of this boot naming a rule");
        }
        for (position, (id, records)) in &self.rule_positions {
            let _ = write!(line, " {records}\u{d7} position {position} ({id});");
        }
        lines.push(line);
        lines.join("\n")
    }
}

/// Hold the two recordings, the policy and the wire to each other.
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
    policy: &Policy,
) -> Result<Agreement, String> {
    let mut found = Vec::new();
    found.extend(selection_differences(log, capture));
    for surface in [log, capture] {
        found.extend(carried_differences(surface));
        found.extend(clamping_differences(surface));
        found.extend(interface_differences(surface, wire));
        found.extend(fabrication_differences(surface, wire));
        found.extend(annotation_differences(surface));
        found.extend(vocabulary_differences(surface));
        // Over both files rather than over the capture alone: the two are paired
        // by packet id and not by what each says, so a record misattributed in
        // the connection history and sound in the capture pairs cleanly and
        // would go unread if only one of them were held to the policy.
        found.extend(policy_differences(surface, policy));
    }
    found.extend(distinctness_differences(log, capture));
    found.extend(lifecycle_differences(log));
    found.extend(verdict_differences(capture, wire));
    found.extend(outcome_differences(capture, policy));
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
            "the recordings, the policy and the wire do not agree in {} respect(s):\n{}",
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
        rule_positions: rule_positions(capture, policy),
    })
}

/// Which rule each of this boot's capture records credited, named by the id the
/// document gave that position.
///
/// A position the document does not declare is carried under an empty id rather
/// than dropped: it is a finding [`policy_differences`] has already reported, and
/// a summary that quietly omitted it would describe a boot that did not happen.
fn rule_positions(capture: &Surface, policy: &Policy) -> BTreeMap<u16, (String, usize)> {
    let mut counts: BTreeMap<u16, (String, usize)> = BTreeMap::new();
    for position in capture
        .own_packets()
        .filter_map(|packet| packet.annotation)
        .filter_map(|annotation| annotation.rule_position())
    {
        let id = policy
            .declared
            .get(usize::from(position))
            .cloned()
            .unwrap_or_default();
        let entry = counts.entry(position).or_insert((id, 0));
        entry.1 = entry.1.saturating_add(1);
    }
    counts
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
        target: surface.recording,
        packets: surface.parsed.packets.len(),
        inherited: surface.inherited_packets(),
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
            log.recording,
            framed(log),
            capture.recording,
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
            log.recording,
            capture.recording,
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
            log.recording,
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
                surface.recording
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
                surface.recording,
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
    let at = |clause: &str| format!("{}: {}: {clause}", surface.recording, name(packet));
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
                    log.recording,
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
                    capture.recording,
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
                log.recording,
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

/// The filter's own two refusals, as the annotation encodes them — a position in
/// [`DROP_REASONS`], one higher than the index.
///
/// Written as numbers and held to the names rather than looked up at each use:
/// the laws below are about *which* refusal a record states, and a lookup that
/// silently found nothing would turn a renamed reason into a law that stopped
/// applying rather than a build that stopped compiling.
const POLICY_DENIED_REASON: u8 = 25;
const NO_POLICY_MATCH_REASON: u8 = 26;

const _: () = assert!(matches!(
    DROP_REASONS[POLICY_DENIED_REASON as usize - 1].as_bytes(),
    b"policy_denied"
));
const _: () = assert!(matches!(
    DROP_REASONS[NO_POLICY_MATCH_REASON as usize - 1].as_bytes(),
    b"no_policy_match"
));

/// Every record's verdict, held to the rule its own annotation names and to what
/// the harness arranged for this boot.
///
/// **The whole account of a rule's work.** These laws hold one record at a time
/// to a document and a probe set chosen outside the appliance, and each fires on
/// the first record that breaks it — where a join between two of the appliance's
/// own totals could only say that the appliance agreed with itself.
///
/// The four laws, each catching a fault the others do not:
///
/// * a position at or past the count the policy in force declares is a record
///   crediting a rule nobody wrote, stated against the harness's own count of
///   what the document declares;
/// * `policy_denied` names a rule and `no_policy_match` names none. The same
///   statement over the *event* is [`annotation_laws`]', and stating it here over
///   the **refusal reason** is what binds the two: a record whose event and
///   reason describe different outcomes satisfies either law alone and neither
///   pair;
/// * under one policy the accepting rule appears only where the frame was
///   forwarded and the dropping rule only where it was refused. This is the
///   misattribution the counter join cannot see at all: a denial credited to the
///   accepting rule raises that rule's hits and the denial counter together, so
///   both totals still agree;
/// * an appliance nobody owns runs no filter, so no record of one names any rule.
///   The counter join would pass such a record whenever the exposition credited
///   the same rule — two surfaces agreeing about work that could not have
///   happened.
///
/// Only the third is ever conditional. It stands down where the boot ran **two**
/// policies — the reconfiguration document keeps both ids and exchanges their
/// actions, so across the commit each rule legitimately appears under both
/// verdicts and the law is about a rule whose action does not move — and where the
/// boot had no owner, the fourth being the stronger statement about the same
/// records. The first two hold on every boot, an unowned one included: a refusal
/// this build's vocabulary places outside the document, or one whose reason and
/// whose attribution describe different outcomes, is wrong whoever owns the node.
///
/// Every law is stated over [`Surface::own_packets`] — a previous boot's records
/// were written under a policy and an ownership this witness does not describe.
fn policy_differences(surface: &Surface, policy: &Policy) -> Vec<String> {
    let mut found = Vec::new();
    let witness = &policy.witness;
    let accepted = witness.policy.accepted.id.as_str();
    let denied = witness.policy.denied.id.as_str();
    let accepting = policy.position_of(accepted);
    let dropping = policy.position_of(denied);
    // The harness contradicting itself rather than the appliance misbehaving:
    // the witness's two rules and the declared list are read out of one
    // document, so an id with no position means the two were taken from
    // different ones and every attribution below would be stated about the
    // wrong rule.
    for (which, id, position) in [
        ("accepting", accepted, accepting),
        ("dropping", denied, dropping),
    ] {
        if position.is_none() {
            found.push(format!(
                "the witness names {id:?} as this policy's {which} rule and the document declares \
                 {:?}, so nothing says which position that rule occupies and no record can be \
                 attributed to it",
                policy.declared
            ));
        }
    }
    for packet in surface.own_packets() {
        let Some(annotation) = packet.annotation else {
            continue;
        };
        let at = |clause: &str| format!("{}: {}: {clause}", surface.recording, name(packet));
        let position = annotation.rule_position();
        if let Some(position) = position
            && usize::from(position) >= witness.rules
        {
            found.push(at(&format!(
                "the rule at position {position} and the policy in force declares {} rule(s), so \
                 the record credits a rule no operator wrote",
                witness.rules
            )));
        }
        match (annotation.drop_reason, position) {
            (POLICY_DENIED_REASON, None) => found.push(at(
                "a frame refused as policy_denied and no rule named: a rule is what denied it, so \
                 the record states a refusal it cannot attribute",
            )),
            (NO_POLICY_MATCH_REASON, Some(position)) => found.push(at(&format!(
                "a frame refused as no_policy_match naming the rule at position {position}: \
                 falling past every rule is the one refusal no rule made"
            ))),
            _ => {}
        }
        if witness.unowned {
            // The whole of the attribution law on a boot with no owner, and it
            // replaces the two below rather than joining them: naming *any* rule
            // is already the finding, so stating which of the two it should have
            // been would report one fault twice.
            if let Some(position) = position {
                found.push(at(&format!(
                    "the rule at position {position} on a boot of an appliance nobody owns. \
                     Ownership is settled in front of admission and the filter is never \
                     consulted, so a record naming a rule is a stage deciding in another stage's \
                     name"
                )));
            }
        } else if !witness.reconfigured {
            // Where the two rules exchanged actions mid-boot, a rule's own
            // records legitimately carry both verdicts, so nothing can be said
            // about one record in isolation and this law stands down rather than
            // firing on every record the commit's far side wrote.
            if position == accepting && annotation.verdict != VERDICT_FORWARDED {
                found.push(at(&format!(
                    "the rule {accepted:?} accepts, and this record carries verdict {} rather \
                     than a forwarded frame: the rule that admitted a conversation cannot be the \
                     one that refused it",
                    annotation.verdict
                )));
            }
            if position == dropping && annotation.verdict == VERDICT_FORWARDED {
                found.push(at(&format!(
                    "the rule {denied:?} drops, and this record carries a forwarded frame: a \
                     frame the appliance carried was admitted by some other rule than the one \
                     credited here"
                )));
            }
        }
        if found.len() >= REPORTED {
            break;
        }
    }
    found
}

/// Each of the filter's two refusals appears in the capture exactly where this
/// boot's probes provoked it.
///
/// **Both directions, and the absence is the stronger one.** That a refusal the
/// harness aimed at happened is also said — anchored to the probe's own bytes —
/// by [`event_differences`], but only of the connection history; here it is said
/// of the capture, which is the surface that holds every observation of a frame
/// and so the one an *absence* can be stated over at all. A boot whose probes
/// reach neither refusal and whose capture holds one is either a frame nobody put
/// on the wire or a stage refusing in another stage's name, and no count anywhere
/// says so: the counters would simply be non-zero and agree with each other.
///
/// Stated over [`Surface::own_packets`] for [`policy_differences`]' reason, and
/// here it is what makes the absence usable at all: a medium a previous boot
/// wrote holds that boot's refusals, and a run that read them as this boot's
/// would report the law broken on every scenario that resumes one.
fn outcome_differences(capture: &Surface, policy: &Policy) -> Vec<String> {
    let mut found = Vec::new();
    let witness = &policy.witness;
    for (event, reason, probed, what) in [
        (
            EVENT_POLICY_DENIED,
            "policy_denied",
            witness.probed_the_denying_rule,
            "a rule that says drop",
        ),
        (
            EVENT_POLICY_NO_MATCH,
            "no_policy_match",
            witness.probed_the_fallthrough,
            "the default deny",
        ),
    ] {
        let records = capture
            .own_packets()
            .filter_map(|packet| packet.annotation)
            .filter(|annotation| annotation.event == event)
            .count();
        if probed && records == 0 {
            found.push(format!(
                "the boot injected a probe {reason:?} had to refuse and {} holds no record of \
                 one, so {what} did not happen",
                capture.recording
            ));
        }
        if !probed && records != 0 {
            found.push(format!(
                "{} holds {records} record(s) refused as {reason:?} and this boot injected \
                 nothing {what} could refuse — every probe it did inject is settled before the \
                 filter is consulted or is permitted by a rule",
                capture.recording
            ));
        }
    }
    found
}

/// Every refusal a record states names a reason **this build's tap ABI
/// encodes**.
///
/// A per-record law and not a comparison against a counter: it needs nothing the
/// appliance published, so it says exactly as much with one surface as it did
/// beside two. It is what remains of the refusal comparison that used to sit
/// here — a count per reason held to `librefirewall_route_drops_total` under the
/// name the position indexes — and it is the half of that pair which was never
/// about the exposition at all: a reason outside the vocabulary indexes no name,
/// and a recording naming one is wrong whatever any counter says.
///
/// Stated over **every** record in the file, a previous boot's included, for the
/// reason the policy laws are not: the vocabulary is a property of the build
/// that wrote the bytes, and this build wrote every record on the medium.
fn vocabulary_differences(surface: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    let mut reported: BTreeSet<u8> = BTreeSet::new();
    for packet in &surface.parsed.packets {
        let Some(annotation) = packet.annotation else {
            continue;
        };
        // A forwarded frame refused nothing and a revoked conversation refused no
        // frame, so neither carries a reason to look up: that both read zero here
        // is `annotation_laws`' statement, not this one's.
        if annotation.verdict == VERDICT_FORWARDED || annotation.is_revocation() {
            continue;
        }
        let known = usize::from(annotation.drop_reason)
            .checked_sub(1)
            .is_some_and(|at| at < DROP_REASONS.len());
        if !known && reported.insert(annotation.drop_reason) {
            found.push(format!(
                "{}: {} names drop reason {}, which is outside the {} this build's vocabulary \
                 declares",
                surface.recording,
                name(packet),
                annotation.drop_reason,
                DROP_REASONS.len()
            ));
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
///
/// What restating cannot carry is the *arithmetic*: this array is indexed by the
/// annotation's own encoding, so a reason inserted anywhere but the end renames
/// every record after it and a check comparing counts still passes. The length is
/// therefore held to [`wire::TAP_DROP_REASON_COUNT`] below — the constant the
/// encoding is derived from — which turns a silently shifted vocabulary into a
/// build that does not compile.
pub const DROP_REASONS: [&str; 26] = [
    "unowned",
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

// The annotation carries a *position* in this vocabulary, so a reason added to
// the appliance and not to this array does not shorten the list — it renames
// every reason after the one that moved, and a recording then disagrees with an
// exposition that is telling the truth. Comparing against the constant the
// encoding itself is derived from is what makes that a compile error.
const _: () = assert!(DROP_REASONS.len() == wire::TAP_DROP_REASON_COUNT as usize);

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

/// A resumed recording may not offer fewer packet blocks than the medium already
/// held.
///
/// **The one relation between a file and a number that survives having only the
/// file.** The number here is not a counter the appliance published — it is what
/// this harness read off the disk image before QEMU was spawned — so the two
/// sides are the same bytes at two instants and the statement is exact. A
/// recording resumed in place continues at the byte its predecessor stopped on,
/// which makes what the medium held a *prefix* of what the extent now answers;
/// an extent holding fewer records than that prefix is a restart that cost a
/// deployment its evidence, which is the whole thing resuming in place exists to
/// prevent.
///
/// **There is deliberately no bound in the other direction.** The one that used
/// to stand here held the file to `librefirewall_recording_records_total` for
/// its sink, and both halves of that pair went with the exposition. Nothing
/// replaces them: a lower bound taken from a *reading* would be unsound, the
/// relay being push-based — the recorder frames whatever the publisher last
/// settled, at most once per pass — so a block's counters are older than the
/// block by an unbounded amount, and a real boot answers a reading reporting no
/// encoded record with records already standing ahead of it.
fn carried_differences(surface: &Surface) -> Vec<String> {
    let mut found = Vec::new();
    let held = surface.parsed.packets.len() as u64;
    let inherited = surface.inherited_packets();
    if held < inherited {
        found.push(format!(
            "{} answers {held} packet block(s) and the medium already held {inherited} going into \
             this boot; a resumed recording continues at the byte its predecessor stopped on, so \
             an extent that offers fewer records than were already there has lost some",
            surface.recording
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
                surface.recording,
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
            log.recording, capture.recording,
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
            surface.recording,
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
                surface.recording, interface.name,
            ));
        }
        if interface.snap_len != surface.snap_len {
            found.push(format!(
                "{}: interface block {at} declares a snap length of {} and this sink keeps {}",
                surface.recording, interface.snap_len, surface.snap_len,
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
            surface.recording,
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
                surface.recording,
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
