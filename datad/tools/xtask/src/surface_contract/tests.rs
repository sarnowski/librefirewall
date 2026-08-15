//! The judgement, exercised over synthetic recordings.
//!
//! Every case is built by [`recording`] and then *perturbed* in exactly one
//! way, so a test that fires proves the assertion it is named for and nothing
//! else — and the agreeing case proves that none of the others fires on a
//! sound pair. That is what keeps the contract from being vacuous: each
//! perturbation below is a thing that would have to break in the appliance for
//! the corresponding assertion to fire in QEMU.

use std::sync::LazyLock;

use config::Identifier;

use super::*;
use crate::recording_contract::{
    CLASSIFICATION_NEW, EVENT_FLOW_REFUSED, Interface, STATE_TIME_WAIT,
};
use crate::topology::{PortPolicy, PortRule};

const LOG_RECORDING: &str = "the connection history";
const CAPTURE_RECORDING: &str = "the capture";
const LOG_SNAP: u32 = 128;
const CAPTURE_SNAP: u32 = 2048;
const PORTS: usize = 2;

/// The two probes the synthetic bench injects, one per port, each opening a
/// conversation the connection history must record.
fn injected() -> Vec<Injected> {
    vec![
        Injected {
            name: String::from("routed-0-to-1"),
            frame: (0..65u8).collect(),
            observed: true,
            verdict: VERDICT_FORWARDED,
            event: Some(EVENT_FLOW_OPENED),
        },
        Injected {
            name: String::from("routed-1-to-0"),
            frame: (100..166u8).collect(),
            observed: true,
            verdict: VERDICT_FORWARDED,
            event: Some(EVENT_FLOW_OPENED),
        },
        // The probe the tap never sees, which must NOT be demanded of the
        // capture: it is here so a change that started demanding every probe
        // fails a test rather than a ten-minute boot.
        Injected {
            name: String::from("legacy-l2-broadcast"),
            frame: vec![0xff; 60],
            observed: false,
            verdict: VERDICT_DROPPED,
            event: None,
        },
    ]
}

/// A sound annotation for a record that opened a conversation on `slot`.
fn opening(interface: u32, slot: u32) -> Annotation {
    Annotation {
        version: ANNOTATION_VERSION,
        verdict: VERDICT_FORWARDED,
        drop_reason: 0,
        interface_id: interface as u8,
        direction: 0,
        classification: CLASSIFICATION_NEW,
        event: EVENT_FLOW_OPENED,
        flow_state: 9,
        configuration_generation: 1,
        flow_slot: slot,
        flow_generation: 1,
        // One higher than the position, so this names the rule at position 0.
        rule: 1,
    }
}

/// One recording holding `ids`, each carrying the bytes of the probe at
/// `probe`, truncated to `snap_len` the way its sink would.
fn recording(snap_len: u32, ids: &[(u64, usize)]) -> Parsed {
    let probes = injected();
    Parsed {
        sections: 1,
        interfaces: (0..PORTS)
            .map(|port| Interface {
                name: format!("port{port}"),
                snap_len,
                link_type: 1,
            })
            .collect(),
        packets: ids
            .iter()
            .map(|(id, probe)| {
                let frame = &probes[*probe].frame;
                let interface = (*probe % PORTS) as u32;
                Packet {
                    interface_id: interface,
                    packet_id: Some(*id),
                    original_len: frame.len() as u32,
                    flags: Some(crate::recording_contract::FLAGS_INBOUND),
                    captured: frame
                        .iter()
                        .take(snap_len as usize)
                        .copied()
                        .collect::<Vec<u8>>(),
                    verdict: Some(vec![VERDICT_KIND, VERDICT_FORWARDED]),
                    // One conversation per probe, so a record of the same probe
                    // names the same identity however often it appears.
                    annotation: Some(opening(interface, *probe as u32)),
                }
            })
            .collect(),
        consumed: 0,
        snapshots: Vec::new(),
        padding_blocks: 0,
        transcript: Vec::new(),
        transcript_batches: 0,
    }
}

/// A record of the probe at `probe`, at `snap_len`, carrying `annotation` — the
/// shape every perturbation below is built from.
fn record(snap_len: u32, id: u64, probe: usize, annotation: Annotation) -> Packet {
    let frame = injected()[probe].frame.clone();
    Packet {
        interface_id: u32::from(annotation.interface_id),
        packet_id: Some(id),
        original_len: frame.len() as u32,
        flags: Some(crate::recording_contract::FLAGS_INBOUND),
        captured: frame.into_iter().take(snap_len as usize).collect(),
        verdict: Some(vec![VERDICT_KIND, annotation.verdict]),
        annotation: Some(annotation),
    }
}

/// The annotation code for a refusal named by its token.
///
/// Derived rather than written, because the code *is* a position in
/// [`DROP_REASONS`]: a reason added to the vocabulary shifts every code after it,
/// and a fixture carrying the old number would go on passing while describing a
/// different refusal. Naming the reason is what keeps these tests about the thing
/// they say they are about.
fn reason_code(name: &str) -> u8 {
    let at = DROP_REASONS
        .iter()
        .position(|known| *known == name)
        .unwrap_or_else(|| panic!("{name} is not a drop reason this build encodes"));
    u8::try_from(at + 1).expect("the vocabulary fits a byte")
}

/// The rule ids the synthetic document declares, in the order the filter decides
/// them — which is the position a record names.
///
/// The accepting rule first, because [`opening`] credits position 0: the
/// document and the annotations under test have to describe one policy, or a
/// case that perturbs a rule would be perturbing a different one.
const DECLARED: [&str; 2] = ["probe-forward", "probe-blocked"];

/// The position [`opening`] credits, which is the accepting rule's.
const ACCEPTING: u16 = 0;
/// The position a refusal credits, which is the dropping rule's.
const DROPPING: u16 = 1;

/// [`DECLARED`] as the judgement takes it — owned strings, because a rule id in
/// a running document is text an operator wrote rather than a literal.
static DECLARED_IDS: LazyLock<Vec<String>> =
    LazyLock::new(|| DECLARED.iter().map(|id| (*id).to_owned()).collect());

/// The policy a sound run ran under: the synthetic document's two rules, and a
/// probe set that reached neither of the filter's refusals.
///
/// The refusals are off because [`SOUND`] holds forwarded records only. A case
/// that turns one on makes the zero half of the outcome law into the demand
/// half, which is what puts both of its directions within reach from here.
fn policy() -> Policy<'static> {
    Policy {
        declared: &DECLARED_IDS,
        witness: witness(),
    }
}

fn witness() -> PolicyWitness {
    let rule = |at: u16, destination_port| PortRule {
        id: Identifier::new(DECLARED[at as usize].as_bytes())
            .expect("the fixture's rule ids are identifiers the schema admits"),
        destination_port,
    };
    PolicyWitness {
        policy: PortPolicy {
            accepted: rule(ACCEPTING, 5000),
            denied: rule(DROPPING, 5001),
            unmatched: 5002,
        },
        probed_the_denying_rule: false,
        probed_the_fallthrough: false,
        probed_an_established_flow: false,
        probed_mid_stream: false,
        rules: DECLARED.len(),
        reconfigured: false,
        unowned: false,
        flooded_tuples: 0,
    }
}

/// The blocks both sinks hold on a sound run: each probe seen twice, as a
/// station that retransmitted once would produce.
const SOUND: &[(u64, usize)] = &[(0, 0), (1, 1), (2, 0), (3, 1)];

fn log_surface(parsed: &Parsed) -> Surface<'_> {
    Surface {
        recording: LOG_RECORDING,
        snap_len: LOG_SNAP,
        parsed,
        carried: None,
    }
}

fn capture_surface(parsed: &Parsed) -> Surface<'_> {
    Surface {
        recording: CAPTURE_RECORDING,
        snap_len: CAPTURE_SNAP,
        parsed,
        carried: None,
    }
}

/// The same surface on a medium a previous boot wrote: `carried` is the prefix
/// of `parsed` that boot left, which is what the counters beside it are *not* an
/// account of.
fn resumed<'a>(surface: Surface<'a>, carried: &'a Parsed) -> Surface<'a> {
    Surface {
        carried: Some(carried),
        ..surface
    }
}

fn wire(injected: &[Injected]) -> Wire<'_> {
    Wire {
        injected,
        ports: PORTS,
    }
}

#[test]
fn two_recordings_of_the_same_traffic_agree() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let agreement = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect("a sound pair");
    assert_eq!(agreement.paired, 4);
    // Two of the three probes are observable; the broadcast one is not, and
    // demanding it would be asserting a contract the appliance does not have.
    assert_eq!(agreement.probes_matched, 2);
    let evidence = agreement.evidence();
    assert!(evidence.contains(LOG_RECORDING), "{evidence}");
    assert!(evidence.contains(CAPTURE_RECORDING), "{evidence}");
    assert!(evidence.contains("snap length of 128"), "{evidence}");
    assert!(evidence.contains("snap length of 2048"), "{evidence}");
}

/// **The selection, holding rather than breaking.** A connection history shorter
/// than the capture is what the two recordings differing by what they record
/// *is*: the capture holds every observation and the log holds the ones that
/// carried an event.
#[test]
fn a_connection_history_shorter_than_the_capture_is_the_selection() {
    // The capture holds every observation; the log holds two of them, which is
    // what a run whose other two frames caused no event looks like.
    let log = recording(LOG_SNAP, &SOUND[..2]);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let agreement = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect("a selection is not a lost observation");
    assert_eq!(agreement.paired, 2);
    assert_eq!(agreement.events.get("flow-opened"), Some(&2));
}

/// A connection history holding *more* than the capture, which the selection
/// makes impossible: every observation the log selects was offered to the capture
/// too.
#[test]
fn a_connection_history_longer_than_the_capture_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, &SOUND[..3]);
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a selection cannot be larger than what it selects from");
    assert!(error.contains("holds 4 record(s)"), "{error}");
    assert!(error.contains("can never hold more"), "{error}");
    assert!(error.contains("does not pair"), "{error}");
}

/// Equal counts and different identities: a log record the capture never saw. A
/// count check alone passes this.
#[test]
fn an_unpaired_packet_id_is_a_finding_even_at_an_equal_count() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, &[(0, 0), (1, 1), (2, 0), (99, 1)]);
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("an identity in the history and not the capture is fabrication");
    assert!(error.contains("does not pair"), "{error}");
    assert!(error.contains('3'), "{error}");
    assert!(
        !error.contains("can never hold more"),
        "the counts agree, so no count difference may be reported: {error}"
    );
}

/// **A connection history that stopped selecting.** A record naming no event is
/// the log gone back to being a truncated capture, which is precisely what this
/// landing changed.
#[test]
fn a_history_record_naming_no_event_is_a_finding() {
    let mut log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = log.packets.first_mut() {
        packet.annotation = Some(Annotation {
            event: 0,
            classification: 0,
            flow_state: 0,
            flow_slot: 0,
            flow_generation: 0,
            rule: 0,
            ..opening(0, 0)
        });
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a record for its own sake is the packet log this is not");
    assert!(
        error.contains("naming no lifecycle or policy event"),
        "{error}"
    );
    assert!(error.contains("rather than the admission rate"), "{error}");
}

/// The events the probes oblige the history to hold, missing. A history that
/// parses, pairs and clamps correctly and simply never recorded the opening.
#[test]
fn an_event_the_probes_oblige_and_the_history_lacks_is_a_finding() {
    let mut log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    // Every record of the first probe becomes a refusal, so no record of it
    // names the opening the probe had to produce.
    for packet in log
        .packets
        .iter_mut()
        .filter(|packet| packet.captured.first() == Some(&0))
    {
        packet.annotation = Some(Annotation {
            verdict: VERDICT_DROPPED,
            drop_reason: reason_code("flow_mid_stream"),
            event: EVENT_FLOW_REFUSED,
            classification: 0,
            flow_state: 0,
            flow_slot: 0,
            flow_generation: 0,
            rule: 0,
            ..opening(0, 0)
        });
        packet.verdict = Some(vec![VERDICT_KIND, VERDICT_DROPPED]);
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("the opening the probe had to cause is not in the history");
    assert!(
        error.contains("holds no record of probe routed-0-to-1 naming flow-opened"),
        "{error}"
    );
    assert!(error.contains("flow-refused"), "{error}");
}

/// **The verdict the harness watched on the wire.** A record that says a probe
/// was dropped when two host sockets watched it come out the far side — the one
/// disagreement no surface can notice on its own.
#[test]
fn a_verdict_disagreeing_with_the_wire_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = capture.packets.first_mut() {
        packet.annotation = Some(Annotation {
            verdict: VERDICT_DROPPED,
            drop_reason: reason_code("policy_denied"),
            event: EVENT_POLICY_DENIED,
            ..opening(0, 0)
        });
        packet.verdict = Some(vec![VERDICT_KIND, VERDICT_DROPPED]);
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("the harness watched that probe come back on the far port");
    assert!(error.contains("under verdict 1"), "{error}");
    assert!(error.contains("come back on the far port"), "{error}");
}

/// A close with no open of the same identity ahead of it: a history describing
/// the end of something it never saw begin, which is the merge a bare slot index
/// would produce and the generation exists to make impossible.
#[test]
fn a_close_with_no_matching_open_is_a_finding() {
    let mut log = recording(LOG_SNAP, &SOUND[..1]);
    let capture = recording(CAPTURE_SNAP, SOUND);
    log.packets.push(record(
        LOG_SNAP,
        1,
        0,
        Annotation {
            classification: CLASSIFICATION_ESTABLISHED,
            event: EVENT_FLOW_CLOSED,
            flow_state: STATE_TIME_WAIT,
            // A slot the opening above does not name.
            flow_slot: 77,
            rule: 0,
            ..opening(0, 0)
        },
    ));
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a close naming a conversation nothing opened");
    assert!(error.contains("no earlier record opens it"), "{error}");
    assert!(error.contains("slot 77"), "{error}");
}

/// A close naming a state a conversation leaves: the record says one ended and
/// does not say how, which is the whole content of a close event.
#[test]
fn a_close_that_does_not_say_how_is_a_finding() {
    let mut log = recording(LOG_SNAP, &SOUND[..1]);
    let capture = recording(CAPTURE_SNAP, SOUND);
    log.packets.push(record(
        LOG_SNAP,
        1,
        0,
        Annotation {
            classification: CLASSIFICATION_ESTABLISHED,
            event: EVENT_FLOW_CLOSED,
            // Established: a state a conversation carries traffic in.
            flow_state: 3,
            rule: 0,
            ..opening(0, 0)
        },
    ));
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a close must name a state a conversation does not leave");
    assert!(error.contains("does not say how"), "{error}");
}

/// **The reply's law.** An advance on a flow classified `new`, or one naming a
/// rule: either would say the filter decided a packet it is never consulted
/// about.
#[test]
fn an_advance_classified_new_or_naming_a_rule_is_a_finding() {
    for (annotation, clause) in [
        (
            Annotation {
                event: EVENT_FLOW_ADVANCED,
                classification: CLASSIFICATION_NEW,
                rule: 0,
                ..opening(0, 0)
            },
            "only a established classification reaches that event",
        ),
        (
            Annotation {
                event: EVENT_FLOW_ADVANCED,
                classification: CLASSIFICATION_ESTABLISHED,
                // The rule at position 0, on a decision the filter never took.
                rule: 1,
                ..opening(0, 0)
            },
            "the whole of when a rule may appear",
        ),
    ] {
        let mut log = recording(LOG_SNAP, &SOUND[..1]);
        let capture = recording(CAPTURE_SNAP, SOUND);
        log.packets.push(record(LOG_SNAP, 1, 0, annotation));
        let probes = injected();
        let error = judge(
            &log_surface(&log),
            &capture_surface(&capture),
            &wire(&probes),
            &policy(),
        )
        .expect_err("an advance the filter is claimed to have decided");
        assert!(error.contains(clause), "{error}");
    }
}

/// A record with no annotation at all: the bytes without the decision, which is
/// what the recordings held before this landing.
#[test]
fn a_record_carrying_no_annotation_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = capture.packets.first_mut() {
        packet.annotation = None;
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a record without the decision is not evidence of one");
    assert!(
        error.contains("carries no PEN-tagged annotation"),
        "{error}"
    );
}

/// `epb_verdict` and the annotation disagreeing about one decision. A reader that
/// knows only the standard option relies on the first.
#[test]
fn a_standard_verdict_option_disagreeing_with_the_annotation_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = capture.packets.first_mut() {
        packet.verdict = Some(vec![VERDICT_KIND, VERDICT_DROPPED]);
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("two statements of one decision, disagreeing");
    assert!(error.contains("disagree about one decision"), "{error}");
}

/// A recorder answering blocks it never encoded. The presence check passes it
/// completely — every probe is still there — and only the fabrication
/// direction catches it.
#[test]
fn a_packet_the_harness_never_injected_is_a_finding() {
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    capture.packets.push(Packet {
        // The first probe with one byte changed near its end: a fabrication
        // that a length comparison alone would accept.
        captured: (0..65u8)
            .map(|byte| if byte == 60 { 0 } else { byte })
            .collect(),
        ..record(CAPTURE_SNAP, 4, 0, opening(0, 0))
    });
    let mut log = recording(LOG_SNAP, SOUND);
    log.packets.push(capture.packets[4].clone());
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a block matching no injected frame is fabrication");
    assert!(
        error.contains("no prefix of anything the harness injected"),
        "{error}"
    );
    // The diagnostic a human needs without re-running: which block, and where.
    assert!(error.contains("packet id 4"), "{error}");
    assert!(error.contains("nearest is probe routed-0-to-1"), "{error}");
    assert!(error.contains("at offset 60"), "{error}");
}

/// A fabricated block that retained *nothing*. Every slice starts with the
/// empty slice, so a prefix test alone accepts it against the first injected
/// frame of the same claimed length — which is the one shape of invention a
/// sink can produce for free.
#[test]
fn a_packet_block_that_retained_no_byte_is_a_finding() {
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    capture.packets.push(Packet {
        // The first probe's length on the wire, and not one byte of it kept.
        captured: Vec::new(),
        ..record(CAPTURE_SNAP, 4, 0, opening(0, 0))
    });
    let mut log = recording(LOG_SNAP, SOUND);
    log.packets.push(capture.packets[4].clone());
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("an empty capture is no prefix of anything");
    assert!(
        error.contains("no prefix of anything the harness injected"),
        "{error}"
    );
    assert!(error.contains("0 captured byte(s)"), "{error}");
}

/// A log sink that retained more than it declared. The recording is still a
/// valid pcapng file and still pairs with the capture; what it broke is the
/// clamping law.
#[test]
fn a_log_capture_past_the_snap_length_is_a_finding() {
    let mut log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    // A frame longer than the log sink keeps, recorded whole.
    let long: Vec<u8> = (0..200u8).collect();
    log.packets.push(Packet {
        original_len: 200,
        captured: long.clone(),
        ..record(LOG_SNAP, 4, 0, opening(0, 0))
    });
    let probes = [
        injected(),
        vec![Injected {
            name: String::from("oversized"),
            frame: long,
            observed: false,
            verdict: VERDICT_FORWARDED,
            event: None,
        }],
    ]
    .concat();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a log block keeping 200 bytes at a snap length of 128 is unclamped");
    assert!(error.contains("keeps 200 captured byte(s)"), "{error}");
    assert!(error.contains("whichever is smaller (128)"), "{error}");
}

/// The clamp, holding rather than breaking: a frame past the log sink's snap
/// length is kept whole by the capture and cut by the log, and both are sound.
/// This is the case that would exercise the truncation half of the contract in
/// QEMU, and does not today — every probe this bench injects is well under 128
/// bytes.
#[test]
fn a_frame_past_the_log_snap_length_is_sound_when_each_sink_clamps_its_own_way() {
    let long: Vec<u8> = (0..200u8).collect();
    let probes = vec![Injected {
        name: String::from("oversized"),
        frame: long.clone(),
        observed: true,
        verdict: VERDICT_FORWARDED,
        event: Some(EVENT_FLOW_OPENED),
    }];
    let block = |snap: usize| Parsed {
        sections: 1,
        interfaces: (0..PORTS)
            .map(|port| Interface {
                name: format!("port{port}"),
                snap_len: snap as u32,
                link_type: 1,
            })
            .collect(),
        packets: vec![Packet {
            interface_id: 0,
            packet_id: Some(0),
            original_len: 200,
            flags: Some(crate::recording_contract::FLAGS_INBOUND),
            captured: long.iter().take(snap).copied().collect(),
            verdict: Some(vec![VERDICT_KIND, VERDICT_FORWARDED]),
            annotation: Some(opening(0, 0)),
        }],
        consumed: 0,
        snapshots: Vec::new(),
        padding_blocks: 0,
        transcript: Vec::new(),
        transcript_batches: 0,
    };
    let log = block(LOG_SNAP as usize);
    let capture = block(CAPTURE_SNAP as usize);
    let agreement = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect("each sink keeping its own snap length of one frame is the contract");
    assert_eq!(agreement.probes_matched, 1);
    assert_eq!(agreement.counted[0].longest_capture, 128);
    assert_eq!(agreement.counted[1].longest_capture, 200);
}

/// One ring served under both names: two byte-identical files, which every
/// pairing and fabrication assertion accepts. Only what the files say about
/// themselves tells them apart.
#[test]
fn two_recordings_declaring_one_snap_length_are_not_two_recordings() {
    let log = recording(CAPTURE_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let error = judge(
        &Surface {
            recording: LOG_RECORDING,
            // The sink this extent belongs to keeps 128, and the file on it
            // declares 2048 — which is the duplicate showing.
            snap_len: LOG_SNAP,
            parsed: &log,
            carried: None,
        },
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("one ring under two names is one recording");
    assert!(
        error.contains("both declare a snap length of 2048"),
        "{error}"
    );
}

/// **A recording outlives the node and this boot's witness does not.** A boot
/// that resumed one answers earlier boots' records out of the same extent, so
/// what the medium already held is separated out and every law stated against
/// this boot is stated over the rest — which the run log then states both ways
/// round, because a reader of a later failure needs to see which number moved.
#[test]
fn a_resumed_recording_is_held_to_the_records_it_added_and_not_the_mediums() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let carried_log = recording(LOG_SNAP, &SOUND[..2]);
    let carried_capture = recording(CAPTURE_SNAP, &SOUND[..2]);
    let probes = injected();
    let agreement = judge(
        &resumed(log_surface(&log), &carried_log),
        &resumed(capture_surface(&capture), &carried_capture),
        &wire(&probes),
        &policy(),
    )
    .expect("two of the four blocks were on the medium before this boot");
    assert_eq!(agreement.counted[1].packets, 4);
    assert_eq!(agreement.counted[1].inherited, 2);
    assert!(
        agreement
            .evidence()
            .contains("of which 2 were on the medium before this boot, so 2 are this boot's"),
        "{}",
        agreement.evidence()
    );
}

/// And the one relation between a file and a number that a carried medium
/// carries at all: an extent offering fewer records than the medium already held
/// is a restart that cost a deployment its evidence. The number is the harness's
/// own read of the disk image, so it needs no account from the appliance.
#[test]
fn a_resumed_recording_offering_fewer_records_than_the_medium_held_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, &SOUND[..2]);
    let carried = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &resumed(capture_surface(&capture), &carried),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a resumed recording may not lose what the medium already held");
    assert!(
        error.contains("the medium already held 4 going into this boot"),
        "{error}"
    );
}

/// A probe the appliance decided on and no recording holds — the tap losing an
/// observation, which is invisible in every other assertion here because the
/// two recordings lose it together.
#[test]
fn a_probe_missing_from_both_recordings_is_a_finding() {
    let log = recording(LOG_SNAP, &[(0, 0), (1, 0)]);
    let capture = recording(CAPTURE_SNAP, &[(0, 0), (1, 0)]);
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("the second probe was injected and nothing recorded it");
    assert!(error.contains("probe routed-1-to-0"), "{error}");
    assert!(error.contains("is owed"), "{error}");
}

/// A block naming an interface no section describes: unresolvable to a reader,
/// and a recording that cannot be opened is not evidence.
#[test]
fn a_packet_naming_an_interface_the_document_does_not_configure_is_a_finding() {
    let mut log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = log.packets.first_mut() {
        packet.interface_id = 7;
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("interface 7 on a two-port bench resolves to nothing");
    assert!(error.contains("naming an interface outside"), "{error}");
    assert!(error.contains("interface 7"), "{error}");
}

/// A prologue that describes fewer ports than the document configures, so some
/// packet in the section names an interface the section never declared.
#[test]
fn a_prologue_short_of_the_documents_ports_is_a_finding() {
    let mut log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    log.interfaces.truncate(1);
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("one interface block for a two-port document is a short prologue");
    assert!(error.contains("declares 1 interface block(s)"), "{error}");
    assert!(error.contains("2 dataplane port(s)"), "{error}");
}

/// Two sections, each with its own prologue — what a recording spanning two
/// segments is, and what the per-section interface count has to accept.
#[test]
fn a_recording_spanning_two_sections_declares_a_prologue_in_each() {
    let mut log = recording(LOG_SNAP, SOUND);
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    for (parsed, snap) in [(&mut log, LOG_SNAP), (&mut capture, CAPTURE_SNAP)] {
        parsed.sections = 2;
        for port in 0..PORTS {
            parsed.interfaces.push(Interface {
                name: format!("port{port}"),
                snap_len: snap,
                link_type: 1,
            });
        }
    }
    let probes = injected();
    judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect("a second segment's prologue is a second interface table, not a stray one");
}

/// A block with no `epb_packetid`: nothing can pair it, so the pairing
/// assertion would silently weaken rather than fail.
#[test]
fn a_packet_with_no_identity_cannot_be_paired_and_is_a_finding() {
    let mut log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = log.packets.first_mut() {
        packet.packet_id = None;
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a block with no identity pairs with nothing");
    assert!(error.contains("no epb_packetid"), "{error}");
}

/// Every finding at once, so a run that has to be repeated to see the second
/// one is a run that costs ten minutes to learn one fact.
#[test]
fn every_disagreement_is_reported_not_only_the_first() {
    // Three faults at once: a short prologue, a history record naming no event,
    // and the second probe's opening missing from the history entirely.
    let mut log = recording(LOG_SNAP, &[(0, 0)]);
    let capture = recording(CAPTURE_SNAP, SOUND);
    log.interfaces.truncate(1);
    if let Some(packet) = log.packets.first_mut() {
        packet.annotation = Some(Annotation {
            event: 0,
            classification: 0,
            flow_state: 0,
            flow_slot: 0,
            flow_generation: 0,
            rule: 0,
            ..opening(0, 0)
        });
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a pair broken several ways");
    assert!(error.contains("do not agree in 4 respect(s)"), "{error}");
    assert!(
        error.contains("naming no lifecycle or policy event"),
        "{error}"
    );
    assert!(error.contains("interface block(s)"), "{error}");
    assert!(error.contains("naming flow-opened"), "{error}");
}

/// A refusal the filter itself made, as a record states it.
fn refusal(reason: &str, event: u8, rule: u16) -> Annotation {
    Annotation {
        verdict: VERDICT_DROPPED,
        drop_reason: reason_code(reason),
        event,
        classification: 0,
        flow_state: 0,
        flow_slot: 0,
        flow_generation: 0,
        rule,
        ..opening(0, 0)
    }
}

/// The witness a boot that provoked the dropping rule carries.
fn probed_the_denying_rule() -> PolicyWitness {
    PolicyWitness {
        probed_the_denying_rule: true,
        ..witness()
    }
}

/// A capture holding [`SOUND`] plus one record of the probe the tap is not held
/// to, carrying `annotation`.
///
/// Probe 2 rather than either routed one, because the harness watched both of
/// those come back on the far port: a refusal carrying their bytes would be
/// caught by the wire comparison and the case would prove that instead.
fn capture_with(annotation: Annotation) -> Parsed {
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    capture.packets.push(record(CAPTURE_SNAP, 9, 2, annotation));
    capture
}

/// **The misattribution the counter comparison cannot see.** A denial credited
/// to the rule that *accepts* moves that rule's hit total and the denial counter
/// together, so both of the appliance's accounts still agree — and the join
/// between them passes while the record in front of it says the filter admitted
/// and refused one frame by one rule.
///
/// Both halves are asserted here, on one fixture: the old law finding nothing is
/// what makes the new one worth its cost.
#[test]
fn a_denial_credited_to_the_accepting_rule_is_a_finding_no_counter_can_make() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = capture_with(refusal(
        "policy_denied",
        EVENT_POLICY_DENIED,
        ACCEPTING.saturating_add(1),
    ));
    let surface = capture_surface(&capture);
    let found = policy_differences(
        &surface,
        &Policy {
            declared: &DECLARED_IDS,
            witness: probed_the_denying_rule(),
        },
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found.iter().any(
            |difference| difference.contains("cannot be the one that refused it")
                && difference.contains("probe-forward")
        ),
        "{found:?}"
    );
    // And through the whole judgement, so the law is reachable from a boot
    // rather than only from a direct call.
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &surface,
        &wire(&probes),
        &Policy {
            declared: &DECLARED_IDS,
            witness: probed_the_denying_rule(),
        },
    )
    .expect_err("a denial credited to the rule that accepts");
    assert!(
        error.contains("cannot be the one that refused it"),
        "{error}"
    );
}

/// The mirror: the rule that *drops* on a frame the appliance carried.
#[test]
fn a_forwarded_frame_credited_to_the_dropping_rule_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = capture.packets.first_mut() {
        packet.annotation = Some(Annotation {
            rule: DROPPING.saturating_add(1),
            ..opening(0, 0)
        });
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect_err("a frame the appliance carried, credited to the rule that drops");
    assert!(
        error.contains("admitted by some other rule than the one credited here"),
        "{error}"
    );
    assert!(error.contains("probe-blocked"), "{error}");
}

/// A boot that ran two policies: the same two ids exchange their actions across
/// the commit, so each legitimately appears under both verdicts and the
/// attribution law stands down.
#[test]
fn a_reconfigured_boot_lets_one_rule_carry_both_verdicts() {
    let log = recording(LOG_SNAP, SOUND);
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    if let Some(packet) = capture.packets.first_mut() {
        packet.annotation = Some(Annotation {
            rule: DROPPING.saturating_add(1),
            ..opening(0, 0)
        });
    }
    let probes = injected();
    judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &Policy {
            declared: &DECLARED_IDS,
            witness: PolicyWitness {
                reconfigured: true,
                ..witness()
            },
        },
    )
    .expect("across a commit a rule's action moves, so its records carry both verdicts");
}

/// A record crediting a rule past the end of the policy in force: a rule no
/// operator wrote.
#[test]
fn a_rule_position_past_the_policy_in_force_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = capture_with(refusal(
        "policy_denied",
        EVENT_POLICY_DENIED,
        // One past the last rule the witness says the document declares.
        u16::try_from(DECLARED.len())
            .expect("two rules fit")
            .saturating_add(1),
    ));
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &Policy {
            declared: &DECLARED_IDS,
            witness: probed_the_denying_rule(),
        },
    )
    .expect_err("a rule nobody wrote");
    assert!(
        error.contains("credits a rule no operator wrote"),
        "{error}"
    );
}

/// The two refusals the filter makes, each held to naming a rule or naming none:
/// a denial is a rule's decision and a fallthrough is the absence of one.
#[test]
fn a_refusal_attributed_against_its_own_reason_is_a_finding() {
    for (reason, event, rule, clause) in [
        (
            "policy_denied",
            EVENT_POLICY_DENIED,
            0,
            "states a refusal it cannot attribute",
        ),
        (
            "no_policy_match",
            EVENT_POLICY_NO_MATCH,
            DROPPING.saturating_add(1),
            "the one refusal no rule made",
        ),
    ] {
        let log = recording(LOG_SNAP, SOUND);
        let capture = capture_with(refusal(reason, event, rule));
        let probes = injected();
        let error = judge(
            &log_surface(&log),
            &capture_surface(&capture),
            &wire(&probes),
            &Policy {
                declared: &DECLARED_IDS,
                witness: PolicyWitness {
                    probed_the_denying_rule: true,
                    probed_the_fallthrough: true,
                    ..witness()
                },
            },
        )
        .expect_err("a refusal whose reason and whose attribution describe different outcomes");
        assert!(error.contains(clause), "{error}");
    }
}

/// An appliance nobody owns settles every frame in front of admission, so no
/// record of that boot names a rule.
///
/// No count could state this at all: a hit total that credits the rule and a
/// record that names it agree with each other about work that could not have
/// happened, whichever way round they are read.
#[test]
fn a_rule_named_on_an_unowned_boot_is_a_finding() {
    let capture = recording(CAPTURE_SNAP, SOUND);
    let surface = capture_surface(&capture);
    let found = policy_differences(
        &surface,
        &Policy {
            declared: &DECLARED_IDS,
            witness: PolicyWitness {
                unowned: true,
                ..witness()
            },
        },
    );
    assert!(
        found
            .iter()
            .any(|difference| difference.contains("nobody owns")),
        "{found:?}"
    );
}

/// The zero case of the outcome law, which is its stronger half: a refusal in
/// the capture that no probe of this boot could have provoked.
#[test]
fn a_refusal_no_probe_provoked_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = capture_with(refusal(
        "policy_denied",
        EVENT_POLICY_DENIED,
        DROPPING.saturating_add(1),
    ));
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        // The default witness: this boot injected nothing the dropping rule
        // could refuse.
        &policy(),
    )
    .expect_err("a refusal nobody put on the wire");
    assert!(
        error.contains("injected nothing a rule that says drop could refuse"),
        "{error}"
    );
}

/// And the demand half: a refusal the probes aimed at, and a capture that holds
/// none.
#[test]
fn a_refusal_the_probes_provoked_and_the_capture_lacks_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &Policy {
            declared: &DECLARED_IDS,
            witness: PolicyWitness {
                probed_the_fallthrough: true,
                ..witness()
            },
        },
    )
    .expect_err("a probe the default deny had to refuse, and no record of it");
    assert!(error.contains("the default deny did not happen"), "{error}");
}

/// A previous boot's records are not this boot's to answer for: the medium it
/// carried was written under a policy and an ownership this witness does not
/// describe.
#[test]
fn a_carried_mediums_records_are_not_held_to_this_boots_policy() {
    // The medium and the download built the same way, so what the earlier boot
    // left is exactly the prefix this boot answers — and this boot appended
    // nothing, leaving the misattribution below entirely the earlier boot's.
    let misattributed = || {
        capture_with(refusal(
            "policy_denied",
            EVENT_POLICY_DENIED,
            ACCEPTING.saturating_add(1),
        ))
    };
    let carried_log = recording(LOG_SNAP, SOUND);
    let log = recording(LOG_SNAP, SOUND);
    let carried_capture = misattributed();
    let capture = misattributed();
    let probes = injected();
    judge(
        &resumed(log_surface(&log), &carried_log),
        &resumed(capture_surface(&capture), &carried_capture),
        &wire(&probes),
        &policy(),
    )
    .expect("a witness describes the boot that carries it and no earlier one");
}

/// A refusal naming a reason this build's tap ABI has no word for.
///
/// The law that survives its counter half being taken out of the comparison it
/// used to sit inside: it consults no counter, so it says exactly as much with
/// one surface as it did beside two.
#[test]
fn a_drop_reason_outside_the_vocabulary_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let mut capture = capture_with(refusal(
        "policy_denied",
        EVENT_POLICY_DENIED,
        DROPPING.saturating_add(1),
    ));
    if let Some(packet) = capture.packets.last_mut()
        && let Some(annotation) = packet.annotation.as_mut()
    {
        annotation.drop_reason = u8::try_from(DROP_REASONS.len())
            .expect("the vocabulary fits a byte")
            .saturating_add(1);
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &Policy {
            declared: &DECLARED_IDS,
            witness: probed_the_denying_rule(),
        },
    )
    .expect_err("a refusal this build has no word for");
    assert!(
        error.contains("outside the 26 this build's vocabulary declares"),
        "{error}"
    );
}

/// The harness contradicting itself: a witness whose rules the document it was
/// read beside does not declare, so no record can be attributed to either.
#[test]
fn a_witness_rule_the_document_does_not_declare_is_a_finding() {
    let capture = recording(CAPTURE_SNAP, SOUND);
    let elsewhere = vec![String::from("some-other-rule")];
    let found = policy_differences(
        &capture_surface(&capture),
        &Policy {
            declared: &elsewhere,
            witness: witness(),
        },
    );
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found
            .iter()
            .any(|difference| difference.contains("accepting rule")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|difference| difference.contains("dropping rule")),
        "{found:?}"
    );
}

/// The attribution itself, in the run log: which rule this boot's records
/// credited, and how often.
#[test]
fn the_evidence_states_which_rule_each_record_credited() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let agreement = judge(
        &log_surface(&log),
        &capture_surface(&capture),
        &wire(&probes),
        &policy(),
    )
    .expect("a sound pair");
    assert_eq!(
        agreement.rule_positions.get(&ACCEPTING),
        Some(&(String::from("probe-forward"), 4))
    );
    let evidence = agreement.evidence();
    assert!(
        evidence.contains("4\u{d7} position 0 (probe-forward)"),
        "{evidence}"
    );
}

/// A refusal whose reason and whose attribution describe different outcomes is
/// wrong whoever owns the node, so that law holds on an unowned boot too.
///
/// It has to be stated separately because the law that *replaces* the
/// attribution law there cannot reach this record: the fault is a denial naming
/// no rule, and a record naming no rule is exactly what an unowned boot's own law
/// is satisfied by. The rest of the fixture is sound traffic, and every record of
/// it trips that other law correctly — an unowned appliance consults no filter,
/// so a forwarded frame crediting a rule is a finding whatever else is wrong.
#[test]
fn an_unowned_boot_still_holds_a_refusal_to_its_own_reason() {
    let capture = capture_with(refusal("policy_denied", EVENT_POLICY_DENIED, 0));
    let found = policy_differences(
        &capture_surface(&capture),
        &Policy {
            declared: &DECLARED_IDS,
            witness: PolicyWitness {
                unowned: true,
                ..witness()
            },
        },
    );
    assert_eq!(
        found
            .iter()
            .filter(|difference| difference.contains("states a refusal it cannot attribute"))
            .count(),
        1,
        "{found:?}"
    );
}
