//! The judgement, exercised over synthetic recordings.
//!
//! Every case is built by [`recording`] and then *perturbed* in exactly one
//! way, so a test that fires proves the assertion it is named for and nothing
//! else — and the agreeing case proves that none of the others fires on a
//! sound pair. That is what keeps the contract from being vacuous: each
//! perturbation below is a thing that would have to break in the appliance for
//! the corresponding assertion to fire in QEMU.

use super::*;
use crate::recording_contract::{
    CLASSIFICATION_NEW, EVENT_FLOW_REFUSED, Interface, STATE_TIME_WAIT,
};

const LOG_TARGET: &str = "/logs.pcapng";
const CAPTURE_TARGET: &str = "/capture.pcapng";
const LOG_SNAP: u32 = 128;
const CAPTURE_SNAP: u32 = 2048;
const PORTS: usize = 2;

/// The two probes the synthetic bench injects, one per port, each opening a
/// conversation the connection history must record.
fn injected() -> Vec<Injected> {
    vec![
        Injected {
            name: "routed-0-to-1",
            frame: (0..65u8).collect(),
            observed: true,
            verdict: VERDICT_FORWARDED,
            event: Some(EVENT_FLOW_OPENED),
        },
        Injected {
            name: "routed-1-to-0",
            frame: (100..166u8).collect(),
            observed: true,
            verdict: VERDICT_FORWARDED,
            event: Some(EVENT_FLOW_OPENED),
        },
        // The probe the tap never sees, which must NOT be demanded of the
        // capture: it is here so a change that started demanding every probe
        // fails a test rather than a ten-minute boot.
        Injected {
            name: "legacy-l2-broadcast",
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
        captured: frame.into_iter().take(snap_len as usize).collect(),
        verdict: Some(vec![VERDICT_KIND, annotation.verdict]),
        annotation: Some(annotation),
    }
}

/// The exposition a sound run answers: enough forwarding and enough hits for
/// every record the recordings hold.
fn published() -> Published {
    Published {
        forwarded_frames: 100,
        drop_reasons: DROP_REASONS
            .iter()
            .map(|reason| ((*reason).to_owned(), Some(100)))
            .collect(),
        rules: vec![DeclaredRule {
            id: "probe-forward".to_owned(),
            hits: Some(4),
        }],
    }
}

/// The blocks both sinks hold on a sound run: each probe seen twice, as a
/// station that retransmitted once would produce.
const SOUND: &[(u64, usize)] = &[(0, 0), (1, 1), (2, 0), (3, 1)];

fn log_surface(parsed: &Parsed, published: u64) -> Surface<'_> {
    Surface {
        target: LOG_TARGET,
        snap_len: LOG_SNAP,
        parsed,
        published_records: published,
    }
}

fn capture_surface(parsed: &Parsed, published: u64) -> Surface<'_> {
    Surface {
        target: CAPTURE_TARGET,
        snap_len: CAPTURE_SNAP,
        parsed,
        published_records: published,
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
    )
    .expect("a sound pair");
    assert_eq!(agreement.paired, 4);
    // Two of the three probes are observable; the broadcast one is not, and
    // demanding it would be asserting a contract the appliance does not have.
    assert_eq!(agreement.probes_matched, 2);
    let evidence = agreement.evidence();
    assert!(evidence.contains("/logs.pcapng"), "{evidence}");
    assert!(evidence.contains("/capture.pcapng"), "{evidence}");
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
            drop_reason: 16,
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
            drop_reason: 24,
            event: EVENT_POLICY_DENIED,
            ..opening(0, 0)
        });
        packet.verdict = Some(vec![VERDICT_KIND, VERDICT_DROPPED]);
    }
    let probes = injected();
    let error = judge(
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
    )
    .expect_err("the harness watched that probe come back on the far port");
    assert!(error.contains("under verdict 1"), "{error}");
    assert!(error.contains("come back on the far port"), "{error}");
}

/// A record naming a rule the appliance credits with no hit: two accounts of one
/// match, disagreeing.
#[test]
fn a_rule_the_exposition_credits_with_no_hit_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let error = judge(
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &Published {
            rules: vec![DeclaredRule {
                id: "probe-forward".to_owned(),
                hits: Some(0),
            }],
            ..published()
        },
    )
    .expect_err("a record crediting a rule that never ran");
    assert!(error.contains("credits it with no hit"), "{error}");
    assert!(error.contains("probe-forward"), "{error}");
}

/// A record refused for a reason the exposition never counted: a recording
/// describing refusals the appliance never made.
#[test]
fn a_refusal_the_exposition_never_counted_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    for packet in &mut capture.packets {
        packet.annotation = Some(Annotation {
            verdict: VERDICT_DROPPED,
            // `flow_mid_stream`, the sixteenth reason this build encodes.
            drop_reason: 16,
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
    let probes: Vec<Injected> = injected()
        .into_iter()
        .map(|injected| Injected {
            verdict: VERDICT_DROPPED,
            event: None,
            ..injected
        })
        .collect();
    let mut drop_reasons = published().drop_reasons;
    drop_reasons.insert("flow_mid_stream".to_owned(), Some(1));
    let error = judge(
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &Published {
            drop_reasons,
            ..published()
        },
    )
    .expect_err("four records of a refusal the appliance counted once");
    assert!(error.contains("refused as \"flow_mid_stream\""), "{error}");
    assert!(error.contains("the appliance counted 1"), "{error}");
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
            &log_surface(&log, 4),
            &capture_surface(&capture, 4),
            &wire(&probes),
            &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 5),
        &capture_surface(&capture, 5),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 5),
        &capture_surface(&capture, 5),
        &wire(&probes),
        &published(),
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
            name: "oversized",
            frame: long,
            observed: false,
            verdict: VERDICT_FORWARDED,
            event: None,
        }],
    ]
    .concat();
    let error = judge(
        &log_surface(&log, 5),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        name: "oversized",
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
            captured: long.iter().take(snap).copied().collect(),
            verdict: Some(vec![VERDICT_KIND, VERDICT_FORWARDED]),
            annotation: Some(opening(0, 0)),
        }],
        consumed: 0,
    };
    let log = block(LOG_SNAP as usize);
    let capture = block(CAPTURE_SNAP as usize);
    let agreement = judge(
        &log_surface(&log, 1),
        &capture_surface(&capture, 1),
        &wire(&probes),
        &published(),
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
            target: LOG_TARGET,
            // The sink this download came from keeps 128, and the file it
            // answered declares 2048 — which is the duplicate showing.
            snap_len: LOG_SNAP,
            parsed: &log,
            published_records: 4,
        },
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
    )
    .expect_err("one ring under two names is one recording");
    assert!(
        error.contains("both declare a snap length of 2048"),
        "{error}"
    );
}

/// A recorder answering more than it says it encoded. The only direction of the
/// metric comparison that is a finding, and the reason it is stated as an
/// inequality.
#[test]
fn a_recording_holding_more_than_the_recorder_published_is_a_finding() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let error = judge(
        &log_surface(&log, 2),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
    )
    .expect_err("four blocks against two encoded records is fabrication");
    assert!(error.contains("answers 4 packet block(s)"), "{error}");
    assert!(error.contains("as 2"), "{error}");
}

/// The other side of the same inequality: a recording holding fewer than the
/// counter says is legitimate — the metric is read before the download and
/// counts records encoded, not records flushed.
#[test]
fn a_recording_holding_fewer_than_the_recorder_published_is_accepted() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    judge(
        &log_surface(&log, 9),
        &capture_surface(&capture, 9),
        &wire(&probes),
        &published(),
    )
    .expect("a staging buffer between the scrape and the download is not a finding");
}

/// A recorder that published nothing at all, so the comparison would be two
/// numbers about nothing.
#[test]
fn a_sink_publishing_no_record_proves_nothing() {
    let log = recording(LOG_SNAP, &[]);
    let capture = recording(CAPTURE_SNAP, &[]);
    let probes = injected();
    let error = judge(
        &log_surface(&log, 0),
        &capture_surface(&capture, 0),
        &wire(&probes),
        &published(),
    )
    .expect_err("zero against zero is not agreement");
    assert!(error.contains("no encoded record at all"), "{error}");
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
        &log_surface(&log, 2),
        &capture_surface(&capture, 2),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
        &published(),
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
