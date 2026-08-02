//! The judgement, exercised over synthetic recordings.
//!
//! Every case is built by [`recording`] and then *perturbed* in exactly one
//! way, so a test that fires proves the assertion it is named for and nothing
//! else — and the agreeing case proves that none of the others fires on a
//! sound pair. That is what keeps the contract from being vacuous: each
//! perturbation below is a thing that would have to break in the appliance for
//! the corresponding assertion to fire in QEMU.

use super::*;
use crate::recording_contract::Interface;

const LOG_TARGET: &str = "/logs.pcapng";
const CAPTURE_TARGET: &str = "/capture.pcapng";
const LOG_SNAP: u32 = 128;
const CAPTURE_SNAP: u32 = 2048;
const PORTS: usize = 2;

/// The two probes the synthetic bench injects, one per port.
fn injected() -> Vec<Injected> {
    vec![
        Injected {
            name: "routed-0-to-1",
            frame: (0..65u8).collect(),
            observed: true,
        },
        Injected {
            name: "routed-1-to-0",
            frame: (100..166u8).collect(),
            observed: true,
        },
        // The probe the tap never sees, which must NOT be demanded of the
        // capture: it is here so a change that started demanding every probe
        // fails a test rather than a ten-minute boot.
        Injected {
            name: "legacy-l2-broadcast",
            frame: vec![0xff; 60],
            observed: false,
        },
    ]
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
                Packet {
                    interface_id: (*probe % PORTS) as u32,
                    packet_id: Some(*id),
                    original_len: frame.len() as u32,
                    captured: frame
                        .iter()
                        .take(snap_len as usize)
                        .copied()
                        .collect::<Vec<u8>>(),
                }
            })
            .collect(),
        consumed: 0,
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

/// A sink that silently dropped a record. Invisible in that recording, which
/// still parses and still counts up — and visible only against the other one.
#[test]
fn a_recording_short_of_the_others_blocks_is_a_finding() {
    let log = recording(LOG_SNAP, &SOUND[..3]);
    let capture = recording(CAPTURE_SNAP, SOUND);
    let probes = injected();
    let error = judge(
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
    )
    .expect_err("three blocks against four is a lost observation");
    assert!(error.contains("holds 3 packet block(s)"), "{error}");
    assert!(error.contains("holds 4"), "{error}");
    // And it names the identity that is missing, not merely the count.
    assert!(error.contains("does not pair"), "{error}");
    assert!(error.contains('3'), "{error}");
}

/// Equal counts and different identities: a sink that lost one observation and
/// recorded one the other never saw. A count check alone passes this.
#[test]
fn an_unpaired_packet_id_is_a_finding_even_at_an_equal_count() {
    let log = recording(LOG_SNAP, SOUND);
    let capture = recording(CAPTURE_SNAP, &[(0, 0), (1, 1), (2, 0), (99, 1)]);
    let probes = injected();
    let error = judge(
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
    )
    .expect_err("an identity in one and not the other is a lost observation");
    assert!(error.contains("does not pair"), "{error}");
    assert!(error.contains("99"), "{error}");
    assert!(
        !error.contains("packet block(s) and"),
        "the counts agree, so no count difference may be reported: {error}"
    );
}

/// A recorder answering blocks it never encoded. The presence check passes it
/// completely — every probe is still there — and only the fabrication
/// direction catches it.
#[test]
fn a_packet_the_harness_never_injected_is_a_finding() {
    let mut capture = recording(CAPTURE_SNAP, SOUND);
    capture.packets.push(Packet {
        interface_id: 0,
        packet_id: Some(4),
        original_len: 65,
        // The first probe with one byte changed near its end: a fabrication
        // that a length comparison alone would accept.
        captured: (0..65u8)
            .map(|byte| if byte == 60 { 0 } else { byte })
            .collect(),
    });
    let mut log = recording(LOG_SNAP, SOUND);
    log.packets.push(capture.packets[4].clone());
    let probes = injected();
    let error = judge(
        &log_surface(&log, 5),
        &capture_surface(&capture, 5),
        &wire(&probes),
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
        interface_id: 0,
        packet_id: Some(4),
        original_len: 200,
        captured: long.clone(),
    });
    let probes = [
        injected(),
        vec![Injected {
            name: "oversized",
            frame: long,
            observed: false,
        }],
    ]
    .concat();
    let error = judge(
        &log_surface(&log, 5),
        &capture_surface(&capture, 4),
        &wire(&probes),
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
        }],
        consumed: 0,
    };
    let log = block(LOG_SNAP as usize);
    let capture = block(CAPTURE_SNAP as usize);
    let agreement = judge(
        &log_surface(&log, 1),
        &capture_surface(&capture, 1),
        &wire(&probes),
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
    )
    .expect_err("a block with no identity pairs with nothing");
    assert!(error.contains("no epb_packetid"), "{error}");
}

/// Every finding at once, so a run that has to be repeated to see the second
/// one is a run that costs ten minutes to learn one fact.
#[test]
fn every_disagreement_is_reported_not_only_the_first() {
    let mut log = recording(LOG_SNAP, &[(0, 0)]);
    let capture = recording(CAPTURE_SNAP, SOUND);
    log.interfaces.truncate(1);
    let probes = injected();
    let error = judge(
        &log_surface(&log, 4),
        &capture_surface(&capture, 4),
        &wire(&probes),
    )
    .expect_err("a pair broken several ways");
    assert!(error.contains("do not agree in"), "{error}");
    assert!(error.contains("does not pair"), "{error}");
    assert!(error.contains("interface block(s)"), "{error}");
}
