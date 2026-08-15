use super::*;

/// A frame as the framing contract lays one out, composed here rather than
/// through anything the appliance links.
fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&[kind, 0, 0, 0]);
    out.extend_from_slice(payload);
    out
}

fn shipment(kind: u8, position: u64, bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::from(position.to_be_bytes());
    payload.extend_from_slice(bytes);
    frame(kind, &payload)
}

/// A transcript with `openssl`'s own chatter around one session, which is what
/// the file on disk actually looks like.
fn transcript(session: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(&b"Using default temp DH parameters\nACCEPT\n"[..]);
    out.extend_from_slice(session);
    out.extend_from_slice(b"\nDONE\nshutting down SSL\nCONNECTION CLOSED\n");
    out
}

fn session(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::from(APPLIANCE_GREETING);
    for frame in frames {
        out.extend_from_slice(frame);
    }
    out
}

#[test]
fn a_session_is_anchored_on_the_greeting_and_its_shipments_read_back() {
    let body = transcript(&session(&[
        shipment(UP_RECORDS, 0, b"abcd"),
        shipment(UP_CAPTURE, 16, b"wxyz"),
    ]));

    let found = walk(&body);

    assert_eq!(found.sessions, 1);
    assert_eq!(
        found.shipments,
        vec![
            Shipment {
                ring: Ring::Log,
                position: 0,
                bytes: b"abcd".to_vec(),
            },
            Shipment {
                ring: Ring::Capture,
                position: 16,
                bytes: b"wxyz".to_vec(),
            },
        ]
    );
}

#[test]
fn each_redial_is_its_own_session_and_every_shipment_is_kept() {
    let mut body = transcript(&session(&[shipment(UP_RECORDS, 0, b"one")]));
    body.extend_from_slice(&transcript(&session(&[shipment(UP_RECORDS, 3, b"two")])));

    let found = walk(&body);

    assert_eq!(found.sessions, 2, "the appliance greeted twice");
    assert_eq!(found.shipments.len(), 2);
    assert_eq!(found.shipments[1].position, 3);
}

#[test]
fn chatter_where_a_frame_header_would_be_ends_the_session_rather_than_the_walk() {
    // The defect this closes: a walk that trusted whatever followed the last
    // frame would read `openssl`'s own trailing lines as a header, take a
    // nonsense length, and either lose the next session or invent a shipment.
    let mut body = transcript(&session(&[shipment(UP_RECORDS, 0, b"kept")]));
    body.extend_from_slice(&transcript(&session(&[shipment(UP_CAPTURE, 0, b"also")])));

    let found = walk(&body);

    assert_eq!(found.sessions, 2);
    assert_eq!(found.shipments.len(), 2);
    assert_eq!(found.shipments[1].ring, Ring::Capture);
}

#[test]
fn a_length_past_the_framing_bound_stops_the_walk_instead_of_sizing_anything() {
    let mut runaway = Vec::from(APPLIANCE_GREETING);
    runaway.extend_from_slice(&u32::MAX.to_be_bytes());
    runaway.extend_from_slice(&[UP_RECORDS, 0, 0, 0]);
    runaway.extend_from_slice(b"short");

    let found = walk(&transcript(&runaway));

    assert_eq!(found.sessions, 1);
    assert!(
        found.shipments.is_empty(),
        "a frame whose length the transcript does not carry is not a shipment"
    );
}

#[test]
fn a_truncated_final_frame_yields_no_shipment_and_no_panic() {
    let mut cut = Vec::from(APPLIANCE_GREETING);
    let whole = shipment(UP_RECORDS, 0, b"abcdefgh");
    cut.extend_from_slice(&whole[..whole.len() - 3]);

    let found = walk(&cut);

    assert_eq!(found.sessions, 1);
    assert!(found.shipments.is_empty());
}

fn extents<'a>(log: &'a [u8], capture: &'a [u8]) -> Vec<Extent<'a>> {
    vec![
        Extent {
            ring: Ring::Log,
            payload: log,
            durable: log.len(),
        },
        Extent {
            ring: Ring::Capture,
            payload: capture,
            durable: capture.len(),
        },
    ]
}

#[test]
fn shipments_matching_the_medium_at_the_positions_they_state_agree() {
    let log = b"0123456789abcdef".to_vec();
    let capture = b"ABCDEFGH".to_vec();
    let shipped = walk(&transcript(&session(&[
        shipment(UP_RECORDS, 0, &log[..8]),
        shipment(UP_RECORDS, 8, &log[8..]),
        shipment(UP_CAPTURE, 0, &capture),
    ])));

    let agreement = judge(&shipped, &extents(&log, &capture), 8).expect("every byte is the disk's");

    assert_eq!(agreement.sessions, 1);
    assert_eq!(
        agreement.carried.get(Ring::Log.name()),
        Some(&(2, 16, 16u64))
    );
}

#[test]
fn a_shipment_that_differs_from_the_medium_names_the_ring_position_and_both_bytes() {
    let log = b"0123456789abcdef".to_vec();
    let capture = b"ABCDEFGH".to_vec();
    let mut wrong = log[8..].to_vec();
    wrong[2] = b'!';
    let shipped = walk(&transcript(&session(&[
        shipment(UP_RECORDS, 8, &wrong),
        shipment(UP_CAPTURE, 0, &capture),
    ])));

    let verdict = judge(&shipped, &extents(&log, &capture), 1).expect_err("byte 10 differs");

    assert!(verdict.contains("ring position 10"), "got: {verdict}");
    assert!(
        verdict.contains("0x61") && verdict.contains("0x21"),
        "got: {verdict}"
    );
    assert!(
        verdict.contains("its own medium does not say"),
        "the verdict must say what the disagreement means: {verdict}"
    );
}

#[test]
fn a_shipment_past_what_the_superblock_made_durable_is_a_finding() {
    // The fault worth catching: an appliance that shipped a management server
    // bytes it had not yet committed to its own medium. The content happens to
    // match, so only the durable bound catches it.
    let log = b"0123456789abcdef".to_vec();
    let capture = b"ABCDEFGH".to_vec();
    let shipped = walk(&transcript(&session(&[shipment(UP_RECORDS, 0, &log)])));
    let mut held = extents(&log, &capture);
    held[0].durable = 8;

    let verdict = judge(&shipped, &held, 1).expect_err("the ring is durable only to byte 8");

    assert!(verdict.contains("only 8 byte(s)"), "got: {verdict}");
    assert!(verdict.contains("does not stand behind"), "got: {verdict}");
}

#[test]
fn a_shipment_reaching_past_the_extent_is_refused_rather_than_indexed() {
    let log = b"0123".to_vec();
    let capture = b"AB".to_vec();
    let shipped = walk(&transcript(&session(&[shipment(
        UP_RECORDS,
        0,
        b"0123456789",
    )])));
    let mut held = extents(&log, &capture);
    held[0].durable = 64;

    let verdict = judge(&shipped, &held, 1).expect_err("the extent is four bytes long");

    assert!(
        verdict.contains("payload area is 4 byte(s) long"),
        "got: {verdict}"
    );
}

#[test]
fn a_boot_that_greeted_nobody_is_refused_rather_than_passing_vacuously() {
    let verdict = judge(&Shipped::default(), &extents(b"", b""), 0)
        .expect_err("no session means nothing was corroborated");

    assert!(
        verdict.contains("no greeting from the appliance"),
        "got: {verdict}"
    );
}

#[test]
fn a_session_that_shipped_less_than_the_boot_owed_is_a_finding() {
    let log = b"0123456789abcdef".to_vec();
    let capture = b"ABCDEFGH".to_vec();
    let shipped = walk(&transcript(&session(&[
        shipment(UP_RECORDS, 0, &log),
        shipment(UP_CAPTURE, 0, &capture[..2]),
    ])));

    let verdict = judge(&shipped, &extents(&log, &capture), 8)
        .expect_err("the capture ring shipped two bytes");

    assert!(verdict.contains("the capture"), "got: {verdict}");
    assert!(verdict.contains("at least 8"), "got: {verdict}");
}
