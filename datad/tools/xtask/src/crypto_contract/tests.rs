use super::*;

fn log() -> &'static Path {
    Path::new("/nonexistent/qemu.log")
}

/// What a passing boot leaves: the feature word, one proof per primitive in
/// the vocabulary, one cost per measured primitive, and the verdict.
fn capture() -> String {
    let mut text = String::from(
        "Bootstrapping kernel\r\n\
         LFW-BOOT slot=A state=confirmed\r\n\
         LFW-PD domain=crypto state=starting\r\n\
         LFW-PD domain=crypto state=negotiated features=0xfeda3203078bfbff\r\n",
    );
    for primitive in Primitive::ALL {
        let _ = write!(
            text,
            "LFW-PD domain=crypto state=negotiated primitive={primitive} vectors=17\r\n"
        );
    }
    for (primitive, _) in CEILINGS {
        let _ = write!(
            text,
            "LFW-PD domain=crypto state=negotiated primitive={primitive} \
             milli-cycles-per-byte=900\r\n"
        );
    }
    for (primitive, _) in OPERATION_CEILINGS {
        let _ = write!(
            text,
            "LFW-PD domain=crypto state=negotiated primitive={primitive} \
             cycles-per-operation=900000\r\n"
        );
    }
    text.push_str(DELEGATION_BEFORE);
    text.push_str(SESSION);
    text.push_str(DELEGATION_AFTER);
    text.push_str("LFW-PD domain=crypto state=ready\r\n");
    // The store domain's own rendering of the same appliance, which the
    // delegation's records are held against: the claim is that two domains name
    // one node, so a capture with only one side of it proves nothing.
    text.push_str(STORE_IDENTITY);
    text
}

/// The appliance the key holder names, as both domains render it.
const DEVICE: &str = "3f7a1b0c5d2e4f6a8b9c0d1e2f3a4b5c";

/// The direct proof's record: the holder answered, signed, the signature verified
/// under the key it named, and the certificate it handed over carried that key.
const DELEGATION_BEFORE: &str = "LFW-PD domain=crypto state=negotiated \
     delegated-device=3f7a1b0c5d2e4f6a8b9c0d1e2f3a4b5c delegated-signatures=1 \
     delegated-certificate=452\r\n";

/// The same tally after a session whose server half ran on the delegated key. It
/// has moved by the handshake's own `CertificateVerify`; the certificate has not,
/// one appliance having one of those.
const DELEGATION_AFTER: &str = "LFW-PD domain=crypto state=negotiated \
     delegated-device=3f7a1b0c5d2e4f6a8b9c0d1e2f3a4b5c delegated-signatures=2 \
     delegated-certificate=452\r\n";

/// The key holder's own record, on the same boot.
const STORE_IDENTITY: &str = "LFW-PD domain=store state=ready \
     device=3f7a1b0c5d2e4f6a8b9c0d1e2f3a4b5c generation=1 onboarded=false\r\n";

/// What the session and the arena leave behind on a passing boot.
const SESSION: &str = "LFW-PD domain=crypto state=negotiated tls-version=0x0304 \
     tls-suite=0x1303\r\n\
     LFW-PD domain=crypto state=negotiated tls-group=0x11ec tls-echoed=32\r\n\
     LFW-PD domain=crypto state=negotiated \
     peer-device=8f1c2d3e4a5b6c7d8e9f0a1b2c3d4e5f\r\n\
     LFW-PD domain=crypto state=negotiated arena-bytes=196608 \
     arena-bound=2097152\r\n\
     LFW-PD domain=crypto state=negotiated arena-bytes=4096 arena-bound=262144\r\n";

#[test]
fn a_boot_that_proved_and_measured_every_primitive_is_accepted() {
    let verdict = judge(capture().as_bytes(), log(), true).expect("a proven domain");
    for primitive in Primitive::ALL {
        assert!(verdict.contains(&format!("{primitive}=17")), "{verdict}");
    }
    assert!(verdict.contains("under every ceiling"), "{verdict}");
}

/// The same capture on an emulated boot: reported in full, asserted against
/// nothing, and the verdict says which it was.
#[test]
fn an_emulated_boot_reports_its_numbers_without_a_verdict_on_them() {
    let slow = capture().replace("milli-cycles-per-byte=900", "milli-cycles-per-byte=250000");
    let verdict = judge(slow.as_bytes(), log(), false).expect("an emulated boot");
    assert!(
        verdict.contains("emulated rather than accelerated"),
        "{verdict}"
    );
    let refused = judge(slow.as_bytes(), log(), true).expect_err("the same boot, accelerated");
    assert!(refused.contains("slower on this part"), "{refused}");
    assert!(refused.contains("aes-256-gcm"), "{refused}");
}

#[test]
fn a_refusal_is_reported_as_the_refusal_it_is() {
    let text = capture().replace(
        "LFW-PD domain=crypto state=ready",
        "LFW-PD domain=crypto state=refused cause=aes-256-gcm-vector-mismatch signalled=false \
         detail=0x3",
    );
    let verdict = judge(text.as_bytes(), log(), true).expect_err("a refused domain");
    assert!(
        verdict.contains("the cryptography domain refused"),
        "{verdict}"
    );
    assert!(verdict.contains("aes-256-gcm-vector-mismatch"), "{verdict}");
}

/// The exhaustiveness property, from the side that can check it: a vocabulary
/// member whose record never appeared fails, whichever member it is.
#[test]
fn a_primitive_the_domain_never_proved_is_refused_by_name() {
    for primitive in Primitive::ALL {
        let dropped = capture()
            .lines()
            .filter(|line| !line.contains(&format!("primitive={primitive} vectors=")))
            .collect::<Vec<_>>()
            .join("\r\n");
        let verdict = judge(dropped.as_bytes(), log(), true).expect_err("a missing primitive");
        assert!(
            verdict.contains(&format!("primitive={primitive} vectors=")),
            "{verdict}"
        );
    }
}

#[test]
fn a_measured_primitive_with_no_cost_record_is_refused_by_name() {
    for (primitive, _) in CEILINGS {
        let dropped = capture()
            .lines()
            .filter(|line| !line.contains(&format!("primitive={primitive} milli-cycles-per-byte=")))
            .collect::<Vec<_>>()
            .join("\r\n");
        let verdict = judge(dropped.as_bytes(), log(), true).expect_err("a missing measurement");
        assert!(verdict.contains("milli-cycles-per-byte="), "{verdict}");
    }
}

#[test]
fn a_table_that_proved_nothing_is_refused_rather_than_counted() {
    let empty = capture().replace("vectors=17", "vectors=0");
    let verdict = judge(empty.as_bytes(), log(), true).expect_err("an empty table");
    assert!(verdict.contains("against 0 published vectors"), "{verdict}");
}

#[test]
fn a_measurement_of_zero_is_refused_rather_than_read_as_infinitely_fast() {
    let zero = capture().replace("milli-cycles-per-byte=900", "milli-cycles-per-byte=0");
    let verdict = judge(zero.as_bytes(), log(), true).expect_err("a zero cost");
    assert!(verdict.contains("0 thousandths of a cycle"), "{verdict}");
}

#[test]
fn a_boot_with_no_feature_record_is_refused() {
    let silent = capture()
        .lines()
        .filter(|line| !line.contains(" features=0x"))
        .collect::<Vec<_>>()
        .join("\r\n");
    let verdict = judge(silent.as_bytes(), log(), true).expect_err("no feature record");
    assert!(verdict.contains("no `features=` record"), "{verdict}");
}

#[test]
fn a_boot_that_never_finished_and_one_that_finished_twice_are_both_refused() {
    let missing = capture().replace("LFW-PD domain=crypto state=ready\r\n", "");
    let verdict = judge(missing.as_bytes(), log(), true).expect_err("no ready record");
    assert!(verdict.contains("carried 0"), "{verdict}");

    let doubled = format!("{}LFW-PD domain=crypto state=ready\r\n", capture());
    let verdict = judge(doubled.as_bytes(), log(), true).expect_err("a doubled record");
    assert!(verdict.contains("carried 2"), "{verdict}");
}

/// The delegation's own claims, each refused for the reason it exists.
#[test]
fn a_boot_that_did_not_delegate_or_delegated_to_the_wrong_appliance_is_refused() {
    // Only the direct proof, so nothing says the session ran on the delegated
    // key.
    let once = capture().replace(DELEGATION_AFTER, "");
    let verdict = judge(once.as_bytes(), log(), true).expect_err("one delegation record");
    assert!(verdict.contains("exactly two"), "{verdict}");

    // Two records and a tally that did not move: the handshake signed some other
    // way, which is exactly what the pair exists to catch.
    let still = capture().replace("delegated-signatures=2", "delegated-signatures=1");
    let verdict = judge(still.as_bytes(), log(), true).expect_err("an unmoved tally");
    assert!(verdict.contains("signed some other way"), "{verdict}");

    // A holder that reports no signature at all after the direct proof.
    let zero = capture().replace("delegated-signatures=1", "delegated-signatures=0");
    let verdict = judge(zero.as_bytes(), log(), true).expect_err("a zero tally");
    assert!(verdict.contains("0 signatures"), "{verdict}");

    // The two domains naming two appliances, which is the delegation having
    // reached a key that is not this node's.
    let stranger = capture().replace(
        &format!("device={DEVICE} generation=1"),
        "device=00000000000000000000000000000001 generation=1",
    );
    let verdict = judge(stranger.as_bytes(), log(), true).expect_err("two identities");
    assert!(verdict.contains("is not this appliance's"), "{verdict}");

    // A holder that answered with no certificate at all, on a boot that still
    // claimed the delegation worked.
    let bare = capture().replace("delegated-certificate=452", "delegated-certificate=0");
    let verdict = judge(bare.as_bytes(), log(), true).expect_err("no certificate");
    assert!(verdict.contains("0 bytes of certificate"), "{verdict}");

    // Two certificates on one boot, which is one appliance answering as two.
    let two = capture().replace(
        "delegated-signatures=2 delegated-certificate=452",
        "delegated-signatures=2 delegated-certificate=451",
    );
    let verdict = judge(two.as_bytes(), log(), true).expect_err("two certificates");
    assert!(
        verdict.contains("one appliance has one certificate"),
        "{verdict}"
    );

    // A record that lost the certificate field entirely is not a delegation record
    // at all: a partial rendering must not pass for a whole one.
    let partial = capture().replace(" delegated-certificate=452\r\n", "\r\n");
    let verdict = judge(partial.as_bytes(), log(), true).expect_err("partial records");
    assert!(verdict.contains("exactly two"), "{verdict}");

    // And the two records themselves disagreeing.
    let drifted = capture().replace(
        &format!("delegated-device={DEVICE} delegated-signatures=2"),
        "delegated-device=00000000000000000000000000000001 delegated-signatures=2",
    );
    let verdict = judge(drifted.as_bytes(), log(), true).expect_err("a drifting identifier");
    assert!(verdict.contains("a boot has one identity"), "{verdict}");

    // A capture with no store record to hold the claim against.
    let alone = capture().replace(STORE_IDENTITY, "");
    let verdict = judge(alone.as_bytes(), log(), true).expect_err("no holder record");
    assert!(verdict.contains("no `device=` record"), "{verdict}");
}

#[test]
fn another_domains_records_are_never_read_as_this_ones() {
    let other = capture().replace("domain=crypto", "domain=console");
    let verdict = judge(other.as_bytes(), log(), true).expect_err("no crypto records at all");
    assert!(verdict.contains("no `features=` record"), "{verdict}");
}
