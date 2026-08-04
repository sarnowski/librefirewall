use super::*;

fn log() -> &'static Path {
    Path::new("/nonexistent/qemu.log")
}

const EARLY: &str = "2026-07-30T20:27:00.123456789Z";
const LATE: &str = "2026-07-30T20:27:01.000000000Z";

/// A capture of the shape a passing boot leaves: records emitted before the
/// clock domain published, its own record, and the stamped ones after it.
fn capture(tail: &str) -> String {
    format!(
        "Bootstrapping kernel\r\n\
         LFW-BOOT slot=A state=confirmed\r\n\
         LFW-PD time=unsynchronized domain=config state=starting\r\n\
         LFW-PD time=unsynchronized domain=clock state=starting\r\n\
         LFW-CFG time=unsynchronized generation=0 outcome=applied changes=0\r\n\
         LFW-PD time=unsynchronized domain=clock state=ready tsc-hz=2999998000 \
         utc=2026-07-30T20:27:00.000000000Z\r\n\
         {tail}"
    )
}

fn management(at: &str, frames: u32) -> String {
    format!("LFW-PD time={at} domain=management state=ready frames={frames} bytes=64\r\n")
}

#[test]
fn a_boot_that_stamped_after_its_clock_published_is_accepted() {
    let text = capture(&format!("{}{}", management(EARLY, 1), management(LATE, 2)));
    let proved = judge(text.as_bytes(), log()).expect("a well-stamped transcript");
    assert!(proved.contains("carry a UTC instant"), "{proved}");
}

#[test]
fn a_record_carrying_no_instant_at_all_is_refused_by_the_field_it_is_missing() {
    let text = capture("LFW-PD domain=management state=ready frames=1 bytes=64\r\n");
    let verdict = judge(text.as_bytes(), log()).expect_err("a record with no time field");
    assert!(verdict.contains("carries no `time=` field"), "{verdict}");
}

/// The value has exactly two forms, and anything else is a renderer that has
/// parted from the grammar rather than a value to interpret.
#[test]
fn a_field_that_is_neither_form_is_refused_rather_than_read_as_a_time() {
    for bad in [
        "unsynchronised",
        "0",
        "2026-07-30T20:27:00Z",
        "2026-07-30T20:27:00.123456789",
        "2026-07-30 20:27:00.123456789Z",
        "202X-07-30T20:27:00.123456789Z",
    ] {
        let text = capture(&management(bad, 1));
        let verdict = judge(text.as_bytes(), log()).expect_err(bad);
        assert!(verdict.contains("neither the"), "{bad}: {verdict}");
    }
}

#[test]
fn an_instant_outside_the_band_the_appliance_accepts_is_refused() {
    // Every one of these is an instant a `u64` of nanoseconds can name — the
    // renderer's whole range ends in 2554 — so each lands as a *band* refusal
    // rather than as a field that is no instant.
    for year in ["1970", "1999", "2201", "2553"] {
        let text = capture(&management(&EARLY.replace("2026", year), 1));
        let verdict = judge(text.as_bytes(), log()).expect_err(year);
        assert!(verdict.contains("dated in the year"), "{verdict}");
        assert!(verdict.contains(year), "{verdict}");
    }
    for year in [MIN_PLAUSIBLE_YEAR, MAX_PLAUSIBLE_YEAR] {
        let text = capture(&management(&EARLY.replace("2026", &year.to_string()), 1));
        judge(text.as_bytes(), log()).expect("a year on the boundary");
    }
}

/// The direction of the transition, which is the whole of what the chain
/// claims: a domain stamps nothing, then stamps everything.
#[test]
fn a_domain_that_stopped_stamping_is_refused() {
    let text = capture(&format!(
        "{}{}",
        management(EARLY, 1),
        management(UNSYNCHRONIZED, 2)
    ));
    let verdict = judge(text.as_bytes(), log()).expect_err("a withdrawn calibration");
    assert!(verdict.contains("carries no instant after"), "{verdict}");
}

#[test]
fn a_domains_instants_may_not_go_backwards() {
    let text = capture(&format!("{}{}", management(LATE, 1), management(EARLY, 2)));
    let verdict = judge(text.as_bytes(), log()).expect_err("a counter that went backwards");
    assert!(
        verdict.contains("dated before an earlier record"),
        "{verdict}"
    );
    // The same pair the other way round is what a healthy node produces.
    let forward = capture(&format!("{}{}", management(EARLY, 1), management(LATE, 2)));
    judge(forward.as_bytes(), log()).expect("instants in order");
}

/// Two records of the same instant are ordinary: the counter is read per
/// record and a domain can emit two inside one nanosecond's worth of ticks.
#[test]
fn two_records_sharing_an_instant_are_accepted() {
    let text = capture(&format!("{}{}", management(EARLY, 1), management(EARLY, 2)));
    judge(text.as_bytes(), log()).expect("an unchanged instant");
}

/// The console's rotation decides the capture's order, so two *different*
/// domains' instants may appear in either order and neither is a fault.
#[test]
fn two_domains_out_of_order_against_each_other_are_not_a_fault() {
    let text = capture(&format!(
        "LFW-PD time={LATE} domain=forwarder state=starting\r\n{}",
        management(EARLY, 1)
    ));
    judge(text.as_bytes(), log()).expect("across domains nothing is ordered");
}

/// Three protection domains publish under the one `nic-driver` token, into
/// three rings the rotation interleaves, so their records carry no ordering to
/// judge — and they are still held to the field and to the band.
#[test]
fn the_three_driver_instances_are_not_ordered_against_one_another() {
    let out_of_order = capture(&format!(
        "LFW-PD time={LATE} domain=nic-driver state=ready rx-posted=64\r\n\
         LFW-PD time={EARLY} domain=nic-driver state=ready rx-posted=64\r\n{}",
        management(EARLY, 1)
    ));
    judge(out_of_order.as_bytes(), log()).expect("one token, three rings");

    let outside = capture(&format!(
        "LFW-PD time=1999-07-30T20:27:00.123456789Z domain=nic-driver state=ready rx-posted=64\r\n{}",
        management(EARLY, 1)
    ));
    let verdict = judge(outside.as_bytes(), log()).expect_err("a driver outside the band");
    assert!(verdict.contains("dated in the year"), "{verdict}");
}

#[test]
fn a_capture_with_no_record_at_all_is_refused() {
    for silent in ["", "Bootstrapping kernel\r\n"] {
        let verdict = judge(silent.as_bytes(), log()).expect_err("silence");
        assert!(verdict.contains("no in-kernel record"), "{verdict}");
    }
}

/// Both halves of the chain must appear. A transcript in which nothing predates
/// the calibration means the field is not being read from the region, and one
/// in which nothing follows it means the calibration reached no writer.
#[test]
fn a_transcript_missing_either_half_of_the_transition_is_refused() {
    let never_stamped = capture("LFW-PD time=unsynchronized domain=forwarder state=starting\r\n");
    let verdict = judge(never_stamped.as_bytes(), log()).expect_err("nothing stamped");
    assert!(
        verdict.contains("no record carried an instant"),
        "{verdict}"
    );

    let always_stamped = format!(
        "LFW-BOOT slot=A state=confirmed\r\nLFW-PD time={EARLY} domain=clock state=starting\r\n"
    );
    let verdict = judge(always_stamped.as_bytes(), log()).expect_err("nothing unstamped");
    assert!(verdict.contains("every record carried"), "{verdict}");
}

/// A record that shares its line with kernel prose is still a record, which is
/// the obligation the debug kernel's own output makes real.
#[test]
fn a_record_that_did_not_begin_its_line_is_still_judged() {
    let torn = capture(&format!("Bootstrapping node #0{}", management(EARLY, 1)));
    judge(torn.as_bytes(), log()).expect("a record sharing its line with prose");
}

/// Every instant the renderer can produce is one this parser reads back, which
/// is what keeps the two from agreeing separately about a different form.
#[test]
fn the_parser_reads_back_exactly_what_the_renderer_writes() {
    for nanos in [
        0,
        1,
        1_785_443_220_123_456_789,
        u64::from(u32::MAX) * NANOS_PER_SECOND,
        u64::MAX,
    ] {
        let mut rendered = [0u8; INSTANT_LEN];
        lfw_clock::render_rfc3339(UtcNanos::from_unix_nanos(nanos), &mut rendered);
        let text = core::str::from_utf8(&rendered).expect("the renderer writes ASCII");
        assert_eq!(unix_nanos(text), Some(nanos), "{text}");
    }
}
