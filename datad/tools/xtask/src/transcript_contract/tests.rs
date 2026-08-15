use super::*;

const TARGET: &str = "the connection history";

fn serial(lines: &[&str]) -> Vec<u8> {
    let mut out = String::from("Booting `librefirewall`...\r\nseL4 kernel starting\r\n");
    for line in lines {
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.into_bytes()
}

fn line(origin: u8, nanos: Option<u64>, text: &str) -> TranscriptLine {
    TranscriptLine {
        origin,
        unix_nanos: nanos,
        line: text.to_owned(),
    }
}

const READY: &str = "LFW-PD time=unsynchronized domain=management state=ready";
const STARTING: &str = "LFW-PD time=unsynchronized domain=console state=starting";

fn demanded() -> Demanded {
    Demanded {
        at_least: 1,
        anchored_on: "domain=management state=ready",
    }
}

#[test]
fn a_recording_whose_lines_the_boot_printed_agrees() {
    let carried = [line(6, None, STARTING), line(5, Some(7), READY)];
    let agreement = judge(
        TARGET,
        &carried,
        1,
        &serial(&[STARTING, READY]),
        &demanded(),
    )
    .expect("both lines were printed");
    let evidence = agreement.evidence();
    assert!(evidence.contains("2 console line(s) in 1 batch(es)"));
    assert!(evidence.contains("1 of them carry an instant and 1 were emitted"));
}

/// The failure this contract exists for: a line in the recording that the boot
/// never printed. A relay publishing a stale slot, an entry walked with the wrong
/// stride and a length that overran all look like this and like nothing else.
#[test]
fn a_line_the_boot_never_printed_is_refused_and_quoted() {
    let carried = [
        line(5, None, READY),
        line(
            5,
            None,
            "LFW-PD time=unsynchronized domain=store state=refused",
        ),
    ];
    let error = judge(TARGET, &carried, 1, &serial(&[READY]), &demanded())
        .expect_err("the second line was never printed");
    assert!(error.contains("line 2 of 2"));
    assert!(error.contains("domain=store state=refused"));
    assert!(error.contains("invented"));
}

/// Containment must not pass on a recording that carries nothing, which is what
/// the floor refuses.
#[test]
fn a_recording_carrying_no_transcript_is_refused_rather_than_trivially_contained() {
    let error = judge(
        TARGET,
        &[],
        0,
        &serial(&[READY]),
        &Demanded {
            at_least: 1,
            anchored_on: "domain=management state=ready",
        },
    )
    .expect_err("no line at all");
    assert!(error.contains("at least 1"));
}

/// And the anchor refuses the other vacuous pass: a relay that filled during
/// bring-up and never recovered leaves a recording holding only the first few
/// lines, every one of which is contained.
#[test]
fn a_recording_missing_the_anchor_is_refused_however_many_lines_it_holds() {
    let carried = [line(3, None, STARTING), line(3, None, STARTING)];
    let error = judge(
        TARGET,
        &carried,
        1,
        &serial(&[STARTING, READY]),
        &demanded(),
    )
    .expect_err("the anchor was never framed");
    assert!(error.contains("carries no line containing"));
    assert!(error.contains("bring-up"));
}

/// The origin byte is read at a fixed offset in every entry, so a value outside
/// the vocabulary is the offset being wrong rather than a domain this build has
/// not heard of.
#[test]
fn an_origin_no_protection_domain_answers_to_is_refused() {
    let carried = [line(u8::MAX, None, READY)];
    let error = judge(TARGET, &carried, 1, &serial(&[READY]), &demanded())
        .expect_err("255 names no domain");
    assert!(error.contains("names origin 255"));
    assert!(error.contains("wrong offset"));
}

/// A boot whose console said nothing is a boot with nothing to compare against,
/// and answering "contained" for it would be the emptiest pass of all.
#[test]
fn a_boot_with_no_console_records_is_refused() {
    let error = judge(TARGET, &[], 0, b"seL4 kernel starting\r\n", &demanded())
        .expect_err("nothing was printed");
    assert!(error.contains("no console record at all"));
}

/// A transcript read out of an emulator's log may carry either line ending, and a
/// line that kept a stray carriage return would compare unequal for no reason a
/// reader would accept.
#[test]
fn either_line_ending_in_the_serial_log_is_the_same_line() {
    let carried = [line(5, None, READY)];
    for terminator in ["\r\n", "\n"] {
        let serial = format!("kernel\n{READY}{terminator}");
        judge(TARGET, &carried, 1, serial.as_bytes(), &demanded())
            .unwrap_or_else(|error| panic!("{terminator:?} should not matter: {error}"));
    }
}

/// The lines an operator reads are the console's, and a recording carrying the
/// boot manager's words would mean the walk had picked up something else.
#[test]
fn only_the_appliances_own_records_are_taken_out_of_the_serial_log() {
    let taken = printed(&serial(&["Loading kernel", READY, "EFI stub: done"]));
    assert_eq!(taken.len(), 1);
    assert!(taken.contains(READY));
}
