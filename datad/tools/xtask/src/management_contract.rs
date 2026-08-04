//! The management port's record on the `LFW-PD` console channel, and the two
//! questions a boot has to answer about it.
//!
//! This is [`crate::clock_contract`]'s pattern on a third record, and the one
//! whose content the harness *does* know in advance: the frames it injected into
//! the management port and the bytes they carried. Where the clock's record can
//! only be held to a band, this one is held to an equality — the appliance must
//! report exactly what was put on that wire, no more and no less.
//!
//! # What each direction of that equality catches
//!
//! **Fewer** frames than were injected means the chain dropped one: the NIC, the
//! driver's receive path, the pipeline, or the management domain's own drain.
//! **More** means something else reached the port, or a count was double-added —
//! either way the number an operator reads is not the traffic the port saw. The
//! byte total is what makes the frame count more than a tally of notifications:
//! the injected frames are of four different lengths, so a report that summed a
//! constant, or summed the wrong field, cannot produce the right total.
//!
//! # Why the harness waits before injecting, and what it waits for
//!
//! A frame put on a wire before the appliance has posted a receive buffer is
//! lost — QEMU's virtio-net drops it exactly as a real link drops one to a peer
//! that is not up. The routed contract tolerates that by retransmitting; an
//! *exact* count cannot, because a retransmission is a second frame. So the
//! injection happens once, at a point the capture proves the port is ready, and
//! [`ports_are_ready`] is that point: every driver instance has primed its
//! receive queue and the management domain has attached its regions.
//!
//! # No adversary
//!
//! As [`crate::console_records`]: this reads the appliance's own output on a wire
//! only the harness is attached to.

use std::path::Path;

use lfw_log::{Domain, DomainState};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value};
use crate::topology::PORTS;

/// Driver instances the image carries, and so the number of `state=ready`
/// records the drivers produce between them: one per dataplane port plus the
/// management port's. A build fact — the system description declares an instance
/// per port — and the reason a reader cannot tell them apart is
/// that all three report as `domain=nic-driver`, one binary having one name.
const DRIVER_INSTANCES: usize = PORTS + 1;

/// What the harness put on the management wire, and therefore what the appliance
/// owes a record of.
///
/// Carried from the injection to the judgement rather than restated, so the two
/// cannot disagree: a contract that named its own expected numbers would be
/// asserting against a second copy of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagementInjection {
    pub frames: usize,
    pub bytes: u64,
}

impl ManagementInjection {
    /// Whether anything was injected at all. A run that never reached the
    /// injection point has nothing to be judged against, and saying so is not
    /// the same as passing.
    pub fn is_empty(&self) -> bool {
        self.frames == 0
    }
}

/// Whether the capture proves every port is up and the management domain has
/// attached — the point at which a frame injected into the management port will
/// be received rather than dropped for want of a posted buffer.
///
/// Both halves are needed and neither implies the other. A driver's `ready`
/// record is written after its device has gone live with a primed receive queue,
/// so counting them is what says the management NIC will take a frame; the
/// management domain's own `ready` record is what says the domain that must
/// drain the pipeline exists and holds its handles.
pub fn ports_are_ready(serial: &[u8]) -> bool {
    let text = String::from_utf8_lossy(serial);
    let records = lifecycle_records(&text);
    let ready = field("state", DomainState::Ready.name());
    let ready_records = |domain: Domain| {
        records
            .iter()
            .filter(|record| {
                record.contains(&field("domain", domain.name())) && record.contains(&ready)
            })
            .count()
    };
    ready_records(Domain::NicDriver) >= DRIVER_INSTANCES && ready_records(Domain::Management) >= 1
}

/// The running total the management domain has most recently reported, or zero
/// where it has reported none.
///
/// The domain writes its total on every drain that moved a frame, so this is what
/// the port is known to have received *so far* — which is what lets the harness
/// inject a burst the pipeline can actually hold and wait for it before sending
/// more. Zero and "nothing reported yet" are the same answer on purpose: both
/// mean no frame is known to have arrived, which is what a caller about to send
/// the first chunk needs.
#[must_use]
pub fn frames_reported(serial: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(serial);
    lifecycle_records(&text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Management.name())))
        .filter_map(|record| value(record, "frames"))
        .filter_map(|frames| frames.parse::<u64>().ok())
        .next_back()
        .unwrap_or(0)
}

/// Judge the management domain's records in one boot's serial capture against
/// what was injected into its port.
///
/// # Errors
/// The verdict, naming what the channel carried against what the appliance owes
/// it, and where the whole run log is.
pub fn judge(serial: &[u8], log: &Path, injected: ManagementInjection) -> Result<String, String> {
    if injected.is_empty() {
        return Err(format!(
            "the harness injected nothing into the management port, so there is no count for the \
             console to be judged against. The injection happens once, at the point the capture \
             proves every port is up, so this means that point was never reached — no boot can \
             satisfy this contract without it\n  full run log: {}",
            log.display()
        ));
    }

    let text = String::from_utf8_lossy(serial);
    let ours: Vec<&str> = lifecycle_records(&text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Management.name())))
        .collect();

    // Every record carrying a count, in the order the domain wrote them. There
    // may be several: the domain reports its running total on each drain that
    // moved a frame, and how many drains a burst takes is the scheduler's to
    // decide. The final one is the whole of what the port received.
    let mut counted: Vec<(u64, u64)> = Vec::new();
    for record in &ours {
        let Some(frames) = value(record, "frames") else {
            continue;
        };
        let bytes = value(record, "bytes").ok_or_else(|| {
            format!(
                "{record:?} carries `frames=` and no `bytes=`, and the pair is specified to travel \
                 together\n  full run log: {}",
                log.display()
            )
        })?;
        let frames = number(record, "frames", frames, log)?;
        let bytes = number(record, "bytes", bytes, log)?;
        counted.push((frames, bytes));
    }

    let Some(&(frames, bytes)) = counted.last() else {
        return Err(format!(
            "the console carried no `{}` record with a `frames=` field for the management \
             domain, and {} frames were injected into its port. The domain reports its running \
             total on every drain that moved one, so none means no frame reached it: the NIC, the \
             driver's receive path, the pipeline or the drain itself lost \
             all of them\n  management records observed: {ours:#?}\n  full run log: {}",
            LIFECYCLE_PREFIX.trim_end(),
            injected.frames,
            log.display()
        ));
    };

    // Monotonic, because each record is a cumulative total: a pair that fell is
    // a counter reset or a record read out of the wrong offsets, and either
    // makes the last pair meaningless rather than merely late.
    for window in counted.windows(2) {
        if let [(earlier_frames, earlier_bytes), (later_frames, later_bytes)] = window
            && (later_frames < earlier_frames || later_bytes < earlier_bytes)
        {
            return Err(format!(
                "the management domain reported ({earlier_frames}, {earlier_bytes}) and then \
                 ({later_frames}, {later_bytes}): these are cumulative totals for the domain's \
                 life, so neither may fall\n  management records observed: {ours:#?}\n  full run \
                 log: {}",
                log.display()
            ));
        }
    }

    let expected = (injected.frames as u64, injected.bytes);
    if (frames, bytes) != expected {
        return Err(format!(
            "the management port received {frames} frames of {bytes} bytes and the harness \
             injected {} frames of {} bytes into it. Fewer means the chain dropped one — the NIC, \
             the driver's receive path, the pipeline, or the domain's own drain; more means \
             something else reached the port or a count was added twice. The injected frames are \
             of four different lengths, so the byte total cannot agree by \
             accident\n  management records observed: {ours:#?}\n  full run log: {}",
            expected.0,
            expected.1,
            log.display()
        ));
    }

    Ok(format!(
        "the management port received {frames} frames of {bytes} bytes and forwarded none"
    ))
}

fn number(record: &str, key: &str, raw: &str, log: &Path) -> Result<u64, String> {
    raw.parse().map_err(|error| {
        format!(
            "{record:?}: {key} is no number: {error}\n  full run log: {}",
            log.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    const INJECTED: ManagementInjection = ManagementInjection {
        frames: 4,
        bytes: 352,
    };

    /// The lifecycle records a boot leaves before anything is injected: every
    /// driver ready, the management domain attached, and no count yet.
    fn booted() -> String {
        let mut text = String::from(
            "Bootstrapping kernel\r\n\
             LFW-BOOT slot=A state=confirmed\r\n\
             LFW-PD domain=config state=ready\r\n\
             LFW-PD domain=management state=starting\r\n\
             LFW-PD domain=management state=ready\r\n",
        );
        for _ in 0..DRIVER_INSTANCES {
            text.push_str("LFW-PD domain=nic-driver state=ready rx-posted=64\r\n");
        }
        text
    }

    fn received(frames: u64, bytes: u64) -> String {
        format!("LFW-PD domain=management state=ready frames={frames} bytes={bytes}\r\n")
    }

    #[test]
    fn a_boot_that_reported_exactly_what_was_injected_is_accepted() {
        let capture = booted() + &received(4, 352);
        let proved = judge(capture.as_bytes(), log(), INJECTED).expect("an exact report");
        assert!(proved.contains("4 frames of 352 bytes"), "{proved}");
        assert!(proved.contains("forwarded none"), "{proved}");
    }

    /// The domain reports on every drain that moved a frame, and how many drains
    /// a burst takes is the scheduler's business: the final total is the verdict.
    #[test]
    fn a_burst_reported_over_several_drains_is_judged_by_its_final_total() {
        let capture =
            booted() + &received(1, 60) + &received(2, 124) + &received(3, 224) + &received(4, 352);
        judge(capture.as_bytes(), log(), INJECTED).expect("a report in four parts");
    }

    #[test]
    fn a_count_that_falls_short_names_the_two_numbers() {
        let capture = booted() + &received(3, 292);
        let verdict = judge(capture.as_bytes(), log(), INJECTED).expect_err("a dropped frame");
        assert!(
            verdict.contains("received 3 frames of 292 bytes"),
            "{verdict}"
        );
        assert!(
            verdict.contains("injected 4 frames of 352 bytes"),
            "{verdict}"
        );
    }

    /// The byte total is the half a frame count cannot carry: the right number
    /// of frames summing to the wrong bytes is a report of something other than
    /// the traffic that arrived.
    #[test]
    fn the_right_frame_count_with_the_wrong_byte_total_is_refused() {
        for bytes in [0, 240, 351, 353, u64::MAX] {
            let capture = booted() + &received(4, bytes);
            let verdict =
                judge(capture.as_bytes(), log(), INJECTED).expect_err("a wrong byte total");
            assert!(verdict.contains(&format!("{bytes} bytes")), "{verdict}");
        }
    }

    #[test]
    fn more_frames_than_were_injected_is_refused_as_readily_as_fewer() {
        let capture = booted() + &received(5, 412);
        let verdict = judge(capture.as_bytes(), log(), INJECTED).expect_err("a spurious frame");
        assert!(verdict.contains("received 5 frames"), "{verdict}");
    }

    #[test]
    fn a_boot_that_reported_no_count_at_all_says_which_chain_lost_the_frames() {
        for silent in [String::new(), booted()] {
            let verdict = judge(silent.as_bytes(), log(), INJECTED).expect_err("no count");
            assert!(verdict.contains("carried no"), "{verdict}");
            assert!(verdict.contains("4 frames were injected"), "{verdict}");
        }
    }

    /// A run that never reached the injection point proves nothing, and must not
    /// read as a pass: the counts would agree at zero.
    #[test]
    fn a_run_that_injected_nothing_is_refused_rather_than_trivially_satisfied() {
        let capture = booted() + &received(0, 0);
        let verdict = judge(capture.as_bytes(), log(), ManagementInjection::default())
            .expect_err("nothing was injected");
        assert!(verdict.contains("injected nothing"), "{verdict}");
    }

    #[test]
    fn a_cumulative_total_that_fell_is_refused() {
        let capture = booted() + &received(4, 352) + &received(2, 124);
        let verdict = judge(capture.as_bytes(), log(), INJECTED).expect_err("a falling total");
        assert!(verdict.contains("neither may fall"), "{verdict}");
    }

    #[test]
    fn a_record_carrying_frames_without_bytes_is_refused_by_the_field_it_lacks() {
        let capture = booted() + "LFW-PD domain=management state=ready frames=4\r\n";
        let verdict = judge(capture.as_bytes(), log(), INJECTED).expect_err("half a pair");
        assert!(verdict.contains("no `bytes=`"), "{verdict}");
    }

    #[test]
    fn a_field_that_is_not_a_number_is_reported_rather_than_read_as_zero() {
        for record in [
            "LFW-PD domain=management state=ready frames=some bytes=352\r\n",
            "LFW-PD domain=management state=ready frames=4 bytes=lots\r\n",
        ] {
            let capture = booted() + record;
            let verdict = judge(capture.as_bytes(), log(), INJECTED).expect_err("a bad field");
            assert!(verdict.contains("is no number"), "{verdict}");
        }
    }

    /// Another domain's record is never read as the management domain's. The
    /// channel carries every domain's lifecycle and `domain=` is the only thing
    /// separating them, so a search for `frames=` alone would find nothing today
    /// and the wrong thing the moment a second domain reports a count.
    #[test]
    fn another_domains_count_is_never_read_as_the_management_ports() {
        let capture = booted() + "LFW-PD domain=forwarder state=ready frames=4 bytes=352\r\n";
        let verdict = judge(capture.as_bytes(), log(), INJECTED).expect_err("not ours");
        assert!(verdict.contains("carried no"), "{verdict}");
    }

    #[test]
    fn readiness_needs_every_driver_and_the_management_domain() {
        assert!(ports_are_ready(booted().as_bytes()));
        assert!(!ports_are_ready(b""));

        // One driver short.
        let mut short = String::from("LFW-PD domain=management state=ready\r\n");
        for _ in 0..DRIVER_INSTANCES - 1 {
            short.push_str("LFW-PD domain=nic-driver state=ready rx-posted=64\r\n");
        }
        assert!(!ports_are_ready(short.as_bytes()));

        // Every driver, no management domain.
        let mut driverless = String::new();
        for _ in 0..DRIVER_INSTANCES {
            driverless.push_str("LFW-PD domain=nic-driver state=ready rx-posted=64\r\n");
        }
        assert!(!ports_are_ready(driverless.as_bytes()));

        // A domain that started and never became ready is not ready.
        let starting = driverless.clone() + "LFW-PD domain=management state=starting\r\n";
        assert!(!ports_are_ready(starting.as_bytes()));
    }
}
