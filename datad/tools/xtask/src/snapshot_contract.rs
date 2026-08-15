//! What a booted appliance's metric readings must be.
//!
//! The recorder writes the whole metric surface into the connection history as a
//! PEN-tagged Custom Block, and that block is how a counter leaves this node.
//! The whole weight of this contract rests on three things the appliance did not
//! compose — the frames the harness itself put on the wire, the geometry of the
//! disk images the harness itself created, and the ownership word the harness
//! wrote onto the medium the appliance booted from.
//!
//! # Why an outside anchor rather than a second rendering
//!
//! A second rendering of the same shards would be the cheap comparison to make,
//! and it is the one this deliberately does not: two renderings agree with each
//! other about anything that went wrong upstream of both — a slot a domain
//! published at the wrong offset reads the same on either, and the pair is
//! silent. What such a pair catches is a defect inside one renderer. What it
//! cannot catch is exactly what the three anchors below can, and those are
//! stated against something the appliance never chose.
//!
//! # The three anchors, and why each is outside the appliance
//!
//! **The wire.** The harness holds a socket on both dataplane ports and counts
//! the frames that come back, so `librefirewall_forwarded_frames_total` has a
//! number measured by something the appliance cannot reach. Against a *reading*
//! the relation can only be an inequality, and that is a real loss of sharpness
//! against a surface asked for on demand after the traffic has settled, which
//! could be held to an equality: a reading is published on a schedule and framed
//! when the recorder next runs, so the last one in a file legitimately predates
//! the last frame. Nothing restores the equality, and what keeps the inequality from
//! passing over a reading of nothing is the third anchor below: on a boot that
//! carried traffic these families must also be non-zero, and on one that carried
//! none the refusals must be.
//!
//! **The medium's own geometry.** `librefirewall_block_capacity_sectors` is a
//! device fact, and the device is a file this harness created at a size it chose.
//! Holding the slot to that exact number is what proves the slots are read at the
//! right offsets rather than merely being plausible: an off-by-one in the
//! catalogue leaves every counter still under its wire bound and never lands on
//! this number. A second rendering proves the same thing by agreeing with
//! itself; a disk the harness sized proves it against something the appliance
//! never chose.
//!
//! **This boot's own bench.** The store medium is one the harness attached and
//! the ownership word on it is one the harness wrote, so what the appliance may
//! refuse and what it may forward is decided outside it. On an unowned boot one
//! drop reason must rise and the other twenty-five must read zero; on an owned
//! one that reason must read zero and the forwarding families must not. Those
//! are what keep the inequalities above from passing over a reading of nothing.
//!
//! # Why the file's own order is not a fourth anchor
//!
//! A reading carries how many records stood ahead of its block
//! ([`Snapshot::packets_before`]), and it is tempting to read that as a lower
//! bound on `librefirewall_recording_records_total`: a ring is append-ordered,
//! so those records were on the medium before the block naming them was.
//! **The counter beside them does not follow, and the relay is why.** The
//! numbers in a reading are the management domain's read of every shard at the
//! instant *it* published into the relay; the recorder takes whatever has
//! settled there, at most one reading per pass, and skips a generation it has
//! already framed. So the counters in a block are older than the block by an
//! unbounded amount, and a reading reporting no encoded record while records
//! already stand ahead of it is a correct appliance — which is what a boot
//! produces. There is no sound relation here, and stating one fails honest runs.
//!
//! # Why several readings rather than the last
//!
//! A file carries a reading per publish, so the counters can be held to each
//! other over the length of the boot: a counter may not go backwards, and a
//! constant may carry no number but its device's. Two readings taken back to
//! back would state the first of those over milliseconds; a file states it over
//! a whole run.
//!
//! # And what a boot that changed the appliance owes
//!
//! The three anchors above are what a reading is held to on every boot. A boot
//! that **submits a document** owes more, and owes it here for the same reason:
//! the deciding domain's account of the documents it answered for, and — on the
//! boot that drives one — what the re-decision that commit armed did to the
//! conversations the appliance was already carrying.
//!
//! Those are read here rather than off a surface asked for on demand, and the
//! reason is not tidiness. **The occupancy that must fall is a
//! gauge, and a gauge is a fact about an instant.** Read twice from outside, the
//! two instants are the harness's own — the moment before it submitted and the
//! moment it happened to look afterwards — and a surface published on a schedule
//! cannot answer for either. Read out of a file split on the **forwarding
//! domain's own generation**, they become the appliance's: everything below the
//! committed number was taken while the previous policy was carrying traffic, and
//! everything at or above it after the switch. The lag that makes a reading
//! awkward to assert against stops mattering, because nothing here asks when a
//! reading was framed.

use std::time::Duration;

use lfw_metrics::{SHARDS, Series};

use crate::forward_harness::PolicyWitness;
use crate::recording_contract::Snapshot;

/// One slot's identity, as a caller names it: the shard's domain, the family,
/// and the labels that pick the series out within it.
///
/// Borrowed rather than `'static`, because a name a caller wants to reach a
/// slot by need not be fixed at compile time: a drop reason comes out of this
/// build's vocabulary and a rule id out of the document under test, and a
/// lookup that could only name a literal would stop short of exactly the series
/// a configuration decides.
#[derive(Debug)]
pub struct SeriesAt<'a> {
    pub domain: &'a str,
    pub family: &'a str,
    pub labels: &'a [(&'a str, &'a str)],
}

/// Every series of one family, wherever the catalogue puts it and whatever else
/// labels it.
///
/// Several families carry one series per pipeline, and what a recording is held
/// to is the total across them: a per-pipeline slot compared alone would pass an
/// appliance that counted one direction twice and the other never. So the shape
/// of the comparison follows the shape of the number, and a family with no slot
/// at all is `None` rather than a zero nothing distinguishes from an unlabelled
/// silence.
#[must_use]
pub fn total_of(reading: &Snapshot, family: &str, labels: &[(&str, &str)]) -> Option<u64> {
    let mut base = 0;
    let mut total = None;
    for spec in &SHARDS {
        for (at, series) in spec.series.iter().enumerate() {
            if series.metric.name == family
                && labels.iter().all(|(name, value)| {
                    series
                        .labels
                        .iter()
                        .any(|held| held.name == *name && held.value == *value)
                })
                && let Some(held) = reading.slot(base + at)
            {
                total = Some(total.unwrap_or(0_u64).saturating_add(held));
            }
        }
        base += spec.series.len();
    }
    total
}

/// How many slots one family occupies across every shard, which is the whole
/// cardinality of a family whose series the catalogue fixes.
#[must_use]
pub fn slots_of(family: &str) -> usize {
    SHARDS
        .iter()
        .flat_map(|spec| spec.series.iter())
        .filter(|series| series.metric.name == family)
        .count()
}

/// Where a named series sits in a reading.
///
/// Read out of `lfw_metrics::SHARDS` because the catalogue **is** the mapping:
/// a harness that restated four hundred positions would be restating the thing
/// under test. What the harness does not take from the appliance is how a
/// reading is *framed* — that is read by the offsets the contract page states
/// (`crate::recording_contract`), which is the half a management server writes
/// from the page rather than from this code.
///
/// # Errors
/// A name no shard declares, which is a harness naming a series that has moved.
pub fn slot_of(wanted: &SeriesAt) -> Result<usize, String> {
    let mut base = 0;
    for spec in &SHARDS {
        if spec.domain == wanted.domain {
            for (at, series) in spec.series.iter().enumerate() {
                if matches(series, wanted) {
                    return Ok(base + at);
                }
            }
        }
        base += spec.series.len();
    }
    Err(format!(
        "no series {}{:?} in the {} shard, so this contract names one the catalogue has moved",
        wanted.family, wanted.labels, wanted.domain
    ))
}

fn matches(series: &Series, wanted: &SeriesAt) -> bool {
    series.metric.name == wanted.family
        && series.labels.len() == wanted.labels.len()
        && series
            .labels
            .iter()
            .zip(wanted.labels)
            .all(|(held, (name, value))| held.name == *name && held.value == *value)
}

/// One named slot's value out of a reading.
///
/// # Errors
/// A series the catalogue has moved, or a reading too short to hold its slot.
pub fn value_of(reading: &Snapshot, wanted: &SeriesAt) -> Result<u64, String> {
    let at = slot_of(wanted)?;
    reading.slot(at).ok_or_else(|| {
        format!(
            "the reading has no slot {at}, which is where {} of the {} domain sits",
            wanted.family, wanted.domain
        )
    })
}

/// Families a reading must carry a slot of, one per subsystem this gate made
/// observable.
///
/// Deliberately not the whole catalogue — `lfw_metrics`' own tests hold that to
/// itself — but one name per shard kind, so a shard that stopped being published
/// fails here. The two families whose cardinality a configuration decides are
/// absent because a reading has no room for either: what holds those is the
/// recorded verdict on each frame (`crate::surface_contract`) and the boot's
/// configuration transcript (`crate::config_transcript`).
const REQUIRED: &[&str] = &[
    "librefirewall_policy_packets_total",
    "librefirewall_policy_bytes_total",
    FORWARDED_FRAMES,
    ROUTE_DROPS,
    "librefirewall_receive_frames_total",
    TRANSMIT_FRAMES,
    "librefirewall_input_drops_total",
    "librefirewall_invariant_faults_total",
    "librefirewall_device_faults_total",
    "librefirewall_pool_returns_refused_total",
    "librefirewall_endpoint_frames_total",
    "librefirewall_endpoint_replies_total",
    "librefirewall_tcp_segments_total",
    "librefirewall_tcp_refused_total",
    "librefirewall_http_requests_total",
    "librefirewall_http_responses_total",
    "librefirewall_console_records_total",
    "librefirewall_uart_bytes_written_total",
    "librefirewall_configuration_generation",
    "librefirewall_clock_frequency_hertz",
    "librefirewall_log_records_dropped_total",
    STORE_SIGNATURES,
];

const FORWARDED_FRAMES: &str = "librefirewall_forwarded_frames_total";
const TRANSMIT_FRAMES: &str = "librefirewall_transmit_frames_total";
const ROUTE_DROPS: &str = "librefirewall_route_drops_total";
const CLOCK_TICKS: &str = "librefirewall_clock_ticks_total";
const BLOCK_CAPACITY: &str = "librefirewall_block_capacity_sectors";

/// The store domain's signature tally, named here because it is the one series
/// whose value proves a *shard moved after `init`*.
///
/// Every other series is written once by a domain that then parks, or repeatedly
/// by one that never stops. This one is written by a domain that establishes an
/// identity, publishes, blocks, and publishes again when it is woken — so a
/// reading holding it above zero is the only evidence on this surface that the
/// second publish happens at all.
const STORE_SIGNATURES: &str = "librefirewall_store_signatures_total";

/// The two dataplane drivers, whose transmit counts are the forwarder's own
/// frames seen one hop further out.
const DATAPLANE_DRIVERS: [&str; 2] = ["nic_driver0", "nic_driver1"];

/// The two devices this harness sized itself, in the `domain` each is published
/// under — so the constants in a reading are held to the bench rather than to
/// the appliance.
const SIZED_DEVICES: [(&str, u64); 2] = [
    ("recorder", crate::data_disk::DATA_DISK_BYTES),
    ("store", crate::data_disk::STORE_DISK_BYTES),
];

/// What this boot's traffic and this boot's bench oblige the readings to hold.
#[derive(Debug)]
pub struct Demanded<'a> {
    /// How long the machine has existed, which bounds the periodic wakeup from
    /// above.
    pub booted_for: Duration,
    /// Frames the harness observed coming back on its two dataplane sockets.
    pub forwarded_frames: u64,
    /// Whether this recording's extent already held a previous boot's records
    /// going into this boot.
    ///
    /// **A recording outlives the node and a counter does not.** A resumed
    /// extent holds earlier boots' readings ahead of this boot's, and across
    /// each restart between them every counter is zero again — which is the very
    /// shape [`judge_counters_only_rise`] looks for. Nothing in a reading says
    /// which boot wrote it, and position does not separate them either, an
    /// earlier boot's last record being followed by many of its own readings. So
    /// that one judgement stands down here, and says so.
    pub resumed_medium: bool,
    /// What the probe set obliges the filter to have decided.
    pub witness: PolicyWitness,
    /// The drop-reason vocabulary this build encodes, in its own order.
    pub drop_reasons: &'a [&'a str],
    /// What a boot that **submitted a document** obliges these readings to carry.
    /// `None` on every boot that changed nothing about the appliance.
    pub submitted: Option<Submitted>,
}

/// What a boot that handed the appliance a document obliges its readings to
/// carry, and the number the whole judgement is split on.
#[derive(Clone, Copy, Debug)]
pub struct Submitted {
    /// The generation the configuration domain assigned, as it answered the
    /// submission on the wire.
    ///
    /// **This is the split.** A reading whose forwarding shard is still below it
    /// was taken before the dataplane switched, and one at or above it after — a
    /// separation made at a number the appliance chose, on the appliance's own
    /// timeline, where anything the harness derived from when it happened to look
    /// would be a separation made by the harness's polling.
    pub generation: u32,
    /// The re-decision that commit armed, on the one boot that drives it to
    /// completion. `None` where the scenario submits a document and states
    /// nothing about the conversations already running.
    pub re_decision: Option<ReDecision>,
}

/// What the harness did to work the re-decision a commit armed off, so the
/// readings can be read beside it.
#[derive(Clone, Copy, Debug)]
pub struct ReDecision {
    /// The shard of the driver whose port the wakeups were put on, so the
    /// appliance's own count of what arrived can be reported beside the harness's
    /// count of what it wrote.
    pub driver_domain: &'static str,
    /// Wakeups the harness manufactured.
    pub wakeups: usize,
}

/// What the readings say the re-decision did, for the verdict line a scenario
/// carries. The whole of it is in the evidence lines; this is the headline.
#[derive(Clone, Copy, Debug)]
pub struct ReDecided {
    /// Two-way conversations the table held before the switch.
    pub assured_before: u64,
    /// Flows the pass took back.
    pub revoked: u64,
}

/// What the comparison established, for a run log to carry.
#[derive(Debug)]
pub struct Agreement {
    pub lines: Vec<String>,
    /// What the readings said the re-decision did, where the boot drove one, so a
    /// scenario's own verdict can name it.
    pub re_decision: Option<ReDecided>,
}

impl Agreement {
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut out = String::from(
            "  the metric readings the connection history carries, held to the wire, the disk \
             and this boot's own bench:",
        );
        for line in &self.lines {
            out.push('\n');
            out.push_str(line);
        }
        out
    }
}

/// Hold every reading a recording carries to what this boot can be shown to have
/// done.
///
/// # Errors
/// A recording with no reading at all, a reading whose fingerprint or slot count
/// is not this build's, or any relation in the module header that does not hold.
pub fn judge(
    target: &str,
    snapshots: &[Snapshot],
    fingerprint: u32,
    demanded: &Demanded,
) -> Result<Agreement, String> {
    let Some(last) = snapshots.last() else {
        return Err(format!(
            "{target} holds no metric reading at all, so the recorder never framed one and the \
             management server would have nothing to store"
        ));
    };
    let declared: usize = SHARDS.iter().map(|spec| spec.series.len()).sum();
    for (at, reading) in snapshots.iter().enumerate() {
        if reading.fingerprint != fingerprint {
            return Err(format!(
                "{target} holds a reading (the {} of {}) stamped with catalogue {:#010x} and this \
                 build declares {fingerprint:#010x}, so a management server would refuse it whole",
                at + 1,
                snapshots.len(),
                reading.fingerprint
            ));
        }
        if reading.values.len() != lfw_metrics::SNAPSHOT_SLOTS || reading.values.len() != declared {
            return Err(format!(
                "{target} holds a reading of {} slots; the catalogue declares {} and the {} \
                 shards name {declared} series between them. Every shard's table is laid end to \
                 end in a reading, so a length that is neither is a domain's slots missing from it",
                reading.values.len(),
                lfw_metrics::SNAPSHOT_SLOTS,
                SHARDS.len()
            ));
        }
    }

    let mut lines = vec![format!(
        "    {target}: {} reading(s), {} slots each over {} shards, catalogue {fingerprint:#010x}",
        snapshots.len(),
        lfw_metrics::SNAPSHOT_SLOTS,
        SHARDS.len()
    )];

    for family in REQUIRED {
        if slots_of(family) == 0 {
            return Err(format!(
                "no shard names {family}, so the subsystem it belongs to reaches no reading"
            ));
        }
        if total_of(last, family, &[]).is_none() {
            return Err(format!(
                "{target}'s last reading carries no slot of {family} at all"
            ));
        }
    }
    lines.push(format!(
        "    every one of the {} families this contract names carries a slot",
        REQUIRED.len()
    ));

    lines.push(judge_capacities(target, snapshots)?);
    lines.push(judge_counters_only_rise(
        target,
        snapshots,
        demanded.resumed_medium,
    )?);
    lines.push(judge_signatures(target, last)?);
    lines.push(judge_traffic(target, last, demanded)?);
    lines.push(judge_ticks(target, snapshots, demanded.booted_for)?);
    let mut re_decision = None;
    if let Some(submitted) = demanded.submitted {
        lines.push(judge_submission(target, snapshots, submitted.generation)?);
        if let Some(driven) = submitted.re_decision {
            let (decided, line) =
                judge_re_decision(target, snapshots, submitted.generation, driven)?;
            lines.push(line);
            re_decision = Some(decided);
        }
    }
    Ok(Agreement { lines, re_decision })
}

/// The generation gauge the whole submission judgement is split on: the
/// forwarding domain's, which is the one the dataplane decides under.
const GENERATION: &str = "librefirewall_configuration_generation";

/// Where the forwarding domain's own reading of that gauge sits.
const FORWARDER: &str = "forwarder";

/// And the domain that decides on a document, which is not the one that carries
/// traffic under it.
const CONFIG: &str = "config";

const SUBMISSIONS: &str = "librefirewall_configuration_submissions_total";
const READS: &str = "librefirewall_configuration_reads_total";
const TABLE_ENTRIES: &str = "librefirewall_flow_table_entries";
const FLOW_LIFECYCLE: &str = "librefirewall_flow_lifecycle_total";
const POLICY_SWEEP: &str = "librefirewall_policy_sweep_total";
const POLICY_SWEEP_RUNNING: &str = "librefirewall_policy_sweep_running";
const RECEIVE_FRAMES: &str = "librefirewall_receive_frames_total";

/// What the deciding domain's own counters owe once a boot has submitted its
/// documents, and the reading the claim is stated over.
///
/// # Why the claim is stated over the file and not against one reading
///
/// **A reading's counters are older than the block carrying it by an unbounded
/// amount.** The management domain publishes into the relay on its own schedule
/// and the recorder frames whatever has settled there, at most one reading per
/// pass, so nothing here may assume when any reading was taken. A file also opens
/// with readings framed while the boot was still coming up, long before it had
/// submitted anything, and those carry zero as a matter of course.
///
/// So the claim is the one that needs neither: **some reading in this file saw at
/// least this much.** For a counter that only rises that is exactly the statement
/// worth making — a boot whose deciding domain ever reported two applied documents
/// applied two, whichever reading it was seen in — and it rests on no ordering, so
/// it holds on a file whose ordering clause has stood down.
///
/// Floors and not equalities for the reason any such bound is a floor here: what
/// they refuse is a node whose answers on the wire said one thing about its
/// submissions and whose own counters say another.
fn judge_submission(
    target: &str,
    snapshots: &[Snapshot],
    generation: u32,
) -> Result<String, String> {
    for (family, outcome, least) in [
        (
            SUBMISSIONS,
            Some(crate::config_submission_contract::APPLIED),
            crate::config_submission_contract::OWED_APPLIED,
        ),
        (
            SUBMISSIONS,
            Some(crate::config_submission_contract::REFUSED),
            crate::config_submission_contract::OWED_REFUSED,
        ),
        (READS, None, crate::config_submission_contract::OWED_READS),
    ] {
        let labels: &[(&str, &str)] = match outcome {
            Some(outcome) => &[("outcome", outcome)],
            None => &[],
        };
        let mut highest = None;
        for reading in snapshots {
            let held = value_of(
                reading,
                &SeriesAt {
                    domain: CONFIG,
                    family,
                    labels,
                },
            )?;
            highest = Some(highest.unwrap_or(0_u64).max(held));
        }
        let reported = highest.unwrap_or(0);
        if reported < least {
            return Err(format!(
                "no reading in {target} reports {family}{} above {reported} and at least {least} \
                 is owed. The answers on the wire said one thing about this node's submissions \
                 and the domain that decided them says another",
                outcome.map_or(String::new(), |value| format!("{{outcome={value:?}}}"))
            ));
        }
    }

    // And that the dataplane's own reading of the change reached a reading at
    // all, which is what every clause below is stated over.
    let switched = snapshots
        .iter()
        .filter_map(|reading| forwarder_generation(reading).ok())
        .max()
        .unwrap_or(0);
    if switched < generation {
        return Err(format!(
            "the configuration domain committed generation {generation} and no reading in \
             {target} has the forwarding domain above {switched}. The console said it switched, \
             so this is the same fact reaching two surfaces and only one of them carrying it"
        ));
    }
    Ok(format!(
        "    the deciding domain's own counters account for every document this boot submitted, \
         and the forwarding shard reaches generation {switched}"
    ))
}

/// What the re-decision a commit armed did, as the readings report it.
///
/// # Why the readings are split on the generation, and never on when the harness looked
///
/// The occupancy that has to fall is a gauge, and the two numbers it must be read
/// at are "before the change" and "after the pass". Reading it twice from outside
/// makes those two instants the harness's own, which is precisely what a lagging
/// surface cannot answer for. Splitting the file on the **forwarding domain's own
/// generation** makes them the appliance's: a reading below the committed number
/// was taken while the previous policy was carrying traffic, and one at or above
/// it after the switch. Nothing here has to assume when a reading was framed.
///
/// # Why the pass is known to have finished, and why the gauge is what says so
///
/// A `completed` counter alone would state the window closed one whole pass early:
/// a commit arriving mid-pass does not abandon the running pass, so a `completed`
/// can belong to a pass an earlier generation armed while the submitted document's
/// own pass is still owed. The gauge is the fact that closes it — and, split as
/// above, closes it soundly: the forwarding domain arms the pass on the very
/// wakeup it switches, so a reading that already reports the new generation *and*
/// reports no pass owed is one taken after that pass finished. The two facts are
/// in one reading because a reading is one consistent read of every shard, which
/// is what makes reading them together mean anything.
///
/// # Errors
/// The verdict, naming what the readings reported: no reading taken after the
/// switch with the pass settled, a re-decision that took back nothing, or one that
/// took back more than the single conversation the submitted document stops
/// admitting.
fn judge_re_decision(
    target: &str,
    snapshots: &[Snapshot],
    generation: u32,
    driven: ReDecision,
) -> Result<(ReDecided, String), String> {
    let mut before = None;
    let mut settled = None;
    for reading in snapshots {
        if forwarder_generation(reading)? < generation {
            let assured = assured(reading)?;
            before = Some(before.unwrap_or(0_u64).max(assured));
            continue;
        }
        if forwarder_running(reading)? == 0 {
            // The last such and not the first: after the pass the gauge stays
            // down and the generation stays up, so this is the file's own final
            // word on a table nothing is still re-deciding.
            settled = Some(reading);
        }
    }
    // The maximum below the switch, because the occupancy this is measured against
    // is the one the table actually reached: a file holds readings from before the
    // bench had opened its conversations at all, and the first of those would
    // understate what the commit had to take back.
    let Some(assured_before) = before else {
        return Err(format!(
            "no reading in {target} was taken while the forwarding domain was below generation \
             {generation}, so nothing says what the table held before the commit and a fall in \
             occupancy cannot be stated across it"
        ));
    };
    let Some(settled) = settled else {
        return Err(format!(
            "no reading in {target} has the forwarding domain at generation {generation} with \
             {POLICY_SWEEP_RUNNING} back at zero, so no reading in this file was taken after the \
             pass that commit armed had finished. The harness manufactured {} wakeup(s) to work \
             it off and a wakeup works off at least one bounded window, so this is a re-decision \
             that did not progress rather than one that is slow",
            driven.wakeups
        ));
    };

    let passes = value_of(
        settled,
        &SeriesAt {
            domain: FORWARDER,
            family: POLICY_SWEEP,
            labels: &[("outcome", "completed")],
        },
    )?;
    if passes == 0 {
        return Err(format!(
            "{target}'s settled reading has the forwarding domain at generation {generation} with \
             no pass owed and {POLICY_SWEEP}{{outcome=\"completed\"}} at zero, so the table was \
             switched and never re-decided"
        ));
    }
    let revoked = value_of(
        settled,
        &SeriesAt {
            domain: FORWARDER,
            family: FLOW_LIFECYCLE,
            labels: &[("event", "revoked")],
        },
    )?;
    if revoked != 1 {
        return Err(format!(
            "the commit took back {revoked} flow(s) and exactly one was owed: the submitted \
             document narrows one accept rule by one attribute, so of the two conversations the \
             bench opened it stops admitting one. {} would be a table flushed rather than \
             re-decided",
            if revoked == 0 {
                "None"
            } else {
                "More than one"
            }
        ));
    }
    let assured_after = assured(settled)?;
    if assured_after >= assured_before {
        return Err(format!(
            "the table held {assured_before} two-way conversation(s) in a reading taken before \
             the switch and {assured_after} in one taken after the pass had finished, so the slot \
             the revoked flow held did not come back"
        ));
    }

    // The driven port's own driver, beside the harness's count of what it wrote.
    // Nothing is asserted against it: it is what tells a pass that did not advance
    // apart from frames that never arrived, at the point where somebody reads the
    // failure.
    let received = value_of(
        settled,
        &SeriesAt {
            domain: driven.driver_domain,
            family: RECEIVE_FRAMES,
            labels: &[],
        },
    )?;
    Ok((
        ReDecided {
            assured_before,
            revoked,
        },
        format!(
            "    the commit re-decided the connection table: {assured_before} two-way \
             conversation(s) before the switch and {assured_after} after the pass, {revoked} \
             taken back over {passes} completed pass(es), worked off with {} manufactured \
             wakeup(s) the {} driver counted {received} frame(s) of",
            driven.wakeups, driven.driver_domain
        ),
    ))
}

/// The generation the forwarding shard of one reading carries.
fn forwarder_generation(reading: &Snapshot) -> Result<u32, String> {
    let held = value_of(
        reading,
        &SeriesAt {
            domain: FORWARDER,
            family: GENERATION,
            labels: &[],
        },
    )?;
    u32::try_from(held).map_err(|_| {
        format!("a reading holds {GENERATION} of the {FORWARDER} domain at {held}, which is no generation this appliance can assign")
    })
}

/// Whether a pass over the connection table is still owed, as one reading reports
/// it.
fn forwarder_running(reading: &Snapshot) -> Result<u64, String> {
    value_of(
        reading,
        &SeriesAt {
            domain: FORWARDER,
            family: POLICY_SWEEP_RUNNING,
            labels: &[],
        },
    )
}

/// How many two-way UDP conversations one reading has the table holding.
///
/// That state and no other: a conversation the harness has seen answered is in it,
/// and reading one state rather than summing them keeps the number independent of
/// the transient flows a refused packet opens and the appliance withdraws in the
/// same evaluation.
fn assured(reading: &Snapshot) -> Result<u64, String> {
    value_of(
        reading,
        &SeriesAt {
            domain: FORWARDER,
            family: TABLE_ENTRIES,
            labels: &[("state", "udp_assured")],
        },
    )
}

/// The two constants, held to the geometry of the two files this harness made.
///
/// **The sharpest assertion here, and the one that proves the offsets.** A
/// capacity is a device fact the appliance reports and does not choose, and the
/// device is a file created at a size this harness picked — so an off-by-one
/// anywhere in the catalogue puts some counter at this slot and never lands on
/// this number, while leaving every inequality below satisfied.
///
/// **Zero is the one other value a reading may carry here.** An unwritten shard
/// is every slot at zero, which is the state a domain that has done nothing is
/// in, and a file holds readings taken while the block devices were still coming
/// up — and, on a medium a previous boot wrote, readings from either side of a
/// restart. So the statement is stated in two parts, over the whole file and
/// over its end: no reading anywhere carries any *other* number, and the last one
/// carries the size. The first is what catches a slot that drifts mid-boot; the
/// second is what keeps the pair from being satisfied by a file of zeroes.
fn judge_capacities(target: &str, snapshots: &[Snapshot]) -> Result<String, String> {
    let mut sizes = Vec::new();
    for (domain, bytes) in SIZED_DEVICES {
        let sectors = bytes / lfw_blk::SECTOR_SIZE as u64;
        let at = SeriesAt {
            domain,
            family: BLOCK_CAPACITY,
            labels: &[],
        };
        for (index, reading) in snapshots.iter().enumerate() {
            let held = value_of(reading, &at)?;
            if held != sectors && held != 0 {
                return Err(format!(
                    "{target}'s reading {} of {} puts {BLOCK_CAPACITY} of the {domain} domain at \
                     {held} and this harness created that device {bytes} bytes long, which is \
                     {sectors} sectors. Zero would be a shard the domain has not published yet; \
                     any other number is this slot being read through a table that does not match \
                     the one the appliance wrote — every counter beside it would still look \
                     plausible",
                    index.saturating_add(1),
                    snapshots.len()
                ));
            }
        }
        let last = snapshots.last().ok_or("no reading")?;
        let held = value_of(last, &at)?;
        if held != sectors {
            return Err(format!(
                "{target}'s last reading puts {BLOCK_CAPACITY} of the {domain} domain at {held} \
                 and this harness created that device {sectors} sectors long. A boot leaves its \
                 device up, so the reading it ends on is the one that must carry the number — a \
                 file of zeroes here is anchored to nothing the appliance did not choose"
            ));
        }
        sizes.push(sectors.to_string());
    }
    Ok(format!(
        "    both {BLOCK_CAPACITY} slots read the sector counts of the devices this harness \
         created ({}), in the reading each file ends on and nothing else anywhere in it",
        sizes.join(" and ")
    ))
}

/// A counter only rises, over the whole file rather than over two back-to-back
/// requests.
///
/// Stated over every counter slot of every reading, which is the whole reading
/// less the gauges and the two capacity constants: a slot that went backwards is
/// either a domain that reset a counter or a reading composed out of two
/// different instants. A file states this over the length of a boot, where two
/// two readings taken back to back could state it only over the milliseconds
/// between them.
///
/// **It stands down on a resumed extent, and that is a real gap.** Such a file
/// holds earlier boots' readings ahead of this boot's, and every counter is zero
/// again across each restart — the shape this looks for. Nothing in a reading
/// says which boot wrote it; position does not separate them either, an earlier
/// boot's last record being followed by many of its own readings; and a medium
/// may have been carried more than once, so neither is the number of restarts
/// known. Excusing a fixed number of falls would be excusing the defect on
/// exactly the boots that carry the most history, so the judgement is not made
/// there at all and the run log says where it was not made.
fn judge_counters_only_rise(
    target: &str,
    snapshots: &[Snapshot],
    resumed: bool,
) -> Result<String, String> {
    if resumed {
        return Ok(String::from(
            "    counters are not held to rising in this file: it spans a restart the readings do \
             not name, and every counter is zero again across one",
        ));
    }
    let mut counters: Vec<(usize, &Series, &str)> = Vec::new();
    let mut base = 0usize;
    for spec in &SHARDS {
        for (at, series) in spec.series.iter().enumerate() {
            if series.metric.kind == lfw_metrics::Kind::Counter {
                counters.push((base.saturating_add(at), series, spec.domain));
            }
        }
        base = base.saturating_add(spec.series.len());
    }
    let mut windows = 0usize;
    for pair in snapshots.windows(2) {
        let [before, after] = pair else {
            continue;
        };
        for (at, series, domain) in &counters {
            let (Some(was), Some(now)) = (before.slot(*at), after.slot(*at)) else {
                continue;
            };
            if now < was {
                return Err(format!(
                    "{target} holds two readings where slot {at} — {} of the {domain} domain — \
                     goes from {was} to {now}. It is a counter, and a counter that goes backwards \
                     is either a domain that reset one or a reading composed out of two instants",
                    series.metric.name
                ));
            }
        }
        windows = windows.saturating_add(1);
    }
    Ok(format!(
        "    no counter goes backwards across the {windows} consecutive reading pair(s), over {} \
         counter slot(s) each",
        counters.len()
    ))
}

/// The store domain published again after `init`.
fn judge_signatures(target: &str, last: &Snapshot) -> Result<String, String> {
    let signatures = value_of(
        last,
        &SeriesAt {
            domain: "store",
            family: STORE_SIGNATURES,
            labels: &[],
        },
    )?;
    if signatures < 2 {
        return Err(format!(
            "{target}'s last reading puts {STORE_SIGNATURES} at {signatures}, and a booted \
             appliance has at least two signatures behind it — the delegation's own proof and the \
             session that ran under the delegated key. A lower value means the store domain \
             either is not answering the delegation or is not republishing its shard after it does"
        ));
    }
    Ok(format!(
        "    {STORE_SIGNATURES} reads {signatures}, so the store domain republished after `init`"
    ))
}

/// What the readings say about the traffic the harness put on the wire.
///
/// The forwarding relations are inequalities because a reading is published on a
/// schedule and the last one in a file may predate the last frame. That direction
/// is the one worth catching on its own — a reading claiming more forwarding than
/// left the appliance describes work that never happened — and the vacuous pass
/// it would otherwise permit is closed from the other side, by the bench: on a
/// boot that carried traffic each of these must also be non-zero, and on one
/// whose appliance nobody owns the refusals must be — a claim no forwarding
/// number can make.
fn judge_traffic(target: &str, last: &Snapshot, demanded: &Demanded) -> Result<String, String> {
    let observed = demanded.forwarded_frames;
    // Two series and no total, on purpose: a node that summed them itself would
    // carry one, and a domain restart would corrupt a summed total.
    let pipelines = slots_of(FORWARDED_FRAMES);
    if pipelines != 2 {
        return Err(format!(
            "the catalogue gives {FORWARDED_FRAMES} {pipelines} slot(s) and the appliance has two \
             pipelines; a node that summed them itself would carry one, which the no-total rule \
             forbids"
        ));
    }
    let forwarded = total_of(last, FORWARDED_FRAMES, &[]).ok_or_else(|| {
        format!("{FORWARDED_FRAMES} has no slot at all, so no reading accounts for forwarding")
    })?;
    if forwarded > observed {
        return Err(format!(
            "{target}'s last reading sums {FORWARDED_FRAMES} to {forwarded} and the harness \
             observed {observed} frame(s) coming back on its two dataplane sockets. Every frame \
             the forwarder forwards leaves on one of those ports and nothing else originates on \
             them, so a reading claiming more describes forwarding that never happened"
        ));
    }
    let mut transmitted = 0u64;
    for domain in DATAPLANE_DRIVERS {
        let held = value_of(
            last,
            &SeriesAt {
                domain,
                family: TRANSMIT_FRAMES,
                labels: &[],
            },
        )?;
        transmitted = transmitted.saturating_add(held);
    }
    if transmitted > observed {
        return Err(format!(
            "{target}'s last reading has the two dataplane drivers transmitting {transmitted} \
             frame(s) and the harness observed {observed}; the forwarder and its drivers count \
             the same frames one hop apart"
        ));
    }

    let unowned = total_of(last, ROUTE_DROPS, &[("reason", "unowned")])
        .ok_or_else(|| format!("{ROUTE_DROPS}{{reason=\"unowned\"}} has no slot at all"))?;
    if demanded.witness.unowned {
        // The rise says the injected frames were counted; the zeroes say nothing
        // reached any later stage, which is what "settled in front of admission"
        // means and is the stronger half.
        if unowned == 0 {
            return Err(format!(
                "this boot's appliance has no owner and the harness injected frames it therefore \
                 had to refuse, and {target}'s last reading sums \
                 {ROUTE_DROPS}{{reason=\"unowned\"}} to zero. Either the frames never reached the \
                 forwarding domain, or it forwarded them — and a firewall that carries traffic \
                 for a management plane that has not taken it is the whole of what this reason \
                 exists to prevent"
            ));
        }
        for reason in demanded.drop_reasons {
            if *reason == "unowned" {
                continue;
            }
            let counted = total_of(last, ROUTE_DROPS, &[("reason", reason)]).ok_or_else(|| {
                format!(
                    "{ROUTE_DROPS}{{reason={reason:?}}} has no slot, so a refusal under it cannot \
                     be told from one that never happened"
                )
            })?;
            if counted != 0 {
                return Err(format!(
                    "{target}'s last reading sums {ROUTE_DROPS}{{reason={reason:?}}} to {counted} \
                     on a boot whose appliance has no owner. Ownership is settled in front of \
                     admission, routing, tracking and the filter, so no frame can have reached \
                     the stage that names this reason — a count here is a stage refusing in \
                     another stage's name, or an ownership check that is not first"
                ));
            }
        }
        return Ok(format!(
            "    an unowned appliance refused {unowned} frame(s) as `unowned` and counted zero \
             under each of the other {} reason(s)",
            demanded.drop_reasons.len().saturating_sub(1)
        ));
    }

    if observed == 0 {
        return Err(String::from(
            "the harness observed no frame come back on a boot whose appliance has an owner, so \
             there is no traffic for these readings to be about",
        ));
    }
    if forwarded == 0 {
        return Err(format!(
            "the harness observed {observed} frame(s) come back and {target}'s last reading sums \
             {FORWARDED_FRAMES} to zero, so no reading in this file accounts for any of them"
        ));
    }
    if transmitted == 0 {
        return Err(format!(
            "the harness observed {observed} frame(s) come back and {target}'s last reading has \
             the two dataplane drivers transmitting none of them"
        ));
    }
    // The mirror of the unowned case: this appliance has an owner, so the
    // refusal that is about ownership must never have been reached. The latch is
    // what makes that sayable — a reader that mirrored the word could be walked
    // back to refusing mid-boot by the peer that writes it.
    if unowned != 0 {
        return Err(format!(
            "{target}'s last reading sums {ROUTE_DROPS}{{reason=\"unowned\"}} to {unowned} on a \
             boot whose appliance has an owner and which forwarded {forwarded} frame(s). The \
             forwarding domain latches the first owned reading it sees, so a refusal here is \
             either a frame decided before the domain that holds the identity had published \
             anything, or a reader that can be walked back to forwarding nothing by the peer that \
             writes the word"
        ));
    }
    Ok(format!(
        "    {FORWARDED_FRAMES} reads {forwarded} and the two drivers {transmitted}, against \
         {observed} frame(s) the harness observed on the wire; `unowned` reads zero"
    ))
}

/// The appliance's periodic wakeup, judged from the outside.
///
/// **The counter being non-zero is the load-bearing half.** Nothing in this
/// system asks the clock domain for anything — it is woken by its own timer and
/// by nothing else — so a count above zero is a wakeup that happened on time
/// rather than on traffic, which is the whole property the schedules built on it
/// depend upon. A node whose timer could not be armed reports zero for ever, and
/// says why on its console.
///
/// **The ceiling beside it is what catches a shared interrupt input**, which is
/// a fault no other surface shows: the handler counts another device's
/// interrupts as its own, every schedule runs fast by whatever that device does,
/// and nothing anywhere is in an error state. It was found exactly this way, on
/// an input that looked free and carried the platform's interval timer. The
/// count is held against the time since QEMU started — an upper bound on the
/// appliance's uptime — so it costs the run nothing and asserts only in the
/// direction where an honest appliance has no headroom at all: a periodic
/// comparator cannot fire faster than the accumulator it was armed with.
fn judge_ticks(
    target: &str,
    snapshots: &[Snapshot],
    booted_for: Duration,
) -> Result<String, String> {
    let last = snapshots.last().ok_or_else(|| {
        format!("{target} holds no reading, so nothing says whether its timer ever fired")
    })?;
    let ticks = value_of(
        last,
        &SeriesAt {
            domain: "clock",
            family: CLOCK_TICKS,
            labels: &[],
        },
    )?;
    if ticks == 0 {
        return Err(String::from(
            "the appliance reports no periodic wakeup at all, so nothing is waking the domain \
             that holds this node's schedules: its reconnection backoff, its acknowledgement \
             cadence and its upstream flush would all advance only when a frame happened to \
             arrive. The clock domain's console record says whether it could arm its timer",
        ));
    }
    let ceiling = booted_for
        .as_secs()
        .saturating_mul(pd_runtime::TICKS_PER_SECOND);
    if ticks > ceiling {
        return Err(format!(
            "the appliance reports {ticks} periodic wakeup(s) and its timer is armed for {} a \
             second, so {ceiling} is every wakeup it could have taken in the {:.1}s this machine \
             has existed — firmware and boot included. A count above that is an interrupt input \
             shared with another device, whose interrupts this appliance is taking for its own",
            pd_runtime::TICKS_PER_SECOND,
            booted_for.as_secs_f64()
        ));
    }
    Ok(format!(
        "    the periodic wakeup reports {ticks} across {} reading(s), against a ceiling of \
         {ceiling} for {:.1}s of machine lifetime at {} a second",
        snapshots.len(),
        booted_for.as_secs_f64(),
        pd_runtime::TICKS_PER_SECOND
    ))
}

#[cfg(test)]
mod tests;
