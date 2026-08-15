use super::*;

use crate::topology::Topology;

/// The sector counts the two devices this harness creates have, derived here the
/// same way the contract derives them so a test bends the reading rather than the
/// bench.
const RECORDER_SECTORS: u64 = crate::data_disk::DATA_DISK_BYTES / lfw_blk::SECTOR_SIZE as u64;
const STORE_SECTORS: u64 = crate::data_disk::STORE_DISK_BYTES / lfw_blk::SECTOR_SIZE as u64;

/// Frames the fixture's appliance forwarded on each pipeline, and the number the
/// harness is told it saw. Equal, so the base case sits exactly on the bound and
/// a slot moved either way is a finding.
const PER_PIPELINE: u64 = 3;
const OBSERVED: u64 = PER_PIPELINE * 2;

fn capacity() -> SeriesAt<'static> {
    SeriesAt {
        domain: "recorder",
        family: "librefirewall_block_capacity_sectors",
        labels: &[],
    }
}

fn reading(slots: usize, fill: impl Fn(usize) -> u64) -> Snapshot {
    Snapshot {
        fingerprint: lfw_metrics::CATALOGUE_FINGERPRINT,
        unix_nanos: 1,
        values: (0..slots).map(fill).collect(),
        packets_before: 0,
    }
}

fn whole(fill: impl Fn(usize) -> u64) -> Snapshot {
    reading(lfw_metrics::SNAPSHOT_SLOTS, fill)
}

/// Write one named slot of a reading, so a test can bend exactly one number.
fn put(held: &mut Snapshot, domain: &str, family: &str, labels: &[(&str, &str)], value: u64) {
    let at = slot_of(&SeriesAt {
        domain,
        family,
        labels,
    })
    .expect("the catalogue declares the series this test names");
    *held
        .values
        .get_mut(at)
        .expect("a whole reading holds every slot the catalogue declares") = value;
}

/// A reading every relation in this contract holds for.
///
/// The base case each test below bends one slot of: a fixture that failed for two
/// reasons at once would let a mutation pass for the wrong one.
fn sound() -> Snapshot {
    let mut held = whole(|_| 0);
    put(&mut held, "recorder", BLOCK_CAPACITY, &[], RECORDER_SECTORS);
    put(&mut held, "store", BLOCK_CAPACITY, &[], STORE_SECTORS);
    put(&mut held, "store", STORE_SIGNATURES, &[], 2);
    put(&mut held, "clock", CLOCK_TICKS, &[], 1);
    for pipeline in ["0", "1"] {
        put(
            &mut held,
            "forwarder",
            FORWARDED_FRAMES,
            &[("pipeline", pipeline)],
            PER_PIPELINE,
        );
    }
    for domain in DATAPLANE_DRIVERS {
        put(&mut held, domain, TRANSMIT_FRAMES, &[], PER_PIPELINE);
    }
    held
}

fn topology() -> Topology {
    Topology::read(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../systems/qemu-x86_64/configuration.xml"
    )))
    .expect("the shipped document describes a bench")
}

/// What an owned boot that carried [`OBSERVED`] frames obliges, with the rules
/// read out of the shipped document exactly as a scenario reads them.
fn demanded() -> Demanded<'static> {
    Demanded {
        booted_for: Duration::from_secs(60),
        forwarded_frames: OBSERVED,
        resumed_medium: false,
        witness: PolicyWitness {
            policy: topology()
                .port_policy()
                .expect("the shipped document declares an accepting and a dropping port rule"),
            probed_the_denying_rule: true,
            probed_the_fallthrough: true,
            probed_an_established_flow: false,
            probed_mid_stream: false,
            rules: topology().rule_ids().len(),
            reconfigured: false,
            unowned: false,
            flooded_tuples: 0,
        },
        drop_reasons: &crate::surface_contract::DROP_REASONS,
    }
}

fn judged(snapshots: &[Snapshot]) -> Result<Agreement, String> {
    judge(
        "the connection history",
        snapshots,
        lfw_metrics::CATALOGUE_FINGERPRINT,
        &demanded(),
    )
}

#[test]
fn a_named_series_resolves_to_the_slot_the_catalogue_puts_it_at() {
    let at = slot_of(&capacity()).expect("the recorder shard declares it");
    // Past every shard before the recorder's, and inside the catalogue.
    assert!(at < lfw_metrics::SNAPSHOT_SLOTS);
    // And the same name in another domain is a different slot, which is what
    // makes the domain part of the identity rather than decoration.
    let store = slot_of(&SeriesAt {
        domain: "store",
        family: "librefirewall_block_capacity_sectors",
        labels: &[],
    })
    .expect("the store shard declares it too");
    assert_ne!(at, store);
}

#[test]
fn a_series_the_catalogue_does_not_declare_is_named_rather_than_guessed() {
    let error = slot_of(&SeriesAt {
        domain: "recorder",
        family: "librefirewall_no_such_family",
        labels: &[],
    })
    .expect_err("no such series");
    assert!(error.contains("librefirewall_no_such_family"), "{error}");

    let wrong_domain = slot_of(&SeriesAt {
        domain: "no_such_domain",
        family: "librefirewall_block_capacity_sectors",
        labels: &[],
    })
    .expect_err("no such shard");
    assert!(wrong_domain.contains("no_such_domain"), "{wrong_domain}");
}

/// The cardinality of a family the catalogue fixes, which is what the
/// forwarded-frame shape check reads.
#[test]
fn a_family_occupies_one_slot_per_series_the_shards_declare() {
    assert_eq!(slots_of(FORWARDED_FRAMES), 2, "one per pipeline");
    // One per NIC driver, which is the two dataplane ports and the management
    // one: a family the catalogue fixes has a slot per shard that declares it.
    assert_eq!(
        slots_of(TRANSMIT_FRAMES),
        lfw_metrics::PORT_DOMAINS.len() + 1
    );
    assert_eq!(slots_of("librefirewall_nothing_declares_this"), 0);
}

#[test]
fn a_recording_with_no_reading_at_all_is_a_finding() {
    let error = judged(&[]).expect_err("no reading");
    assert!(error.contains("no metric reading at all"), "{error}");
}

#[test]
fn a_reading_from_another_catalogue_is_refused_whole() {
    let mut foreign = sound();
    foreign.fingerprint = lfw_metrics::CATALOGUE_FINGERPRINT ^ 0xffff;
    let error = judged(&[foreign]).expect_err("a foreign catalogue");
    assert!(error.contains("refuse it whole"), "{error}");
}

/// The slot count is held to two numbers at once — the declared width and the
/// twelve shards' series summed — so a reading of the right length assembled out
/// of the wrong tables is still a finding.
#[test]
fn a_reading_of_another_slot_count_is_refused() {
    let error = judge(
        "the connection history",
        &[reading(3, |_| 0)],
        lfw_metrics::CATALOGUE_FINGERPRINT,
        &demanded(),
    )
    .expect_err("a short reading");
    assert!(error.contains("3 slots"), "{error}");
    assert!(
        error.contains(&format!("{} shards", SHARDS.len())),
        "{error}"
    );
}

#[test]
fn a_sound_reading_satisfies_every_relation_and_says_which() {
    let agreement = judged(&[sound()]).expect("a reading nothing is wrong with");
    let evidence = agreement.evidence();
    for owed in [
        "families this contract names carries a slot",
        "librefirewall_block_capacity_sectors",
        "no counter goes backwards",
        "republished after `init`",
        "the wire",
        "periodic wakeup reports",
    ] {
        assert!(evidence.contains(owed), "{owed:?} missing from {evidence}");
    }
}

/// The half that catches an off-by-one in the mapping: a capacity is the size of
/// a file this harness created, so a slot read one position over reports another
/// series' number and fails here even though every counter beside it would still
/// be under its bound.
#[test]
fn a_capacity_that_is_not_the_device_the_harness_created_is_a_finding() {
    for (domain, sectors) in [("recorder", RECORDER_SECTORS), ("store", STORE_SECTORS)] {
        for bent in [sectors.saturating_sub(1), sectors.saturating_add(1)] {
            let mut held = sound();
            put(&mut held, domain, BLOCK_CAPACITY, &[], bent);
            let error = judged(&[held]).expect_err("a capacity the device does not have");
            assert!(error.contains(domain), "{error}");
            assert!(error.contains("any other number"), "{error}");
        }

        // Zero alone is a shard nobody has written, which is what a boot's first
        // readings and a resumed medium's earlier ones legitimately carry.
        let mut unwritten = sound();
        put(&mut unwritten, domain, BLOCK_CAPACITY, &[], 0);
        judged(&[unwritten.clone(), sound()]).expect("a shard published partway through the file");

        // But a file that never reaches the device's size is anchored to nothing.
        let error = judged(&[sound(), unwritten]).expect_err("a file of zeroes at its end");
        assert!(error.contains("anchored to nothing"), "{error}");
    }
}

/// A file that spans a restart holds earlier boots' readings ahead of this
/// boot's, and every counter is zero again across each boundary — which nothing
/// in the file distinguishes from the fault this looks for.
#[test]
fn a_resumed_extent_is_not_held_to_rising_counters() {
    let mut raised = sound();
    put(
        &mut raised,
        "console",
        "librefirewall_console_records_total",
        &[("outcome", "printed")],
        9,
    );
    let agreement = judge(
        "the connection history",
        &[raised, sound()],
        lfw_metrics::CATALOGUE_FINGERPRINT,
        &Demanded {
            resumed_medium: true,
            ..demanded()
        },
    )
    .expect("a file that spans a restart");
    assert!(
        agreement.evidence().contains("spans a restart"),
        "{}",
        agreement.evidence()
    );
}

#[test]
fn a_counter_that_goes_backwards_between_two_readings_is_a_finding() {
    let mut first = sound();
    put(
        &mut first,
        "console",
        "librefirewall_console_records_total",
        &[("outcome", "printed")],
        9,
    );
    let second = sound();
    let error = judged(&[first, second]).expect_err("a counter that fell");
    assert!(error.contains("goes backwards"), "{error}");

    // And the direction that is not a finding, over the same pair reversed.
    let mut later = sound();
    put(
        &mut later,
        "console",
        "librefirewall_console_records_total",
        &[("outcome", "printed")],
        9,
    );
    judged(&[sound(), later]).expect("a counter that rose");
}

/// A gauge may fall, so the walk must not be over every slot: the configuration
/// generation is one an operator can take back.
#[test]
fn a_gauge_that_falls_between_two_readings_is_not_a_counter_finding() {
    let mut first = sound();
    put(
        &mut first,
        "config",
        "librefirewall_configuration_generation",
        &[],
        7,
    );
    judged(&[first, sound()]).expect("a gauge that fell");
}

#[test]
fn a_store_that_never_republished_after_init_is_a_finding() {
    for signatures in [0u64, 1] {
        let mut held = sound();
        put(&mut held, "store", STORE_SIGNATURES, &[], signatures);
        let error = judged(&[held]).expect_err("a store shard published once");
        assert!(error.contains("two signatures behind it"), "{error}");
    }
}

#[test]
fn a_reading_claiming_more_forwarding_than_the_wire_carried_is_a_finding() {
    let mut held = sound();
    put(
        &mut held,
        "forwarder",
        FORWARDED_FRAMES,
        &[("pipeline", "0")],
        PER_PIPELINE + 1,
    );
    let error = judged(&[held]).expect_err("forwarding that never happened");
    assert!(error.contains("never happened"), "{error}");

    let mut drivers = sound();
    put(
        &mut drivers,
        "nic_driver0",
        TRANSMIT_FRAMES,
        &[],
        OBSERVED + 1,
    );
    let error = judged(&[drivers]).expect_err("a driver past the wire");
    assert!(error.contains("one hop apart"), "{error}");
}

/// The other side of the inequality, which is what keeps it from passing
/// vacuously: an appliance that carried traffic must account for some of it.
#[test]
fn an_owned_boot_whose_reading_accounts_for_nothing_is_a_finding() {
    let mut nothing_forwarded = sound();
    for pipeline in ["0", "1"] {
        put(
            &mut nothing_forwarded,
            "forwarder",
            FORWARDED_FRAMES,
            &[("pipeline", pipeline)],
            0,
        );
    }
    let error = judged(&[nothing_forwarded]).expect_err("a reading accounting for none of it");
    assert!(error.contains("accounts for any of them"), "{error}");

    let mut nothing_transmitted = sound();
    for domain in DATAPLANE_DRIVERS {
        put(&mut nothing_transmitted, domain, TRANSMIT_FRAMES, &[], 0);
    }
    let error = judged(&[nothing_transmitted]).expect_err("drivers that moved nothing");
    assert!(error.contains("transmitting none of them"), "{error}");

    let no_wire = Demanded {
        forwarded_frames: 0,
        ..demanded()
    };
    let mut held = sound();
    for pipeline in ["0", "1"] {
        put(
            &mut held,
            "forwarder",
            FORWARDED_FRAMES,
            &[("pipeline", pipeline)],
            0,
        );
    }
    for domain in DATAPLANE_DRIVERS {
        put(&mut held, domain, TRANSMIT_FRAMES, &[], 0);
    }
    let error = judge(
        "the connection history",
        &[held],
        lfw_metrics::CATALOGUE_FINGERPRINT,
        &no_wire,
    )
    .expect_err("two zeroes prove nothing");
    assert!(error.contains("no traffic for these readings"), "{error}");
}

/// An appliance nobody has taken settles every frame in front of admission, so
/// one reason rises and the other twenty-five stay at zero. The zeroes are the
/// stronger half: they say no later stage was reached at all.
#[test]
fn an_unowned_boot_refuses_under_one_reason_and_no_other() {
    let unowned = |forwarded_frames| Demanded {
        forwarded_frames,
        witness: PolicyWitness {
            unowned: true,
            ..demanded().witness
        },
        ..demanded()
    };
    let judge_unowned = |held: Snapshot| {
        judge(
            "the connection history",
            &[held],
            lfw_metrics::CATALOGUE_FINGERPRINT,
            &unowned(0),
        )
    };

    let mut refused = whole(|_| 0);
    put(
        &mut refused,
        "recorder",
        BLOCK_CAPACITY,
        &[],
        RECORDER_SECTORS,
    );
    put(&mut refused, "store", BLOCK_CAPACITY, &[], STORE_SECTORS);
    put(&mut refused, "store", STORE_SIGNATURES, &[], 2);
    put(&mut refused, "clock", CLOCK_TICKS, &[], 1);
    put(
        &mut refused,
        "forwarder",
        ROUTE_DROPS,
        &[("pipeline", "0"), ("reason", "unowned")],
        4,
    );
    let agreement = judge_unowned(refused.clone()).expect("an appliance that refused everything");
    assert!(
        agreement.evidence().contains("no owner") || agreement.evidence().contains("unowned"),
        "{}",
        agreement.evidence()
    );

    // A frame that reached a later stage, which is what the zeroes forbid.
    let mut reached = refused.clone();
    put(
        &mut reached,
        "forwarder",
        ROUTE_DROPS,
        &[("pipeline", "1"), ("reason", "no_route")],
        1,
    );
    let error = judge_unowned(reached).expect_err("a stage refusing in another stage's name");
    assert!(error.contains("no_route"), "{error}");

    // And nothing refused at all, on a boot whose frames had to be refused.
    let mut silent = refused;
    put(
        &mut silent,
        "forwarder",
        ROUTE_DROPS,
        &[("pipeline", "0"), ("reason", "unowned")],
        0,
    );
    let error = judge_unowned(silent).expect_err("frames that reached nothing");
    assert!(error.contains("has not taken it"), "{error}");
}

/// The mirror: an appliance that has an owner may never refuse in ownership's
/// name, the forwarding domain latching the first owned reading it sees.
#[test]
fn an_owned_boot_that_refused_for_ownership_is_a_finding() {
    let mut held = sound();
    put(
        &mut held,
        "forwarder",
        ROUTE_DROPS,
        &[("pipeline", "0"), ("reason", "unowned")],
        1,
    );
    let error = judged(&[held]).expect_err("a refusal an owned appliance cannot reach");
    assert!(error.contains("latches the first owned reading"), "{error}");
}

#[test]
fn a_timer_that_never_fired_and_one_that_fired_faster_than_it_was_armed() {
    let mut silent = sound();
    put(&mut silent, "clock", CLOCK_TICKS, &[], 0);
    let error = judged(&[silent]).expect_err("a timer that was never armed");
    assert!(error.contains("no periodic wakeup at all"), "{error}");

    let mut fast = sound();
    let ceiling = Duration::from_secs(60)
        .as_secs()
        .saturating_mul(pd_runtime::TICKS_PER_SECOND);
    put(&mut fast, "clock", CLOCK_TICKS, &[], ceiling + 1);
    let error = judged(&[fast]).expect_err("more wakeups than the machine has existed for");
    assert!(error.contains("shared with another device"), "{error}");
}

#[test]
fn a_family_that_spans_pipelines_is_summed_rather_than_read_at_one_slot() {
    // The fault a per-slot read would pass: one pipeline counting twice and the
    // other never leaves either slot plausible and only the total wrong. The
    // wire count a family is held to is the whole appliance's, so the reading it
    // is compared against has to be the whole family's too.
    // The family is labelled by pipeline *and* reason, so one reason alone
    // still spans every pipeline — which is the case a slot lookup cannot even
    // name, its match being on the whole label set.
    let reading = whole(|_| 3);

    let one_pipeline = total_of(
        &reading,
        "librefirewall_route_drops_total",
        &[("pipeline", "0"), ("reason", "no_route")],
    )
    .expect("the forwarder shard declares it");
    let every_pipeline = total_of(
        &reading,
        "librefirewall_route_drops_total",
        &[("reason", "no_route")],
    )
    .expect("the forwarder shard declares it");

    assert_eq!(one_pipeline, 3, "one series was filled with three");
    assert!(
        every_pipeline > one_pipeline,
        "the reason spans more than one pipeline, so its total is past any one of \
         them: {every_pipeline} against {one_pipeline}"
    );
    assert!(
        every_pipeline.is_multiple_of(3),
        "every slot was filled with three, so the total is three per series: {every_pipeline}"
    );
}

#[test]
fn a_family_no_shard_declares_is_absent_rather_than_zero() {
    // A zero would be indistinguishable from a counter that has not moved, and
    // the caller's question is whether the catalogue still carries the family
    // this contract names.
    assert_eq!(
        total_of(&whole(|_| 1), "librefirewall_nothing_declares_this", &[]),
        None
    );
}

/// A reading too short to hold a named slot is a finding for whoever asked
/// rather than a panic in a harness.
#[test]
fn a_reading_too_short_for_a_named_slot_names_it() {
    let error = value_of(&reading(1, |_| 0), &capacity()).expect_err("no such slot");
    assert!(error.contains("recorder"), "{error}");
}
