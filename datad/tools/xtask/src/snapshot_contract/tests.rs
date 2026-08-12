use super::*;

fn capacity() -> SeriesAt {
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
    }
}

fn whole(fill: impl Fn(usize) -> u64) -> Snapshot {
    reading(lfw_metrics::SNAPSHOT_SLOTS, fill)
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

#[test]
fn a_recording_with_no_reading_at_all_is_a_finding() {
    let error = judge("/logs.pcapng", &[], &[], lfw_metrics::CATALOGUE_FINGERPRINT)
        .expect_err("no reading");
    assert!(error.contains("no metric reading at all"), "{error}");
}

#[test]
fn a_reading_from_another_catalogue_is_refused_whole() {
    let mut foreign = whole(|_| 0);
    foreign.fingerprint = lfw_metrics::CATALOGUE_FINGERPRINT ^ 0xffff;
    let error = judge(
        "/logs.pcapng",
        &[foreign],
        &[],
        lfw_metrics::CATALOGUE_FINGERPRINT,
    )
    .expect_err("a foreign catalogue");
    assert!(error.contains("refuse it whole"), "{error}");
}

#[test]
fn a_reading_of_another_slot_count_is_refused() {
    let error = judge(
        "/logs.pcapng",
        &[reading(3, |_| 0)],
        &[],
        lfw_metrics::CATALOGUE_FINGERPRINT,
    )
    .expect_err("a short reading");
    assert!(error.contains("3 slots"), "{error}");
}

#[test]
fn a_counter_no_larger_than_the_scrape_agrees_and_one_larger_does_not() {
    let at = slot_of(&capacity()).expect("declared");
    let held = whole(|slot| if slot == at { 100 } else { 0 });

    for scraped in [100u64, 101, u64::MAX] {
        assert!(
            judge(
                "/logs.pcapng",
                std::slice::from_ref(&held),
                &[Agreed {
                    series: capacity(),
                    scraped,
                    constant: false,
                }],
                lfw_metrics::CATALOGUE_FINGERPRINT,
            )
            .is_ok(),
            "a reading of 100 against a scrape of {scraped}"
        );
    }

    let error = judge(
        "/logs.pcapng",
        std::slice::from_ref(&held),
        &[Agreed {
            series: capacity(),
            scraped: 99,
            constant: false,
        }],
        lfw_metrics::CATALOGUE_FINGERPRINT,
    )
    .expect_err("a recording claiming more than the appliance counted");
    assert!(error.contains("never happened"), "{error}");
}

/// The half that catches an off-by-one in the mapping: a constant must be equal,
/// so a slot read one position over reports another series' number and fails
/// here even though every counter would still be under its scrape.
#[test]
fn a_constant_must_be_equal_in_both_directions() {
    let at = slot_of(&capacity()).expect("declared");
    let held = whole(|slot| if slot == at { 100 } else { 0 });

    assert!(
        judge(
            "/logs.pcapng",
            std::slice::from_ref(&held),
            &[Agreed {
                series: capacity(),
                scraped: 100,
                constant: true,
            }],
            lfw_metrics::CATALOGUE_FINGERPRINT,
        )
        .is_ok()
    );
    for scraped in [99u64, 101] {
        assert!(
            judge(
                "/logs.pcapng",
                std::slice::from_ref(&held),
                &[Agreed {
                    series: capacity(),
                    scraped,
                    constant: true,
                }],
                lfw_metrics::CATALOGUE_FINGERPRINT,
            )
            .is_err(),
            "a constant of 100 was accepted against a scrape of {scraped}"
        );
    }
}

#[test]
fn the_evidence_names_every_slot_it_compared() {
    let at = slot_of(&capacity()).expect("declared");
    let held = whole(|slot| if slot == at { 7 } else { 0 });
    let agreement = judge(
        "/logs.pcapng",
        &[held],
        &[Agreed {
            series: capacity(),
            scraped: 7,
            constant: true,
        }],
        lfw_metrics::CATALOGUE_FINGERPRINT,
    )
    .expect("agreed");
    let evidence = agreement.evidence();
    assert!(evidence.contains(&format!("slot {at}")), "{evidence}");
    assert!(
        evidence.contains("librefirewall_block_capacity_sectors"),
        "{evidence}"
    );
    assert!(evidence.contains("reads 7"), "{evidence}");
}
