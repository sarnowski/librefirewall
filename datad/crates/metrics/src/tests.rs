use super::*;
use crate::catalog::{
    ONBOARD_ANSWERS_REFUSED, ONBOARD_BYTES, ONBOARD_CONNECTIONS, ONBOARD_OVERFLOWED,
    ONBOARD_SESSIONS_CLOSED, TCP_BYTES, TCP_CHALLENGE_ACKS, TCP_CHALLENGES_SUPPRESSED,
    TCP_CONNECTIONS, TCP_REFUSED, TCP_RESETS, TCP_RETRANSMITS, TCP_SEGMENTS, TCP_URGENT_IGNORED,
    TCP_WRITE_REFUSED,
};

/// One declared series, flattened out of the shard tables: the family it
/// belongs to, the domain whose shard carries it, and its own labels.
type Declared = (
    &'static str,
    &'static str,
    Vec<(&'static str, &'static str)>,
);

/// Every series any shard names.
fn declared() -> Vec<Declared> {
    let mut all = Vec::new();
    for spec in &SHARDS {
        for series in spec.series {
            let labels = series
                .labels
                .iter()
                .map(|label| (label.name, label.value))
                .collect();
            all.push((series.metric.name, spec.domain, labels));
        }
    }
    all
}

/// Every family is reachable from some shard, bar the two whose samples came
/// from the committed configuration. Those two are declared and carried by
/// nothing today, which the catalogue states and this test admits by name rather
/// than passing over silently.
#[test]
fn every_declared_family_has_at_least_one_series() {
    let published: Vec<&str> = declared().iter().map(|(name, _, _)| *name).collect();
    for metric in ALL_METRICS {
        if core::ptr::eq(*metric, &INTERFACE_INFO) || core::ptr::eq(*metric, &RULE_HITS) {
            // Their source was the committed configuration rather than any
            // shard, and nothing composes them now: the interface family has no
            // counter at all, and the per-rule hits sit past the forwarder's
            // named table, so no reading carries either.
            continue;
        }
        assert!(
            published.contains(&metric.name),
            "{} is declared and never published",
            metric.name
        );
    }
}

/// The transliteration rule, mechanically: nothing on this surface carries a
/// separator the console spells with `-`, and every name is a legal metric
/// identifier.
#[test]
fn every_name_and_token_follows_the_transliteration_rule() {
    fn identifier(text: &str) -> bool {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            && !text.starts_with(|c: char| c.is_ascii_digit())
    }
    for metric in ALL_METRICS {
        assert!(identifier(metric.name), "{}", metric.name);
        assert!(metric.name.starts_with("librefirewall_"), "{}", metric.name);
        match metric.kind {
            Kind::Counter => assert!(metric.name.ends_with("_total"), "{}", metric.name),
            Kind::Gauge => assert!(!metric.name.ends_with("_total"), "{}", metric.name),
        }
        assert!(!metric.help.is_empty(), "{}", metric.name);
        // A HELP line is written verbatim and no surface that carries it escapes
        // neither of the two bytes that would end or continue it: a newline ends
        // the line, and a backslash begins an escape a consumer resolves against
        // a table this renderer does not apply.
        assert!(!metric.help.contains('\n'), "{}", metric.name);
        assert!(!metric.help.contains('\\'), "{}", metric.name);
    }
    // A label *value* need not be an identifier — Prometheus admits any UTF-8
    // there — but the transliteration rule binds it anyway: one spelling of a
    // token everywhere on this surface, so `-` never appears. A leading digit is
    // the one thing a value may carry and a name may not (`pipeline="0"`,
    // `status="404"`).
    fn token(text: &str) -> bool {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }
    for (_, domain, labels) in declared() {
        assert!(identifier(domain), "{domain}");
        for (name, value) in labels {
            assert!(identifier(name), "{name}");
            assert!(token(value), "{value}");
        }
    }
}

/// Label *names* must not repeat within one series, `domain` included: a
/// duplicate key is a sample a consumer rejects outright.
#[test]
fn no_series_repeats_a_label_name() {
    for (name, _, labels) in declared() {
        let mut keys: Vec<&str> = core::iter::once("domain")
            .chain(labels.iter().map(|(key, _)| *key))
            .collect();
        let before = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), before, "{name} repeats a label name");
    }
}

/// A family's samples must all carry the same label *names*, or a consumer sees
/// one family with two shapes.
#[test]
fn a_family_keeps_one_label_shape_across_every_shard() {
    for metric in ALL_METRICS {
        let mut shape: Option<Vec<&str>> = None;
        for (name, _, labels) in declared() {
            if name != metric.name {
                continue;
            }
            let keys: Vec<&str> = labels.iter().map(|(key, _)| *key).collect();
            match &shape {
                None => shape = Some(keys),
                Some(first) => assert_eq!(first, &keys, "{} has two label shapes", metric.name),
            }
        }
    }
}

/// A family several domains carry is not always a full cross product of its
/// domains and its label values, and the difference is invisible from a name and
/// a label set: `librefirewall_pool_returns_refused_total` declares `pool`
/// values `receive` and `transmit`, and each domain carries exactly one of them.
/// An alert written against a pair that does not exist never fires, so every
/// label value that is *not* carried by every domain of its family is named in
/// the HELP text — the one sentence a reading itself carries.
#[test]
fn a_partitioned_family_names_its_partition_in_its_help() {
    let all = declared();
    for metric in ALL_METRICS {
        let family: Vec<&Declared> = all
            .iter()
            .filter(|(name, ..)| *name == metric.name)
            .collect();
        let mut domains: Vec<&str> = family.iter().map(|(_, domain, _)| *domain).collect();
        domains.sort_unstable();
        domains.dedup();
        let mut pairs: Vec<(&str, &str)> = family
            .iter()
            .flat_map(|(_, _, labels)| labels.iter().copied())
            .collect();
        pairs.sort_unstable();
        pairs.dedup();
        for (key, value) in pairs {
            let carried_by = domains
                .iter()
                .filter(|domain| {
                    family.iter().any(|(_, series_domain, labels)| {
                        series_domain == *domain && labels.contains(&(key, value))
                    })
                })
                .count();
            if carried_by == domains.len() {
                continue;
            }
            assert!(
                metric.help.contains(value),
                "{} carries {key}=\"{value}\" in {carried_by} of its {} domains \
                 and its help text does not name the partition",
                metric.name,
                domains.len()
            );
        }
    }
}

/// A shard is written and read back through the region, slot for slot: the ABI
/// two protection domains share.
#[test]
fn a_shard_round_trips_a_published_sample() {
    let shard = StatsShard::zero();
    assert_eq!(shard.sample(), [0; STATS_SLOTS]);

    let sample = ForwarderSample {
        pipelines: [
            PipelineSample {
                forwarded: 11,
                route_drops: core::array::from_fn(|position| 1 + position as u64),
                stage_drops: [21, 22, 23, 24, 25, 26, 27, 28, 29],
            },
            PipelineSample {
                forwarded: 12,
                route_drops: [31; ROUTE_DROP_REASONS.len()],
                stage_drops: [41; 9],
            },
        ],
        generation: 1,
        images_applied: 1,
        images_refused: 0,
        policy: PolicySample {
            accepted_packets: 61,
            accepted_bytes: 62,
            denied_packets: 63,
            denied_bytes: 64,
            // Distinct per position, so a per-rule block published or read at
            // the wrong offset moves a value rather than repeating one.
            rule_hits: core::array::from_fn(|position| 100 + position as u64),
        },
        flow: FlowSample {
            packets_seen: 71,
            outcomes: [72, 73, 74],
            refusals: core::array::from_fn(|position| 200 + position as u64),
            lifecycle: [81, 82, 83, 84, 85],
            entries: core::array::from_fn(|position| 300 + position as u64),
            probe_collisions: 91,
            slot_desync: 92,
        },
        sweep: PolicySweepSample {
            outcomes: [93, 94],
            running: 1,
            progress: [95, 96],
        },
        tap: TapSample {
            observed: 51,
            dropped: 52,
            refused: 53,
        },
        log: LogSample {
            dropped: 2,
            refused: 3,
        },
    };
    let values = sample.values();
    shard.publish(&values);
    let read = shard.sample();
    assert_eq!(&read[..FORWARDER_SHARD_SLOTS], &values[..]);
    assert!(read[FORWARDER_SHARD_SLOTS..].iter().all(|slot| *slot == 0));
    // The per-rule block where the forwarder writes it, position for position:
    // the one offset two independent walkers of this shard have to agree on.
    for (position, hits) in sample.policy.rule_hits.iter().enumerate() {
        assert_eq!(read[RULE_HITS_BASE + position], *hits, "rule {position}");
    }
}

/// The sample types' own arithmetic: `values()` is a permutation of the fields
/// and drops none of them.
#[test]
fn every_sample_type_fills_exactly_its_declared_slots() {
    assert_eq!(
        ForwarderSample::default().values().len(),
        FORWARDER_SHARD_SLOTS
    );
    assert_eq!(DriverSample::default().values().len(), DRIVER_SLOTS);
    assert_eq!(ManagementSample::default().values().len(), MANAGEMENT_SLOTS);
    assert_eq!(ConsoleSample::default().values().len(), CONSOLE_SLOTS);
    assert_eq!(ConfigSample::default().values().len(), CONFIG_SLOTS);
    assert_eq!(ClockSample::default().values().len(), CLOCK_SLOTS);

    // A distinct value per field, so a `values()` that wrote one field twice
    // leaves a zero behind and a swapped pair is invisible to a count but not to
    // this.
    let management = ManagementSample {
        frames: 1,
        bytes: 2,
        tcp: TcpSample {
            write_refused: 3,
            ..TcpSample::default()
        },
        onboarding: TcpSample {
            write_refused: 4,
            ..TcpSample::default()
        },
        log: LogSample {
            dropped: 0,
            refused: 5,
        },
        ..ManagementSample::default()
    };
    let values = management.values();
    assert_eq!(values[0], 1);
    assert_eq!(values[1], 2);
    assert_eq!(values[MANAGEMENT_SLOTS - 1], 5);
    assert_eq!(values.iter().filter(|value| **value != 0).count(), 5);

    // The configuration domain's, whose per-outcome block is the one set here
    // published by position: a value in the wrong slot would attribute a refusal
    // to a generation that applied.
    let config = ConfigSample {
        generation: 7,
        submissions: [11, 13, 17, 31, 37, 41],
        log: LogSample {
            dropped: 23,
            refused: 29,
        },
    };
    assert_eq!(config.values(), [7, 11, 13, 17, 31, 37, 41, 23, 29]);
    assert_eq!(config.values().len(), CONFIG_SLOTS);

    // The store domain's, which is the only shard carrying four independent
    // booleans: a `values()` that wrote one of them into another's slot would
    // report a node as owned because it had minted, as having minted because it
    // was owned, or as reset because it had minted — and that last pair is the
    // one an alert reads together.
    let store = StoreSample {
        established: true,
        minted: false,
        generation: 3,
        onboarded: true,
        reset: true,
        signatures: 43,
        sign_refusals: 47,
        capacity_sectors: 2048,
        requests: [5, 7],
        bytes: [11, 13],
        device_faults: [17, 19, 23],
        status_undecodable: 29,
        completion_unmapped: 31,
        log: LogSample {
            dropped: 37,
            refused: 41,
        },
    };
    assert_eq!(
        store.values(),
        [
            1, 0, 3, 1, 1, 43, 47, 2048, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41
        ]
    );
    assert_eq!(store.values().len(), STORE_SLOTS);
    // And a node that established nothing, so the flags are not one value read
    // four times.
    assert_eq!(StoreSample::default().values()[..5], [0, 0, 0, 0, 0]);
    assert_eq!(StoreSample::default().values().len(), STORE_SLOTS);
}

/// The table constructors, exercised at run time. They are `const fn`s the
/// tables call at build time, so nothing else ever runs them — and a
/// constructor that dropped a field would be invisible until a series rendered
/// under the wrong name.
#[test]
fn a_series_carries_the_family_and_labels_it_was_built_from() {
    static EXAMPLE: Metric = metric("librefirewall_example_total", Kind::Counter, "An example.");
    const LABELS: &[Label] = &[Label::new("reason", "example")];
    let labelled = crate::catalog::s(&EXAMPLE, LABELS);
    assert_eq!(labelled.metric.name, EXAMPLE.name);
    assert_eq!(labelled.metric.kind, Kind::Counter);
    assert_eq!(labelled.metric.help, "An example.");
    assert_eq!(labelled.labels, LABELS);

    // And the constructor at run time, not only const-evaluated into the table.
    let built = metric(EXAMPLE.name, EXAMPLE.kind, EXAMPLE.help);
    assert_eq!(built.name, EXAMPLE.name);
    assert_eq!(built.kind, EXAMPLE.kind);
    assert_eq!(built.help, EXAMPLE.help);

    let bare = crate::catalog::plain(&EXAMPLE);
    assert!(bare.labels.is_empty());
    assert_eq!(Kind::Counter.token(), "counter");
    assert_eq!(Kind::Gauge.token(), "gauge");
}

#[test]
fn the_shard_table_and_the_region_count_agree() {
    assert_eq!(SHARDS.len(), SHARD_COUNT);
    assert_eq!(SHARDS[FORWARDER_SHARD].domain, "forwarder");
    assert_eq!(SHARDS[MANAGEMENT_SHARD].domain, "management");
    let mut domains: Vec<&str> = SHARDS.iter().map(|spec| spec.domain).collect();
    domains.sort_unstable();
    domains.dedup();
    assert_eq!(
        domains.len(),
        SHARD_COUNT,
        "two shards share a domain label"
    );
}

/// `publish` is bounded by the shard rather than by its argument: a caller
/// offering more than the region holds writes what fits and nothing past it.
#[test]
fn publishing_more_values_than_the_shard_holds_writes_only_what_fits() {
    let shard = StatsShard::zero();
    let values = vec![9u64; STATS_SLOTS * 2];
    shard.publish(&values);
    assert_eq!(shard.sample(), [9; STATS_SLOTS]);
}

/// A snapshot taken through real regions relays exactly what the same values
/// relay when stated directly, and the slots it lays out are the catalogue's own
/// in shard order: the shard ABI is a round trip, and this is the path the
/// appliance takes.
#[test]
fn a_snapshot_read_through_regions_relays_what_the_same_values_do() {
    let shards: Vec<StatsShard> = (0..SHARD_COUNT).map(|_| StatsShard::zero()).collect();
    let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
    for ((index, shard), slots) in shards.iter().enumerate().zip(values.iter_mut()) {
        for (slot, value) in slots.iter_mut().enumerate() {
            *value = (index as u64 + 1) * 100 + slot as u64;
        }
        shard.publish(slots);
    }
    let mut borrowed = [&shards[0]; SHARD_COUNT];
    for (target, shard) in borrowed.iter_mut().zip(&shards) {
        *target = shard;
    }
    let relayed = Snapshot::read(borrowed).relay_values();
    assert_eq!(relayed, Snapshot::new(values).relay_values());

    // And the layout itself: a slot's position in the reading is its position in
    // `SHARDS`, which is the whole of what a reader maps a number back through.
    let mut at = 0;
    for (index, spec) in SHARDS.iter().enumerate() {
        for slot in 0..spec.series.len() {
            assert_eq!(
                relayed[at],
                (index as u64 + 1) * 100 + slot as u64,
                "shard {index} slot {slot}"
            );
            at += 1;
        }
    }
    assert_eq!(at, SNAPSHOT_SLOTS);
}

/// The family is a gauge and carries no `_total`, because the counter semantics
/// the suffix declares are statements about counters and a constant is none of
/// them.
#[test]
fn the_info_family_is_a_gauge_without_the_counter_suffix() {
    assert_eq!(INTERFACE_INFO.kind, Kind::Gauge);
    assert!(!INTERFACE_INFO.name.ends_with("_total"));
}

/// The mapping is the join key's source, so it is held to the domains the driver
/// shards publish under — the other side of the const assertion in
/// `interfaces.rs`, named here so a failure reads as a mismatch rather than as a
/// build error.
#[test]
fn each_port_maps_to_the_domain_its_driver_shard_publishes_under() {
    assert_eq!(port_domain(0), Some(SHARDS[1].domain));
    assert_eq!(port_domain(1), Some(SHARDS[2].domain));
    assert_eq!(MANAGEMENT_PORT_DOMAIN, SHARDS[3].domain);
    assert_eq!(port_domain(PORT_DOMAINS.len() as u8), None);
    assert_eq!(port_domain(u8::MAX), None);
}

/// A sample's fields land on the series that declare them, positionally.
///
/// `SERIES` and `values()` are one ABI in two lists, and nothing about the type
/// system holds them together: a series inserted in the middle of one list and a
/// field appended to the end of the other compiles, keeps
/// `SERIES.len() == MANAGEMENT_SLOTS`, and shifts every series after the
/// insertion point onto its neighbour's value. That has happened, and it was
/// caught by a booted image reporting no HTTP request having just answered one —
/// which is a very long way from the two lines that caused it.
///
/// The statement is per block rather than per field, and it is the one that
/// catches the whole defect class: fill exactly one block, and require every
/// non-zero slot to belong to a family of that block. A shift of any size lights
/// up a slot whose series is some other family's.
#[test]
fn a_filled_block_lands_only_on_the_series_that_declare_it() {
    let onboard = ManagementSample {
        onboard: OnboardSample {
            accepted: 1,
            forgotten: 2,
            received: 3,
            sent: 4,
            closed_by_peer: 5,
            closed_by_consumer: 6,
            overflowed: 7,
            refused: 8,
        },
        ..ManagementSample::default()
    };
    lands_on_its_own_series(
        &onboard,
        &[
            (&ONBOARD_CONNECTIONS, "accepted", 1),
            (&ONBOARD_CONNECTIONS, "forgotten", 2),
            (&ONBOARD_BYTES, "received", 3),
            (&ONBOARD_BYTES, "sent", 4),
            (&ONBOARD_SESSIONS_CLOSED, "peer", 5),
            (&ONBOARD_SESSIONS_CLOSED, "consumer", 6),
            (&ONBOARD_OVERFLOWED, "", 7),
            (&ONBOARD_ANSWERS_REFUSED, "", 8),
        ],
    );

    // The two transports, each filled alone. They are the same twenty-nine
    // families twice over, told apart by one label, so a block written to the
    // other one's slots would otherwise land on series that look right in every
    // way but the port they are about.
    let transport = TcpSample {
        segments_received: 1,
        segments_sent: 2,
        connections_accepted: 3,
        connections_dialled: 4,
        connections_established: 5,
        connections_closed: 6,
        connections_evicted: 7,
        connections_reaped: 8,
        connections_abandoned: 9,
        bytes_received: 10,
        bytes_sent: 11,
        bytes_retransmitted: 12,
        retransmits: 13,
        refused_malformed: 14,
        refused_bad_checksum: 15,
        refused_out_of_window: 16,
        refused_table_full: 17,
        refused_not_listening: 18,
        refused_no_connection: 19,
        refused_unacceptable_ack: 20,
        refused_no_acknowledgement: 21,
        refused_not_a_handshake: 22,
        refused_out_of_order: 23,
        urgent_ignored: 24,
        challenge_acks: 25,
        challenges_suppressed: 26,
        resets_received: 27,
        resets_sent: 28,
        write_refused: 29,
    };
    let owed: [(&Metric, &str, u64); 29] = [
        (&TCP_SEGMENTS, "received", 1),
        (&TCP_SEGMENTS, "sent", 2),
        (&TCP_CONNECTIONS, "accepted", 3),
        (&TCP_CONNECTIONS, "dialled", 4),
        (&TCP_CONNECTIONS, "established", 5),
        (&TCP_CONNECTIONS, "closed", 6),
        (&TCP_CONNECTIONS, "evicted", 7),
        (&TCP_CONNECTIONS, "reaped", 8),
        (&TCP_CONNECTIONS, "abandoned", 9),
        (&TCP_BYTES, "received", 10),
        (&TCP_BYTES, "sent", 11),
        (&TCP_BYTES, "retransmitted", 12),
        (&TCP_RETRANSMITS, "", 13),
        (&TCP_REFUSED, "malformed", 14),
        (&TCP_REFUSED, "bad_checksum", 15),
        (&TCP_REFUSED, "out_of_window", 16),
        (&TCP_REFUSED, "table_full", 17),
        (&TCP_REFUSED, "not_listening", 18),
        (&TCP_REFUSED, "no_connection", 19),
        (&TCP_REFUSED, "unacceptable_ack", 20),
        (&TCP_REFUSED, "no_acknowledgement", 21),
        (&TCP_REFUSED, "not_a_handshake", 22),
        (&TCP_REFUSED, "out_of_order", 23),
        (&TCP_URGENT_IGNORED, "", 24),
        (&TCP_CHALLENGE_ACKS, "", 25),
        (&TCP_CHALLENGES_SUPPRESSED, "", 26),
        (&TCP_RESETS, "received", 27),
        (&TCP_RESETS, "sent", 28),
        (&TCP_WRITE_REFUSED, "", 29),
    ];
    lands_on_its_own_series(
        &ManagementSample {
            tcp: transport,
            ..ManagementSample::default()
        },
        &owed,
    );
    lands_on_its_own_series(
        &ManagementSample {
            onboarding: transport,
            ..ManagementSample::default()
        },
        &owed,
    );
}

/// Every non-zero slot of `sample` belongs to `owed`, in order and by value.
///
/// The discriminating label rather than the first one: the transport families
/// carry `service` in front of the label that separates their series, so a first
/// label would read `channel` twenty-nine times and separate nothing.
fn lands_on_its_own_series(sample: &ManagementSample, owed: &[(&Metric, &str, u64)]) {
    let values = sample.values();
    let mut seen = Vec::new();
    for (slot, value) in values.iter().enumerate() {
        if *value == 0 {
            continue;
        }
        let series = ManagementSample::SERIES
            .get(slot)
            .expect("a slot the series table declares");
        let label = series
            .labels
            .iter()
            .find(|label| label.name != "service")
            .map_or("", |label| label.value);
        seen.push((series.metric.name, label, *value));
    }
    let owed: Vec<(&str, &str, u64)> = owed
        .iter()
        .map(|(metric, label, value)| (metric.name, *label, *value))
        .collect();
    assert_eq!(
        seen, owed,
        "a filled block's values landed on other families' series"
    );
}

/// The two `const fn`s the catalogue is built out of, re-run at run time: one
/// pair of labels, and the string comparison every shard's domain is held to.
/// A derivation nothing calls again is one nothing has ever executed.
#[test]
fn a_label_carries_its_pair_and_the_const_comparison_answers_both_ways() {
    let label = Label::new("domain", "forwarder");
    assert_eq!((label.name, label.value), ("domain", "forwarder"));

    assert!(crate::catalog::same("forwarder", "forwarder"));
    assert!(!crate::catalog::same("forwarder", "forwarders"));
    assert!(!crate::catalog::same("forwarder", "forwardee"));
}
