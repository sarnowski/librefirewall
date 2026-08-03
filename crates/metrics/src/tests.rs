use proptest::prelude::*;

use super::*;

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

/// One rendered line, split back into its parts. The renderer's output is what
/// an operator's scraper parses, so the tests parse it too rather than matching
/// substrings of it.
#[derive(Debug, PartialEq, Eq)]
struct Sample {
    name: String,
    labels: Vec<(String, String)>,
    value: u64,
}

fn parse(text: &str) -> (Vec<(String, String, String)>, Vec<Sample>) {
    let mut families = Vec::new();
    let mut samples = Vec::new();
    let mut helps: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest.split_once(' ').expect("a HELP line names a metric");
            helps.push((name.to_owned(), help.to_owned()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').expect("a TYPE line names a metric");
            let help = helps
                .iter()
                .find(|(family, _)| family == name)
                .map(|(_, help)| help.clone())
                .expect("a TYPE line follows its HELP line");
            families.push((name.to_owned(), kind.to_owned(), help));
            continue;
        }
        assert!(!line.starts_with('#'), "an unexpected comment: {line}");
        let (head, value) = line
            .rsplit_once(' ')
            .expect("a sample line carries a value");
        let value: u64 = value.parse().expect("a decimal value");
        let (name, labels) = match head.split_once('{') {
            Some((name, rest)) => {
                let inner = rest.strip_suffix('}').expect("a label set closes");
                let labels = inner
                    .split(',')
                    .map(|pair| {
                        let (key, quoted) = pair.split_once('=').expect("a label is key=value");
                        let value = quoted
                            .strip_prefix('"')
                            .and_then(|rest| rest.strip_suffix('"'))
                            .expect("a label value is quoted");
                        (key.to_owned(), value.to_owned())
                    })
                    .collect();
                (name.to_owned(), labels)
            }
            None => (head.to_owned(), Vec::new()),
        };
        samples.push(Sample {
            name,
            labels,
            value,
        });
    }
    (families, samples)
}

/// An identifier of stated text, through the check that is the only way to hold
/// one.
fn id(text: &str) -> wire::CheckedIdentifier {
    wire::CheckedIdentifier::new(text.as_bytes()).expect("the test uses the identifier alphabet")
}

/// The widest info series this renderer can be handed: a full inventory, every
/// label at its longest value.
///
/// Dataplane entries with sixteen-byte ids, because that is the wider of the two
/// roles — a management series carries the fixed shorter `management` word as its
/// `interface`. A prefix length of 255 and an all-`ff` MAC are values a *checked*
/// configuration refuses and this type accepts, which is the bound the staging
/// buffer has to survive.
fn worst_case_interfaces() -> InterfaceInventory {
    let mut inventory = InterfaceInventory::EMPTY;
    for _ in 0..MAX_INTERFACE_SERIES {
        inventory
            .push(
                InterfaceInfo::dataplane(
                    0,
                    id("abcdefghijklmnop"),
                    [255, 255, 255, 255],
                    255,
                    [0xff; 6],
                )
                .expect("port 0 has a driver"),
            )
            .expect("exactly the inventory's capacity");
    }
    assert_eq!(inventory.len(), MAX_INTERFACE_SERIES);
    inventory
}

/// A policy declaring every rule the ABI admits, each named at the full
/// identifier width — the widest per-rule block a document can produce.
fn worst_case_rules() -> RuleInventory {
    let mut inventory = RuleInventory::EMPTY;
    for _ in 0..MAX_RULE_SERIES {
        inventory
            .push(id("abcdefghijklmnop"))
            .expect("exactly the inventory's capacity");
    }
    assert_eq!(inventory.len(), MAX_RULE_SERIES);
    inventory
}

/// The snapshot the bound is stated against: every counter at `u64::MAX`, every
/// info label at its widest, and every rule the ABI admits declared.
fn worst_case() -> Snapshot {
    Snapshot::new([[u64::MAX; STATS_SLOTS]; SHARD_COUNT])
        .with_interfaces(worst_case_interfaces())
        .with_rules(worst_case_rules())
}

fn render_to_string(snapshot: &Snapshot) -> String {
    let mut out = vec![0u8; MAX_EXPOSITION_LEN];
    let len = snapshot.render(&mut out).expect("the declared bound fits");
    String::from_utf8(out[..len].to_vec()).expect("the exposition is ASCII")
}

#[test]
fn a_zeroed_snapshot_renders_every_declared_series_exactly_once() {
    let snapshot = Snapshot::new([[0; STATS_SLOTS]; SHARD_COUNT]);
    let (_, samples) = parse(&render_to_string(&snapshot));
    assert_eq!(samples.len(), declared().len());

    let mut seen: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for sample in &samples {
        let key = (sample.name.clone(), sample.labels.clone());
        assert!(!seen.contains(&key), "a duplicated series: {key:?}");
        seen.push(key);
        assert_eq!(sample.value, 0);
    }
}

/// Every series carries the `domain` of the shard it came out of, first, and
/// there is no series anywhere without one: the whole no-pre-summing decision
/// rests on a reader being able to aggregate by domain.
#[test]
fn every_series_carries_its_domains_label() {
    let snapshot = Snapshot::new([[0; STATS_SLOTS]; SHARD_COUNT]);
    let (_, samples) = parse(&render_to_string(&snapshot));
    let domains: Vec<&str> = SHARDS.iter().map(|spec| spec.domain).collect();
    for sample in &samples {
        let (key, value) = sample.labels.first().expect("at least one label");
        assert_eq!(key, "domain", "{sample:?}");
        assert!(domains.contains(&value.as_str()), "{sample:?}");
    }
}

/// The grouping the exposition format asks for: one HELP/TYPE pair per family,
/// and every sample of a family contiguous under it.
#[test]
fn each_family_is_declared_once_and_its_samples_are_contiguous() {
    let snapshot = Snapshot::new([[0; STATS_SLOTS]; SHARD_COUNT]);
    let text = render_to_string(&snapshot);
    let (families, _) = parse(&text);
    assert_eq!(families.len(), ALL_METRICS.len());

    let mut names: Vec<&str> = families.iter().map(|(name, _, _)| name.as_str()).collect();
    let declared_families: Vec<&str> = ALL_METRICS.iter().map(|metric| metric.name).collect();
    assert_eq!(names, declared_families);
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), ALL_METRICS.len(), "duplicated family names");

    // Contiguity: walking the sample lines, a family may not reappear after
    // another has begun.
    let mut order: Vec<String> = Vec::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let name = line
            .split(['{', ' '])
            .next()
            .expect("a sample line names a metric")
            .to_owned();
        if order.last() != Some(&name) {
            assert!(
                !order.contains(&name),
                "{name} reappears after another family"
            );
            order.push(name);
        }
    }
}

/// Every family is reachable from some shard, bar the one whose samples come
/// from the configuration instead. A family nothing publishes would render as a
/// HELP/TYPE pair with no samples — legal exposition, and a name an operator
/// would build an alert against that never moves.
#[test]
fn every_declared_family_has_at_least_one_series() {
    let published: Vec<&str> = declared().iter().map(|(name, _, _)| *name).collect();
    for metric in ALL_METRICS {
        if core::ptr::eq(*metric, &INTERFACE_INFO) || core::ptr::eq(*metric, &RULE_HITS) {
            // Their source is the committed configuration, and a node running
            // generation 0 has configured no interface and declared no rule — so
            // these two families legitimately carry no sample, and the tests
            // below are what hold each to carrying one when a configuration
            // names one.
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
/// separator the console spells with `-`, and every name is a legal Prometheus
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
        // A HELP line is written verbatim and the exposition format escapes
        // neither of the two bytes that would end or continue it: a newline ends
        // the line, and a backslash begins an escape a scraper resolves against
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
/// duplicate key is a sample a scraper rejects outright.
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

/// A family's samples must all carry the same label *names*, or a scraper sees
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
/// the HELP text — the one sentence a scrape itself carries.
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

/// The bound is exact enough to be useful and never short: a snapshot of
/// `u64::MAX` everywhere is the worst case, and it must fit.
#[test]
fn the_declared_bound_holds_the_worst_case_exactly() {
    let snapshot = worst_case();
    let mut out = vec![0u8; MAX_EXPOSITION_LEN];
    let len = snapshot.render(&mut out).expect("the worst case fits");
    assert_eq!(
        len, MAX_EXPOSITION_LEN,
        "the bound is the worst case, so the worst case reaches it"
    );
}

#[test]
fn a_buffer_one_byte_short_of_the_worst_case_is_refused_rather_than_truncated() {
    let snapshot = worst_case();
    let mut out = vec![0u8; MAX_EXPOSITION_LEN - 1];
    assert_eq!(
        snapshot.render(&mut out),
        Err(RenderError::OutOfSpace {
            capacity: MAX_EXPOSITION_LEN - 1
        })
    );
}

#[test]
fn an_empty_buffer_is_refused_and_writes_nothing() {
    let snapshot = Snapshot::new([[7; STATS_SLOTS]; SHARD_COUNT]);
    assert!(snapshot.render(&mut []).is_err());
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
    // The per-rule block where the renderer reads it, position for position:
    // the one offset two independent walkers of this shard have to agree on.
    for (position, hits) in sample.policy.rule_hits.iter().enumerate() {
        assert_eq!(read[RULE_HITS_BASE + position], *hits, "rule {position}");
    }
}

/// Slot order is the table's order, checked at the one place it matters: the
/// value a slot holds renders under the series that table names for it.
#[test]
fn a_published_value_renders_under_the_series_its_slot_names() {
    let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
    for ((shard, spec), slots) in SHARDS.iter().enumerate().zip(values.iter_mut()) {
        for (slot, value) in slots.iter_mut().enumerate().take(spec.series.len()) {
            // A value unique to (shard, slot), so a rendering that crossed two
            // slots or two shards cannot agree by accident.
            *value = (shard as u64 + 1) * 1_000 + slot as u64;
        }
    }
    let (_, samples) = parse(&render_to_string(&Snapshot::new(values)));
    for (shard, spec) in SHARDS.iter().enumerate() {
        for (slot, series) in spec.series.iter().enumerate() {
            let expected = (shard as u64 + 1) * 1_000 + slot as u64;
            let found = samples.iter().find(|sample| {
                sample.name == series.metric.name
                    && sample.labels.first().map(|(_, value)| value.as_str()) == Some(spec.domain)
                    && sample.labels[1..]
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .eq(series.labels.iter().map(|label| (label.name, label.value)))
            });
            assert_eq!(
                found.map(|sample| sample.value),
                Some(expected),
                "shard {shard} slot {slot}"
            );
        }
    }
}

proptest! {
    /// Arbitrary counter values and an arbitrary buffer: the renderer answers,
    /// never panics, and never writes past what it was given.
    #[test]
    fn rendering_is_total_over_arbitrary_values_and_capacities(
        seed in any::<u64>(),
        capacity in 0usize..(MAX_EXPOSITION_LEN + 64),
    ) {
        let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
        let mut state = seed | 1;
        for shard in &mut values {
            for slot in shard.iter_mut() {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *slot = state;
            }
        }
        let snapshot = Snapshot::new(values);
        let mut out = vec![0xAAu8; capacity + 8];
        let result = snapshot.render(&mut out[..capacity]);
        // The guard bytes past the slice are untouched whatever happened.
        prop_assert!(out[capacity..].iter().all(|byte| *byte == 0xAA));
        match result {
            Ok(len) => {
                prop_assert!(len <= capacity);
                prop_assert!(len <= MAX_EXPOSITION_LEN);
                let text = core::str::from_utf8(&out[..len]).expect("ASCII");
                let (families, samples) = parse(text);
                prop_assert_eq!(families.len(), ALL_METRICS.len());
                prop_assert_eq!(samples.len(), declared().len());
            }
            Err(RenderError::OutOfSpace { capacity: reported }) => {
                prop_assert_eq!(reported, capacity);
                prop_assert!(capacity < MAX_EXPOSITION_LEN);
            }
        }
    }

    /// The number formatter, against the host's own.
    #[test]
    fn every_counter_value_renders_as_its_decimal(value in any::<u64>()) {
        let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
        values[0][0] = value;
        let text = render_to_string(&Snapshot::new(values));
        let (_, samples) = parse(&text);
        let forwarded = samples
            .iter()
            .find(|sample| {
                sample.name == "librefirewall_forwarded_frames_total"
                    && sample.labels.contains(&("pipeline".to_owned(), "0".to_owned()))
                    && sample.labels.contains(&("domain".to_owned(), "forwarder".to_owned()))
            })
            .expect("pipeline 0's forwarded count");
        prop_assert_eq!(forwarded.value, value);
        let rendered = format!("}} {value}\n");
        prop_assert!(text.contains(&rendered));
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
        http: HttpSample {
            bodies_refused: 4,
            ..HttpSample::default()
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
        submissions: [11, 13, 17],
        reads: 19,
        log: LogSample {
            dropped: 23,
            refused: 29,
        },
    };
    assert_eq!(config.values(), [7, 11, 13, 17, 19, 23, 29]);
    assert_eq!(config.values().len(), CONFIG_SLOTS);
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

/// A snapshot taken through real regions renders exactly what the same values
/// render as when stated directly: the shard ABI is a round trip, and this is
/// the path the appliance takes.
#[test]
fn a_snapshot_read_through_regions_renders_what_the_same_values_do() {
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
    assert_eq!(
        render_to_string(&Snapshot::read(borrowed)),
        render_to_string(&Snapshot::new(values))
    );
}

/// The worst-case bound is computed at build time out of the same strings the
/// renderer writes, so the two are held together here rather than only through
/// the all-`u64::MAX` render above: a bound derived from a *different* string
/// would agree with the worst case by luck and drift the moment either moved.
#[test]
fn the_declared_bound_is_the_sum_of_the_lines_it_bounds() {
    let mut families = 0usize;
    for metric in ALL_METRICS {
        let header = crate::render::family_header_len(metric);
        let rendered = format!(
            "# HELP {} {}\n# TYPE {} {}\n",
            metric.name,
            metric.help,
            metric.name,
            metric.kind.token()
        );
        assert_eq!(header, rendered.len(), "{}", metric.name);
        families += header;
    }
    let mut series = 0usize;
    for spec in &SHARDS {
        for one in spec.series {
            let bound = crate::render::series_line_len(one, spec.domain);
            let mut labels = vec![format!("domain=\"{}\"", spec.domain)];
            for label in one.labels {
                labels.push(format!("{}=\"{}\"", label.name, label.value));
                assert_eq!(
                    crate::render::label_len(label.name, label.value),
                    labels.last().expect("just pushed").len()
                );
            }
            let rendered = format!("{}{{{}}} {}\n", one.metric.name, labels.join(","), u64::MAX);
            assert_eq!(bound, rendered.len(), "{}", one.metric.name);
            series += bound;
        }
    }
    let rules = MAX_RULE_SERIES * crate::render::rule_line_len();
    let widest_rule = format!(
        "{}{{domain=\"{}\",rule=\"{}\"}} {}\n",
        RULE_HITS.name,
        SHARDS[FORWARDER_SHARD].domain,
        "abcdefghijklmnop",
        u64::MAX,
    );
    assert_eq!(crate::render::rule_line_len(), widest_rule.len());

    let info = MAX_INTERFACE_SERIES * crate::render::info_line_len();
    let widest = format!(
        "{}{{domain=\"{}\",interface=\"{}\",role=\"{}\",address=\"{}\",prefix_length=\"{}\",mac=\"{}\"}} 1\n",
        INTERFACE_INFO.name,
        "nic_driver0",
        "abcdefghijklmnop",
        Role::Dataplane.token(),
        "255.255.255.255",
        255,
        "ff:ff:ff:ff:ff:ff",
    );
    assert_eq!(crate::render::info_line_len(), widest.len());

    assert_eq!(
        crate::render::exposition_bound(),
        families + series + info + rules
    );
    assert_eq!(MAX_EXPOSITION_LEN, families + series + info + rules);
}

/// The bench the info-family tests are stated against: the shipped document's
/// two dataplane interfaces and its management port.
fn shipped_interfaces() -> InterfaceInventory {
    let mut inventory = InterfaceInventory::EMPTY;
    inventory
        .push(
            InterfaceInfo::dataplane(
                0,
                id("dataplane-0"),
                [10, 0, 0, 1],
                24,
                [0x52, 0x54, 0x00, 0x12, 0x34, 0x50],
            )
            .expect("port 0 has a driver"),
        )
        .expect("capacity");
    inventory
        .push(
            InterfaceInfo::dataplane(
                1,
                id("dataplane-1"),
                [10, 0, 1, 1],
                24,
                [0x52, 0x54, 0x00, 0x12, 0x34, 0x51],
            )
            .expect("port 1 has a driver"),
        )
        .expect("capacity");
    inventory
        .push(InterfaceInfo::management(
            [10, 0, 2, 15],
            24,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x52],
        ))
        .expect("capacity");
    inventory
}

/// The exact lines a configured node emits, byte for byte. An operator writes a
/// join against these label names and values, so a rename or a reordered label
/// set is a break of the query rather than a cosmetic change.
#[test]
fn a_configured_node_renders_one_info_line_per_interface() {
    let snapshot =
        Snapshot::new([[0; STATS_SLOTS]; SHARD_COUNT]).with_interfaces(shipped_interfaces());
    let rendered = render_to_string(&snapshot);
    let lines: Vec<&str> = rendered
        .lines()
        .filter(|line| line.starts_with(INTERFACE_INFO.name))
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(
        lines,
        [
            "librefirewall_interface_info{domain=\"nic_driver0\",interface=\"dataplane-0\",\
             role=\"dataplane\",address=\"10.0.0.1\",prefix_length=\"24\",\
             mac=\"52:54:00:12:34:50\"} 1",
            "librefirewall_interface_info{domain=\"nic_driver1\",interface=\"dataplane-1\",\
             role=\"dataplane\",address=\"10.0.1.1\",prefix_length=\"24\",\
             mac=\"52:54:00:12:34:51\"} 1",
            "librefirewall_interface_info{domain=\"nic_driver2\",interface=\"management\",\
             role=\"management\",address=\"10.0.2.15\",prefix_length=\"24\",\
             mac=\"52:54:00:12:34:52\"} 1",
        ]
    );
}

/// The join is what the family exists for, so it is asserted rather than
/// described: every `domain` an info series carries is a `domain` some counter
/// series carries, in the same spelling. A value that matched nothing would leave
/// a query silently empty.
#[test]
fn every_info_series_joins_to_a_counter_series_on_domain() {
    let snapshot =
        Snapshot::new([[0; STATS_SLOTS]; SHARD_COUNT]).with_interfaces(shipped_interfaces());
    let (_, samples) = parse(&render_to_string(&snapshot));
    let info: Vec<&Sample> = samples
        .iter()
        .filter(|sample| sample.name == INTERFACE_INFO.name)
        .collect();
    assert_eq!(info.len(), 3);
    for sample in info {
        let domain = sample
            .labels
            .iter()
            .find(|(key, _)| key == "domain")
            .map(|(_, value)| value.clone())
            .expect("an info series carries a domain");
        assert!(
            samples
                .iter()
                .any(|other| other.name == "librefirewall_receive_frames_total"
                    && other
                        .labels
                        .contains(&("domain".to_owned(), domain.clone()))),
            "no NIC counter series carries domain={domain:?}, so the join matches nothing"
        );
        assert_eq!(sample.value, 1, "an info metric's value is always 1");
    }
}

/// A node that has committed no configuration reports no interface, and that is
/// the truth rather than a gap: generation 0 configures none. The family's two
/// comment lines still appear, so a scraper sees a declared family with no
/// series rather than an unknown name.
#[test]
fn an_unconfigured_node_declares_the_family_and_carries_no_series() {
    let snapshot = Snapshot::new([[0; STATS_SLOTS]; SHARD_COUNT]);
    let rendered = render_to_string(&snapshot);
    let (families, samples) = parse(&rendered);
    assert!(
        families
            .iter()
            .any(|(name, kind, _)| name == INTERFACE_INFO.name && kind == "gauge")
    );
    assert!(
        !samples
            .iter()
            .any(|sample| sample.name == INTERFACE_INFO.name)
    );
}

/// The family is a gauge and carries no `_total`, because the exposed
/// counter semantics are statements about counters and a constant is none of
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
    assert!(
        InterfaceInfo::dataplane(
            PORT_DOMAINS.len() as u8,
            id("wan"),
            [10, 0, 0, 1],
            24,
            [0x52, 0x54, 0x00, 0x00, 0x00, 0x01]
        )
        .is_none(),
        "a port with no driver has no domain to be joined on"
    );
}

/// A full inventory refuses the next entry rather than dropping it silently, and
/// a checked configuration cannot reach the refusal: it holds at most
/// `MAX_INTERFACES` interfaces and one management entry.
#[test]
fn the_inventory_refuses_one_entry_past_its_capacity() {
    let mut inventory = InterfaceInventory::EMPTY;
    assert!(inventory.is_empty());
    for _ in 0..MAX_INTERFACE_SERIES {
        inventory
            .push(InterfaceInfo::management(
                [10, 0, 2, 15],
                24,
                [0x52, 0x54, 0x00, 0x12, 0x34, 0x52],
            ))
            .expect("within capacity");
    }
    assert_eq!(inventory.len(), MAX_INTERFACE_SERIES);
    assert_eq!(
        inventory.push(InterfaceInfo::management(
            [10, 0, 2, 15],
            24,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x52]
        )),
        Err(InventoryFull)
    );
    assert_eq!(MAX_INTERFACE_SERIES, wire::MAX_INTERFACES + 1);
}

/// The shipped document's policy: two rules, the drop first because its line
/// number is its precedence.
fn shipped_rules() -> RuleInventory {
    let mut inventory = RuleInventory::EMPTY;
    inventory.push(id("probe-blocked")).expect("capacity");
    inventory.push(id("probe-forward")).expect("capacity");
    inventory
}

/// The exact lines a node running a two-rule policy emits, byte for byte, and the
/// number each of them carries: a rule's series is its own shard slot, so a block
/// read at the wrong offset reports another rule's traffic under this rule's name.
#[test]
fn a_declared_rule_renders_the_hit_count_at_its_own_position() {
    let mut values = [[0; STATS_SLOTS]; SHARD_COUNT];
    values[FORWARDER_SHARD][RULE_HITS_BASE] = 7;
    values[FORWARDER_SHARD][RULE_HITS_BASE + 1] = 11;
    // A position the document declared no rule at, which must reach no series at
    // all: a counter under no operator's name is not something to expose.
    values[FORWARDER_SHARD][RULE_HITS_BASE + 2] = 13;
    let rendered = render_to_string(&Snapshot::new(values).with_rules(shipped_rules()));
    let lines: Vec<&str> = rendered
        .lines()
        .filter(|line| line.starts_with(RULE_HITS.name))
        .collect();
    assert_eq!(
        lines,
        [
            "librefirewall_rule_hits_total{domain=\"forwarder\",rule=\"probe-blocked\"} 7",
            "librefirewall_rule_hits_total{domain=\"forwarder\",rule=\"probe-forward\"} 11",
        ]
    );
}

/// A node that has committed no configuration declares no rule, so the family
/// carries no series — the same honest emptiness the info family has under
/// generation 0, and the state a default-deny appliance forwards nothing in.
#[test]
fn an_unconfigured_node_declares_the_rule_family_and_carries_no_series() {
    let rendered = render_to_string(&Snapshot::new([[u64::MAX; STATS_SLOTS]; SHARD_COUNT]));
    let (families, samples) = parse(&rendered);
    assert!(
        families
            .iter()
            .any(|(name, kind, _)| name == RULE_HITS.name && kind == "counter")
    );
    assert!(!samples.iter().any(|sample| sample.name == RULE_HITS.name));
}

/// The join every rule series rests on: its `domain` is the domain the forwarding
/// shard publishes its own counters under, so the hit count and the drop reasons
/// that explain it aggregate together.
#[test]
fn every_rule_series_joins_to_the_forwarding_domains_counters() {
    let snapshot = Snapshot::new([[0; STATS_SLOTS]; SHARD_COUNT]).with_rules(shipped_rules());
    let (_, samples) = parse(&render_to_string(&snapshot));
    let hits: Vec<&Sample> = samples
        .iter()
        .filter(|sample| sample.name == RULE_HITS.name)
        .collect();
    assert_eq!(hits.len(), 2);
    for sample in hits {
        assert!(
            sample.labels.contains(&(
                "domain".to_owned(),
                SHARDS[FORWARDER_SHARD].domain.to_owned()
            )),
            "a rule series carries a domain no forwarding counter does: {sample:?}"
        );
    }
}

/// A full inventory refuses the next rule rather than dropping it silently, and a
/// checked configuration cannot reach the refusal: it holds at most `MAX_RULES`.
#[test]
fn the_rule_inventory_refuses_one_rule_past_its_capacity() {
    let mut inventory = RuleInventory::EMPTY;
    assert!(inventory.is_empty());
    for _ in 0..MAX_RULE_SERIES {
        inventory.push(id("r")).expect("within capacity");
    }
    assert_eq!(inventory.len(), MAX_RULE_SERIES);
    assert_eq!(inventory.push(id("r")), Err(RulesFull));
    assert_eq!(MAX_RULE_SERIES, wire::MAX_RULES);
}

proptest! {
    /// Whatever policy the renderer is handed, the exposition stays inside the
    /// declared bound and every rule line reads back as one sample carrying
    /// exactly `domain` and `rule`. The identifiers are checked ones — that is the
    /// only shape this renderer can be handed — and every counter is arbitrary.
    #[test]
    fn an_arbitrary_policy_renders_within_the_bound(
        names in prop::collection::vec(
            prop::collection::vec(
                prop_oneof![Just(b'a'), Just(b'z'), Just(b'0'), Just(b'9'), Just(b'-')],
                1..=16,
            ),
            0..=MAX_RULE_SERIES,
        ),
        counters in any::<u64>(),
    ) {
        let mut inventory = RuleInventory::EMPTY;
        for name in &names {
            inventory
                .push(wire::CheckedIdentifier::new(name).expect("within the alphabet"))
                .expect("at most the inventory's capacity");
        }
        let snapshot = Snapshot::new([[counters; STATS_SLOTS]; SHARD_COUNT])
            .with_rules(inventory)
            .with_interfaces(worst_case_interfaces());
        let mut out = vec![0u8; MAX_EXPOSITION_LEN];
        let len = snapshot.render(&mut out).expect("the declared bound holds");
        let text = String::from_utf8(out[..len].to_vec()).expect("ASCII");
        let (_, samples) = parse(&text);
        let hits: Vec<&Sample> = samples
            .iter()
            .filter(|sample| sample.name == RULE_HITS.name)
            .collect();
        prop_assert_eq!(hits.len(), names.len());
        for sample in hits {
            prop_assert_eq!(sample.value, counters);
            let mut keys: Vec<&str> = sample.labels.iter().map(|(key, _)| key.as_str()).collect();
            keys.sort_unstable();
            prop_assert_eq!(keys, ["domain", "rule"]);
        }
    }
}

proptest! {
    /// Whatever inventory the renderer is handed, the exposition stays inside the
    /// declared bound and every info line reads back as one sample with the six
    /// labels and the value 1. The identifiers are checked ones — that is the only
    /// shape this renderer can be handed — and every other field is arbitrary.
    #[test]
    fn an_arbitrary_inventory_renders_within_the_bound(
        entries in prop::collection::vec(
            (
                0u8..=3,
                prop::collection::vec(
                    prop_oneof![Just(b'a'), Just(b'z'), Just(b'0'), Just(b'9'), Just(b'-')],
                    1..=16,
                ),
                any::<[u8; 4]>(),
                any::<u8>(),
                any::<[u8; 6]>(),
                any::<bool>(),
            ),
            0..=MAX_INTERFACE_SERIES,
        ),
    ) {
        let mut inventory = InterfaceInventory::EMPTY;
        let mut expected = 0usize;
        for (port, text, address, prefix_length, mac, management) in entries {
            let identifier = wire::CheckedIdentifier::new(&text).expect("the alphabet");
            let info = if management {
                Some(InterfaceInfo::management(address, prefix_length, mac))
            } else {
                InterfaceInfo::dataplane(port, identifier, address, prefix_length, mac)
            };
            if let Some(info) = info {
                inventory.push(info).expect("bounded by the capacity");
                expected += 1;
            }
        }
        let snapshot = Snapshot::new([[u64::MAX; STATS_SLOTS]; SHARD_COUNT])
            .with_interfaces(inventory);
        let mut out = vec![0u8; MAX_EXPOSITION_LEN];
        let len = snapshot.render(&mut out).expect("the declared bound holds");
        prop_assert!(len <= MAX_EXPOSITION_LEN);
        let text = core::str::from_utf8(&out[..len]).expect("ASCII");
        let (_, samples) = parse(text);
        let info: Vec<&Sample> = samples
            .iter()
            .filter(|sample| sample.name == INTERFACE_INFO.name)
            .collect();
        prop_assert_eq!(info.len(), expected);
        for sample in info {
            prop_assert_eq!(sample.value, 1);
            let keys: Vec<&str> = sample.labels.iter().map(|(key, _)| key.as_str()).collect();
            prop_assert_eq!(
                keys,
                ["domain", "interface", "role", "address", "prefix_length", "mac"]
            );
            for (_, value) in &sample.labels {
                prop_assert!(!value.is_empty());
                prop_assert!(
                    value.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\'),
                    "a label value a scraper cannot read: {:?}", value
                );
            }
        }
    }
}

/// The exact bound, as a number rather than as a derivation.
///
/// The tests above prove the derivation is right; this is the one that makes a
/// change to it *visible*: the appliance's response staging buffer is sized by
/// this number (`lfw_ip_endpoint::http::RESPONSE_CAPACITY`), so a family added
/// here grows a memory reservation in the domain that faces the management-plane
/// attacker, and that is a number to re-state deliberately rather than to inherit.
#[test]
fn the_declared_bound_is_the_number_the_staging_buffer_is_sized_by() {
    assert_eq!(MAX_EXPOSITION_LEN, 79_943);
}
