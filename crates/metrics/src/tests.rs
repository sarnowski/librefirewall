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

/// Every family is reachable from some shard. A family nothing publishes would
/// render as a HELP/TYPE pair with no samples — legal exposition, and a name an
/// operator would build an alert against that never moves.
#[test]
fn every_declared_family_has_at_least_one_series() {
    let published: Vec<&str> = declared().iter().map(|(name, _, _)| *name).collect();
    for metric in ALL_METRICS {
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
        assert!(!metric.help.is_empty() && !metric.help.contains('\n'));
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

/// The bound is exact enough to be useful and never short: a snapshot of
/// `u64::MAX` everywhere is the worst case, and it must fit.
#[test]
fn the_declared_bound_holds_the_worst_case_exactly() {
    let snapshot = Snapshot::new([[u64::MAX; STATS_SLOTS]; SHARD_COUNT]);
    let mut out = vec![0u8; MAX_EXPOSITION_LEN];
    let len = snapshot.render(&mut out).expect("the worst case fits");
    assert_eq!(
        len, MAX_EXPOSITION_LEN,
        "the bound is the worst case, so the worst case reaches it"
    );
}

#[test]
fn a_buffer_one_byte_short_of_the_worst_case_is_refused_rather_than_truncated() {
    let snapshot = Snapshot::new([[u64::MAX; STATS_SLOTS]; SHARD_COUNT]);
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
                route_drops: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                stage_drops: [21, 22, 23, 24, 25, 26],
            },
            PipelineSample {
                forwarded: 12,
                route_drops: [31; 11],
                stage_drops: [41; 6],
            },
        ],
        generation: 1,
        images_applied: 1,
        images_refused: 0,
        log: LogSample {
            dropped: 2,
            refused: 3,
        },
    };
    let values = sample.values();
    shard.publish(&values);
    let read = shard.sample();
    assert_eq!(&read[..FORWARDER_SLOTS], &values[..]);
    assert!(read[FORWARDER_SLOTS..].iter().all(|slot| *slot == 0));
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
    assert_eq!(ForwarderSample::default().values().len(), FORWARDER_SLOTS);
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
            expositions_refused: 4,
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
    assert_eq!(crate::render::exposition_bound(), families + series);
    assert_eq!(MAX_EXPOSITION_LEN, families + series);
}
