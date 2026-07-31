//! `lfw_metrics`' exposition renderer, against arbitrary counter values in
//! arbitrary output storage.
//!
//! # Adversary
//!
//! CONCEPT §7.1's **byzantine neighbour protection domain**, and through the
//! endpoint that serves the bytes, its **management-plane attacker**. Every
//! `u64` a shard holds was stored by another domain, so the whole snapshot is a
//! peer's choice; the output length is the endpoint's, and the harness varies it
//! anyway because a renderer that only ever meets a big enough buffer is one
//! whose refusal path nothing has driven.
//!
//! # What is asserted, beyond not crashing
//!
//! * **Containment.** Nothing is written past the slice, checked with guard
//!   bytes rather than trusted: the reported length is compared *and* the bytes
//!   beyond it are.
//! * **Refusal, never truncation.** A buffer under the declared bound either
//!   answers a whole exposition or refuses; there is no third answer, and an
//!   `Ok` is always a complete document (ENG-12).
//! * **The declared bound holds.** Any snapshot at all fits
//!   [`MAX_EXPOSITION_LEN`], including the all-`u64::MAX` worst case the
//!   arbitrary values reach.
//! * **The vocabulary is closed.** Every name and every label the output carries
//!   is one the catalogue declares — so a value can never become a name, which
//!   is the one way a peer's `u64` could reach an operator's dashboard as
//!   something other than a number.
//! * **Every declared series appears exactly once**, whatever the values are.

use arbitrary::Unstructured;
use lfw_metrics::{
    ALL_METRICS, MAX_EXPOSITION_LEN, RenderError, SHARD_COUNT, SHARDS, STATS_SLOTS, Snapshot,
    StatsShard,
};

use crate::{any_u32, next_op};

/// A guard run past the caller's slice, so an overrun is caught by inspection
/// rather than by whatever it happened to corrupt.
const GUARD: usize = 64;

pub fn metrics_render_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);

    // Every slot of every shard is the peer's to choose. Where the input runs
    // out the remaining slots stay zero, which is the state of a domain that has
    // published nothing.
    let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
    'fill: for shard in &mut values {
        for slot in shard.iter_mut() {
            if next_op(&mut unstructured).is_none() {
                break 'fill;
            }
            // Two `u32`s rather than a `u64`, so a short input still reaches the
            // top of the range through the high half.
            *slot = (u64::from(any_u32(&mut unstructured)) << 32)
                | u64::from(any_u32(&mut unstructured));
        }
    }
    let snapshot = Snapshot::new(values);

    // The bound is what the appliance's own staging buffer is sized by, so it is
    // asserted first and unconditionally.
    let mut out = vec![0xAAu8; MAX_EXPOSITION_LEN + GUARD];
    let len = snapshot
        .render(&mut out[..MAX_EXPOSITION_LEN])
        .expect("the declared bound holds every snapshot");
    assert!(len <= MAX_EXPOSITION_LEN);
    assert!(
        out[MAX_EXPOSITION_LEN..].iter().all(|byte| *byte == 0xAA),
        "the renderer wrote past the slice it was given"
    );
    check(&out[..len]);

    // And an arbitrary capacity, which is what drives the refusal path.
    let capacity = (any_u32(&mut unstructured) as usize) % (MAX_EXPOSITION_LEN + 2);
    let mut small = vec![0xAAu8; capacity + GUARD];
    match snapshot.render(&mut small[..capacity]) {
        Ok(written) => {
            assert!(written <= capacity);
            assert_eq!(written, len, "two renderings of one snapshot differ");
            check(&small[..written]);
        }
        Err(RenderError::OutOfSpace { capacity: reported }) => {
            assert_eq!(reported, capacity);
            assert!(
                capacity < len,
                "a buffer that held the exposition refused it"
            );
        }
    }
    assert!(
        small[capacity..].iter().all(|byte| *byte == 0xAA),
        "the renderer wrote past the slice it was given"
    );

    // The same values through a real region, which is the path the appliance
    // takes: publish into a shard, read it back, render that.
    let shards: Vec<StatsShard> = (0..SHARD_COUNT).map(|_| StatsShard::zero()).collect();
    for (shard, slots) in shards.iter().zip(&values) {
        shard.publish(slots);
    }
    let mut borrowed = [&shards[0]; SHARD_COUNT];
    for (target, shard) in borrowed.iter_mut().zip(&shards) {
        *target = shard;
    }
    let mut region = vec![0u8; MAX_EXPOSITION_LEN];
    let through = Snapshot::read(borrowed)
        .render(&mut region)
        .expect("the declared bound holds");
    assert_eq!(
        region.get(..through),
        out.get(..len),
        "a snapshot taken through a shared region rendered differently"
    );
}

/// Read the output back and hold it to the catalogue.
fn check(rendered: &[u8]) {
    let text = core::str::from_utf8(rendered).expect("the exposition is ASCII");
    let names: Vec<&str> = ALL_METRICS.iter().map(|metric| metric.name).collect();
    let domains: Vec<&str> = SHARDS.iter().map(|spec| spec.domain).collect();

    let mut families = 0usize;
    let mut samples = 0usize;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, _) = rest.split_once(' ').expect("a HELP line names a metric");
            assert!(names.contains(&name), "an undeclared family: {name}");
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').expect("a TYPE line names a metric");
            assert!(names.contains(&name), "an undeclared family: {name}");
            assert!(
                matches!(kind, "counter" | "gauge"),
                "an unknown type: {kind}"
            );
            families += 1;
            continue;
        }
        assert!(!line.starts_with('#'), "an unexpected comment: {line}");
        samples += 1;
        let (head, value) = line.rsplit_once(' ').expect("a sample carries a value");
        value.parse::<u64>().expect("a decimal value");
        let (name, labels) = head.split_once('{').expect("a sample carries labels");
        assert!(names.contains(&name), "an undeclared name: {name}");
        let inner = labels.strip_suffix('}').expect("a label set closes");
        let mut carries_domain = false;
        for pair in inner.split(',') {
            let (key, quoted) = pair.split_once('=').expect("a label is key=value");
            let label = quoted
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .expect("a label value is quoted");
            assert!(
                declared_label(name, key, label),
                "an undeclared label on {name}: {key}={label}"
            );
            if key == "domain" {
                carries_domain = true;
                assert!(domains.contains(&label), "an undeclared domain: {label}");
            }
        }
        assert!(carries_domain, "a series with no domain label: {line}");
    }
    assert_eq!(families, ALL_METRICS.len(), "a family went unrendered");
    let declared: usize = SHARDS.iter().map(|spec| spec.series.len()).sum();
    assert_eq!(samples, declared, "a series went unrendered or was doubled");
}

/// Whether the catalogue declares this label on this family. `domain` is the
/// shard's and is checked by the caller; everything else must be a pair some
/// series of that family carries.
fn declared_label(metric: &str, key: &str, value: &str) -> bool {
    if key == "domain" {
        return true;
    }
    SHARDS.iter().any(|spec| {
        spec.series.iter().any(|series| {
            series.metric.name == metric
                && series
                    .labels
                    .iter()
                    .any(|label| label.name == key && label.value == value)
        })
    })
}
