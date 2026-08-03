use super::*;

#[test]
fn a_fresh_set_is_zero_everywhere_and_matches_the_derived_default() {
    let counters = FlowCounters::new();
    assert_eq!(counters, FlowCounters::default());
    assert_eq!(counters.refused_total(), 0);
    assert_eq!(counters.classified_total(), 0);
}

/// The refusal total spans every refusal field and nothing else: a field added
/// without being folded in would silently leave a class of turned-away traffic
/// out of the number an operator reads.
#[test]
fn the_refusal_total_spans_every_refusal_field() {
    let mut counters = FlowCounters::new();
    counters.refused_unsupported_protocol = 1;
    counters.refused_fragment = 2;
    counters.refused_malformed = 4;
    counters.refused_invalid_flags = 8;
    counters.refused_mid_stream = 16;
    counters.refused_invalid_state = 32;
    counters.refused_out_of_window = 64;
    counters.refused_no_flow = 128;
    counters.refused_quoted_invalid = 256;
    counters.refused_unsupported_icmp = 512;
    counters.refused_table_full = 1_024;
    counters.refused_bucket_full = 2_048;
    assert_eq!(counters.refused_total(), 4_095);
    // Nothing that is not a refusal joins it.
    counters.packets_seen = 1_000;
    counters.flows_expired = 1_000;
    counters.flows_evicted = 1_000;
    counters.flows_closed = 1_000;
    counters.probe_tag_collisions = 1_000;
    counters.internal_slot_desync = 1_000;
    assert_eq!(counters.refused_total(), 4_095);
}

/// The classified total spans exactly the three outcomes that are not a refusal,
/// so the two totals partition what the table was handed.
#[test]
fn the_classified_total_spans_every_outcome_that_is_not_a_refusal() {
    let mut counters = FlowCounters::new();
    counters.flows_created = 1;
    counters.packets_established = 2;
    counters.packets_related = 4;
    assert_eq!(counters.classified_total(), 7);
    counters.refused_table_full = 8;
    assert_eq!(counters.classified_total(), 7);
}

#[test]
fn every_count_saturates_rather_than_wrapping() {
    let mut count = u64::MAX;
    FlowCounters::bump(&mut count);
    assert_eq!(count, u64::MAX);

    let mut counters = FlowCounters::new();
    counters.refused_mid_stream = u64::MAX;
    counters.refused_table_full = u64::MAX;
    assert_eq!(counters.refused_total(), u64::MAX);
    counters.flows_created = u64::MAX;
    counters.packets_established = u64::MAX;
    assert_eq!(counters.classified_total(), u64::MAX);
}

/// Every refusal kind reads its own field and no other's, so a metric
/// enumerating the vocabulary reports what `classify` actually counted. Each
/// kind is given a distinct value and every one is read back.
#[test]
fn each_refusal_kind_reads_its_own_field() {
    let mut counters = FlowCounters::new();
    counters.refused_unsupported_protocol = 1;
    counters.refused_fragment = 2;
    counters.refused_malformed = 3;
    counters.refused_invalid_flags = 4;
    counters.refused_mid_stream = 5;
    counters.refused_invalid_state = 6;
    counters.refused_out_of_window = 7;
    counters.refused_no_flow = 8;
    counters.refused_quoted_invalid = 9;
    counters.refused_unsupported_icmp = 10;
    counters.refused_table_full = 11;
    counters.refused_bucket_full = 12;
    for (position, kind) in RefusalKind::ALL.into_iter().enumerate() {
        assert_eq!(
            counters.refused(kind),
            position as u64 + 1,
            "{kind:?} reads the wrong field"
        );
    }
    // And the enumeration is the whole of the refusal total, which is the
    // property that makes the per-kind series add up to the aggregate one.
    let summed = RefusalKind::ALL
        .into_iter()
        .fold(0u64, |total, kind| total + counters.refused(kind));
    assert_eq!(summed, counters.refused_total());
}
