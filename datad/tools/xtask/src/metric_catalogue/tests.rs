use super::*;

/// The file is read by a program in another language, so it has to parse — and
/// the one thing this generator can get wrong is quoting. A minimal walk is
/// enough to catch an unterminated string or a missing comma, which is what a
/// hand-written writer is at risk of.
#[test]
fn the_rendered_catalogue_is_balanced_json() {
    let rendered = render();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut strings = 0usize;
    for byte in rendered.bytes() {
        match (in_string, escaped, byte) {
            (true, true, _) => escaped = false,
            (true, false, b'\\') => escaped = true,
            (true, false, b'"') => in_string = false,
            (true, false, _) => {}
            (false, _, b'"') => {
                in_string = true;
                strings += 1;
            }
            (false, _, b'{' | b'[') => depth += 1,
            (false, _, b'}' | b']') => depth -= 1,
            (false, _, _) => {}
        }
        assert!(depth >= 0, "the catalogue closes a bracket it never opened");
    }
    assert_eq!(depth, 0, "the catalogue leaves a bracket open");
    assert!(!in_string, "the catalogue leaves a string unterminated");
    assert!(
        strings > SNAPSHOT_SLOTS,
        "far too few strings for {SNAPSHOT_SLOTS} series"
    );
}

/// One entry per slot and in the snapshot's own order: the file is read
/// positionally, so an entry more or fewer would shift every series after it
/// onto another one's numbers.
#[test]
fn the_catalogue_holds_one_entry_per_slot_in_snapshot_order() {
    let rendered = render();
    assert_eq!(
        rendered.matches("\"domain\":").count(),
        SNAPSHOT_SLOTS,
        "the catalogue does not hold one entry per slot"
    );
    // The first entry is the first shard's first series, which is what makes the
    // file's order the snapshot's order rather than any other.
    let first = &SHARDS[0];
    let head = format!(
        "{{\"domain\": \"{}\", \"family\": \"{}\"",
        first.domain, first.series[0].metric.name
    );
    assert!(
        rendered.contains(&head),
        "the catalogue does not open on slot 0"
    );
}

/// The number both ends compare travels in the file, so a build whose catalogue
/// moved writes a different file — which is the whole mechanism.
#[test]
fn the_fingerprint_is_stated_and_is_this_builds() {
    assert!(render().contains(&format!("\"fingerprint\": {CATALOGUE_FINGERPRINT}")));
}

/// A quote or a backslash in a name would otherwise end the string early and
/// leave a file no parser accepts.
#[test]
fn a_name_that_could_end_its_own_string_is_escaped() {
    assert_eq!(quoted("plain"), "\"plain\"");
    assert_eq!(quoted("a\"b"), "\"a\\\"b\"");
    assert_eq!(quoted("a\\b"), "\"a\\\\b\"");
    assert_eq!(quoted("a\nb"), "\"a\\nb\"");
    assert_eq!(quoted("a\u{1}b"), "\"a\\u0001b\"");
}
