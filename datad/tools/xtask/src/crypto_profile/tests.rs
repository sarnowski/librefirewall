use super::*;

const SPEC: &str = r#"{ "arch": "x86_64",
  "features": "+sse,+sse2,+aes,-mmx,-avx" }"#;

fn page(features: &[&str], primitives: &[(&str, &str)]) -> String {
    let mut text = String::from("# Cryptography profile\n\n");
    text.push_str("| enabled target feature | why |\n|---|---|\n");
    for feature in features {
        text.push_str(&format!("| `{feature}` | because |\n"));
    }
    text.push_str("\n| primitive | proven against | measured |\n|---|---|---|\n");
    for (primitive, measured) in primitives {
        text.push_str(&format!(
            "| `{primitive}` | a published file | {measured} |\n"
        ));
    }
    text
}

fn every_primitive() -> Vec<(&'static str, &'static str)> {
    Primitive::ALL
        .iter()
        .map(|one| {
            let measured = if crypto_contract::measured_primitives().contains(one) {
                "yes"
            } else {
                "no"
            };
            (one.name(), measured)
        })
        .collect()
}

#[test]
fn the_enabled_features_are_read_out_of_the_specification_and_not_the_disabled_ones() {
    let enabled = enabled_features(SPEC).expect("a features string");
    assert_eq!(
        enabled,
        ["sse", "sse2", "aes"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
}

#[test]
fn a_specification_with_no_features_string_is_a_failure_and_not_an_empty_set() {
    assert!(enabled_features("{ \"arch\": \"x86_64\" }").is_none());
}

#[test]
fn a_page_that_matches_both_sides_is_accepted() {
    let text = page(&["sse", "sse2", "aes"], &every_primitive());
    let mut findings = Vec::new();
    check_primitives(&text, &mut findings);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(table_column(&text, "enabled target feature").len(), 3);
}

#[test]
fn a_primitive_the_page_omits_is_reported_by_name() {
    for skipped in Primitive::ALL {
        let kept: Vec<(&str, &str)> = every_primitive()
            .into_iter()
            .filter(|(name, _)| *name != skipped.name())
            .collect();
        let mut findings = Vec::new();
        check_primitives(&page(&[], &kept), &mut findings);
        assert!(
            findings.iter().any(|finding| finding.contains(&format!(
                "`{skipped}` is in the console's primitive vocabulary"
            ))),
            "{findings:?}"
        );
    }
}

#[test]
fn a_primitive_the_page_invents_is_reported() {
    let mut rows = every_primitive();
    rows.push(("rot-13", "no"));
    let mut findings = Vec::new();
    check_primitives(&page(&[], &rows), &mut findings);
    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("lists `rot-13` and it is in no console vocabulary")),
        "{findings:?}"
    );
}

#[test]
fn a_measured_column_that_disagrees_with_the_ceilings_is_reported_both_ways() {
    let flipped: Vec<(&str, &str)> = every_primitive()
        .into_iter()
        .map(|(name, measured)| (name, if measured == "yes" { "no" } else { "yes" }))
        .collect();
    let mut findings = Vec::new();
    check_primitives(&page(&[], &flipped), &mut findings);
    assert!(
        findings
            .iter()
            .any(|f| f.contains("does not mark it measured")),
        "{findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.contains("and no ceiling holds it")),
        "{findings:?}"
    );
}

/// The page in the tree, against the specification in the tree: this is the
/// check itself, run where a unit test can see both.
#[test]
fn the_committed_page_agrees_with_the_committed_specification() {
    let root = crate::util::workspace_root().expect("the workspace root");
    let repository = crate::util::repository_root().expect("the repository root");
    check(&root, &repository).expect("the profile page and the build agree");
}

/// And the shipped binaries, when a build has produced them. Skipped rather
/// than failed where it has not: `make test` runs before any image exists, and
/// `image` calls the same function on the ELFs it just wrote.
#[test]
fn the_built_protection_domains_carry_the_instructions_the_page_claims() {
    let root = crate::util::workspace_root().expect("the workspace root");
    let build = root.join("build/image").join(image::RELEASE_CONFIG);
    if !build.join("crypto.elf").exists() {
        return;
    }
    check_image(&build).expect("the shipped domains carry the accelerated instructions");
}
