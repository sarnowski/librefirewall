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

/// One objdump line as the tool lays it out: address, raw bytes, text, tab
/// separated. The bytes are what this check reads, so a fixture that omitted
/// them would exercise nothing.
fn line(bytes: &str, instruction: &str) -> String {
    format!("  2340a3:\t{bytes} \t{instruction}\n")
}

#[test]
fn a_legacy_encoded_disassembly_carries_no_vector_encoding() {
    let text = [
        line("48 01 c8", "add    %rcx,%rax"),
        line("66 0f 38 f6 c3", "adcx   %ebx,%eax"),
        line("66 0f 38 dc c1", "aesenc %xmm1,%xmm0"),
        line("66 0f 3a 44 c1 00", "pclmullqlqdq %xmm1,%xmm0"),
    ]
    .concat();
    assert_eq!(vector_encoded(&text), None);
}

/// The three prefixes, each on an instruction that carries it, and each found.
/// `shrx` is the one this check was written for: a VEX-encoded instruction
/// naming no vector register at all, which the operand scan cannot see.
#[test]
fn every_vector_encoding_prefix_is_found_whatever_the_mnemonic() {
    for (bytes, mnemonic) in [
        ("c4 62 f3 f7 e8", "shrx"),
        ("c5 fc 57 c0", "vxorps"),
        ("62 f1 7c 48 28 c1", "vmovaps"),
    ] {
        let text = line("48 01 c8", "add    %rcx,%rax") + &line(bytes, mnemonic);
        assert_eq!(
            vector_encoded(&text),
            Some((mnemonic.to_owned(), 1)),
            "{bytes}"
        );
    }
}

/// The count is the whole backend and not the first line of it, so a reader
/// learns whether one instruction strayed in or a crate changed its mind.
#[test]
fn the_finding_names_the_first_one_and_counts_them_all() {
    let text = [
        line("c4 e2 7b f7 c1", "mulx   %rcx,%rax,%rdx"),
        line("48 01 c8", "add    %rcx,%rax"),
        line("c4 e3 fb f0 c1 05", "rorx   $0x5,%rcx,%rax"),
    ]
    .concat();
    assert_eq!(vector_encoded(&text), Some((String::from("mulx"), 2)));
}

/// A `c4` that is a byte of some other instruction rather than its first is not
/// an encoding, and reading the leading byte alone is what tells them apart.
#[test]
fn a_prefix_byte_inside_an_instruction_is_not_read_as_its_encoding() {
    let text = line("48 c7 c0 c4 c5 62 00", "mov    $0x62c5c4,%rax");
    assert_eq!(vector_encoded(&text), None);
}

/// The check is only as good as the bytes objdump is asked for, and it is asked
/// for them here rather than in a comment claiming so.
#[test]
fn the_shipped_specification_enables_no_vector_encoded_feature() {
    let root = crate::util::workspace_root().expect("the workspace root");
    let specification = std::fs::read_to_string(root.join(specification())).expect("the target");
    let enabled = enabled_features(&specification).expect("a features string");
    for vector_encoded in ["avx", "avx2", "bmi", "bmi2", "avx512f"] {
        assert!(
            !enabled.contains(vector_encoded),
            "`{vector_encoded}` is VEX- or EVEX-encoded, and the emulator this image is proved on \
             will not execute that encoding while the kernel's saved state excludes the vector \
             state"
        );
    }
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
