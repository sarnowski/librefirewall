use super::*;
use crate::{Identifier, load, validate};
use proptest::prelude::*;
use std::{format, string::String, vec, vec::Vec};

/// Render into storage the bound guarantees is enough, as the appliance does.
fn rendered(model: &Model) -> String {
    let mut out = vec![0u8; MAX_DOCUMENT_BYTES];
    let len = render(model, &mut out).expect("a validated model fits the bound");
    assert_eq!(len, rendered_len(model), "the two walks disagree");
    String::from_utf8(out.get(..len).expect("in range").to_vec()).expect("ASCII")
}

/// The document the appliance ships, which every claim below is stated against.
const SHIPPED: &str = include_str!("../../../../systems/qemu-x86_64/configuration.xml");

#[test]
fn what_the_appliance_states_is_a_document_it_would_itself_accept() {
    let model = load(SHIPPED.as_bytes()).expect("the shipped document");
    let stated = rendered(&model);
    let read_back = load(stated.as_bytes()).expect("the appliance's own statement");
    assert!(
        model.has_same_content(&read_back),
        "the round trip changed the configuration:\n{stated}"
    );
}

/// The property that makes the read worth having: it is the first step of a
/// change, so what comes back must go back in.
#[test]
fn a_stated_document_states_the_same_thing_again() {
    let model = load(SHIPPED.as_bytes()).expect("the shipped document");
    let once = rendered(&model);
    let twice = rendered(&load(once.as_bytes()).expect("read back"));
    assert_eq!(once, twice, "the canonical form is not canonical");
}

/// Two documents that are one configuration state one document, which is what
/// makes the statement about the configuration rather than about the file.
#[test]
fn one_configuration_written_two_ways_states_one_document() {
    let reformatted = SHIPPED.replace("><", ">\n\n  <");
    let first = rendered(&load(SHIPPED.as_bytes()).expect("shipped"));
    let second = rendered(&load(reformatted.as_bytes()).expect("reformatted"));
    assert_eq!(first, second);
}

#[test]
fn the_statement_names_every_object_the_document_did() {
    let stated = rendered(&load(SHIPPED.as_bytes()).expect("shipped"));
    for expected in [
        "<interface id=\"dataplane-0\"",
        "<interface id=\"dataplane-1\"",
        "<neighbour id=\"endpoint-a\"",
        "<neighbour id=\"endpoint-b\"",
        "id=\"probe-blocked\"",
        "id=\"probe-forward\"",
        "<management ",
        "mac=\"52:54:00:12:34:52\"",
        "address=\"10.0.2.15\"",
        "destination-port=\"5000\"",
        "action=\"accept\"",
        "action=\"drop\"",
    ] {
        assert!(
            stated.contains(expected),
            "{expected} is missing:\n{stated}"
        );
    }
    assert!(stated.starts_with(DECLARATION));
    assert!(stated.ends_with("</configuration>\n"));
}

/// Every criterion is written out, the wildcard included: the schema refuses a
/// rule that omits one, so a statement that omitted one would be a document the
/// appliance could not read back.
#[test]
fn a_wildcard_criterion_is_written_rather_than_omitted() {
    let stated = rendered(&load(SHIPPED.as_bytes()).expect("shipped"));
    for wildcard in [
        "ingress=\"any\"",
        "egress=\"any\"",
        "source=\"any\"",
        "destination=\"any\"",
        "source-port=\"any\"",
        "icmp-type=\"any\"",
        "tracking=\"any\"",
    ] {
        assert!(
            stated.contains(wildcard),
            "{wildcard} is missing:\n{stated}"
        );
    }
}

/// A stated block is the block the model holds, not the address an operator
/// happened to write it as — which is only true because a non-canonical prefix
/// is refused rather than masked.
#[test]
fn a_stated_rule_carries_its_blocks_and_ranges_as_the_model_holds_them() {
    let document = SHIPPED.replacen(
        "source=\"any\" destination=\"any\" protocol=\"udp\"\n              source-port=\"any\" destination-port=\"5001\"",
        "source=\"10.0.0.0/24\" destination=\"10.0.1.0/24\" protocol=\"icmp\"\n              source-port=\"any\" destination-port=\"any\"",
        1,
    );
    let stated = rendered(&load(document.as_bytes()).expect("a narrower rule"));
    assert!(stated.contains("source=\"10.0.0.0/24\""), "{stated}");
    assert!(stated.contains("destination=\"10.0.1.0/24\""), "{stated}");
    assert!(stated.contains("protocol=\"icmp\""), "{stated}");
}

/// A port range written as one port comes back as one port: the model holds a
/// range whose ends are equal, and the token vocabulary is the console's.
#[test]
fn a_port_range_states_the_token_the_vocabulary_mints() {
    let one_port = SHIPPED.replacen(
        "source-port=\"any\" destination-port=\"5000\"",
        "source-port=\"1024-2048\" destination-port=\"5000-5000\"",
        1,
    );
    let stated = rendered(&load(one_port.as_bytes()).expect("a range"));
    assert!(stated.contains("source-port=\"1024-2048\""), "{stated}");
    assert!(stated.contains("destination-port=\"5000\""), "{stated}");
}

/// An empty section is written in the form an operator would have written it,
/// and the reader accepts it: the generation a node holds before its first
/// commit is not otherwise stateable.
#[test]
fn an_empty_section_is_stated_as_the_empty_element() {
    let bare = concat!(
        "<configuration><interfaces/><neighbours/><rules/>",
        "<management enabled=\"false\" mac=\"52:54:00:12:34:52\" ",
        "address=\"192.168.42.15\" prefix-length=\"24\"/>",
        "</configuration>"
    );
    let stated = rendered(&load(bare.as_bytes()).expect("an empty configuration"));
    assert!(stated.contains("<interfaces/>"), "{stated}");
    assert!(stated.contains("<neighbours/>"), "{stated}");
    assert!(stated.contains("<rules/>"), "{stated}");
    assert!(load(stated.as_bytes()).is_ok(), "{stated}");
}

/// The fail-closed configuration states no `<management>` element, because it
/// describes none — and that document is one the schema refuses, which is
/// correct and unreachable over HTTP: a node on generation 0 has no address for
/// a request to arrive at.
#[test]
fn the_fail_closed_configuration_states_what_it_is_and_no_more() {
    let stated = rendered(&Model::EMPTY);
    assert!(!stated.contains("<management"), "{stated}");
    assert!(stated.contains("<rules/>"), "{stated}");
    assert!(
        load(stated.as_bytes()).is_err(),
        "a configuration naming nothing is not a document this appliance accepts"
    );
}

#[test]
fn a_statement_that_does_not_fit_is_refused_rather_than_truncated() {
    let model = load(SHIPPED.as_bytes()).expect("shipped");
    let len = rendered_len(&model);
    let mut out = vec![0u8; len - 1];
    assert_eq!(
        render(&model, &mut out),
        Err(DocumentDoesNotFit { capacity: len - 1 })
    );
    // The refusal claims no length, which is the whole of what a caller acts
    // on: bytes may have been written on the way to discovering the shortfall,
    // and a length would be the only thing that made them a document.
    let mut exact = vec![0u8; len];
    assert_eq!(render(&model, &mut exact), Ok(len));
}

/// The widest objects the schema admits, written as *short* as it admits: one
/// line, no indentation, no declaration.
///
/// The gap between that and the canonical form is what makes the rule below
/// reachable — the appliance indents, writes a declaration, and spells
/// `protocol="6"` as `tcp`, so a document an operator could submit describes a
/// configuration whose own statement is longer than a submission may be.
mod widest {
    use std::{format, string::String};

    /// Sixteen bytes, which is [`lfw_log::MAX_IDENTIFIER_LEN`]: every id below is
    /// exactly that long, so the policy is as wide as the schema allows.
    const STEM: &str = "abcdefghijklmno";

    pub(super) fn interface(port: u8) -> String {
        format!(
            "<interface id=\"{STEM}{port}\" port=\"{port}\" enabled=\"true\" \
             mac=\"52:54:00:12:34:5{port}\" address=\"10.{port}.0.1\" prefix-length=\"24\"/>"
        )
    }

    pub(super) fn neighbour(index: usize) -> String {
        format!(
            "<neighbour id=\"nnnnnnnnnnnnnn{index:02}\" interface=\"{STEM}0\" \
             address=\"10.0.0.{}\" mac=\"52:54:00:00:00:{index:02x}\"/>",
            index + 2
        )
    }

    /// Every criterion stated at its widest: a canonical `/31` and `/30` block,
    /// two five-digit port ranges, and a protocol the vocabulary spells as a
    /// token three bytes longer than the number the document writes.
    pub(super) fn rule(index: usize) -> String {
        format!(
            "<rule id=\"rrrrrrrrrrrrr{index:03}\" ingress=\"{STEM}0\" egress=\"{STEM}1\" \
             source=\"255.255.255.254/31\" destination=\"255.255.255.252/30\" protocol=\"6\" \
             source-port=\"10000-65535\" destination-port=\"10000-65535\" icmp-type=\"any\" \
             tracking=\"opening\" action=\"accept\"/>"
        )
    }

    /// A whole document of `rules` of them, on the two ports this build has.
    pub(super) fn document(rules: usize) -> String {
        let interfaces: String = (0..crate::PORT_COUNT).map(interface).collect();
        let neighbours: String = (0..32).map(neighbour).collect();
        let policy: String = (0..rules).map(rule).collect();
        format!(
            "<configuration><interfaces>{interfaces}</interfaces>\
             <neighbours>{neighbours}</neighbours><rules>{policy}</rules>\
             <management enabled=\"true\" mac=\"52:54:00:12:34:5f\" \
             address=\"192.168.42.15\" prefix-length=\"24\"/></configuration>"
        )
    }
}

/// The rule the module header states, reached: a policy an operator could submit
/// whose canonical form is not a document they could submit back.
///
/// The two inequalities are asserted rather than assumed, so a change to the
/// renderer that made the rule unreachable fails here — an unreachable
/// validation rule is worse than none, reading as a check that is not one.
#[test]
fn a_configuration_the_appliance_could_not_state_back_is_refused() {
    let document = widest::document(232);
    assert!(
        document.len() <= MAX_DOCUMENT_BYTES,
        "the fixture is {} bytes, so it is refused for its own length rather than for \
         the rule this test is about",
        document.len()
    );
    let model = crate::parse(document.as_bytes()).expect("the reader accepts it");
    let len = rendered_len(&model);
    assert!(
        len > MAX_DOCUMENT_BYTES,
        "the canonical form is {len} bytes, so the rule this test is about is unreachable"
    );
    assert!(!fits_the_document_bound(&model));
    assert_eq!(
        validate(&model)
            .expect_err("a configuration that cannot be stated")
            .reason(),
        lfw_log::RejectReason::RenderingTooLarge
    );
    assert_eq!(
        load(document.as_bytes()).expect_err("refused").reason(),
        lfw_log::RejectReason::RenderingTooLarge
    );
    // And the object it names is the configuration itself, there being no entry
    // in it at fault.
    assert_eq!(
        match validate(&model).expect_err("refused") {
            crate::SemanticError::RenderingTooLarge { len: reported } => reported,
            other => panic!("{other:?}"),
        },
        len
    );
}

/// And the boundary from the other side: a policy of the same objects, eight
/// rules shorter, commits and states itself back. So the refusal above is a bound
/// on what can be stated rather than a ban on large policies.
#[test]
fn a_policy_just_inside_the_bound_commits_and_states_itself_back() {
    let document = widest::document(224);
    let model = load(document.as_bytes()).expect("inside the bound");
    assert_eq!(model.rule_count(), 224);
    let len = rendered_len(&model);
    assert!(len <= MAX_DOCUMENT_BYTES, "{len} bytes");
    assert!(
        len > document.len(),
        "the canonical form is the shorter of the two, so nothing is being proved"
    );
    let stated = rendered(&model);
    let again = load(stated.as_bytes()).expect("the appliance's own statement");
    assert!(model.has_same_content(&again));
}

proptest! {
    /// Rendering is total over every model the reader can produce, and what it
    /// produces is always readable again: the two together are the whole of the
    /// read surface's contract.
    #[test]
    fn every_document_the_reader_accepts_states_a_document_it_accepts(
        interfaces in 0usize..4,
        neighbours in 0usize..4,
        enabled in any::<bool>(),
    ) {
        let ifaces: String = (0..interfaces)
            .map(|index| format!(
                "<interface id=\"if-{index}\" port=\"{}\" enabled=\"{enabled}\" \
                 mac=\"52:54:00:00:00:0{index}\" address=\"10.{index}.0.1\" \
                 prefix-length=\"24\"/>",
                index % usize::from(crate::PORT_COUNT),
            ))
            .collect();
        let neigh: String = (0..neighbours.min(interfaces))
            .map(|index| format!(
                "<neighbour id=\"n-{index}\" interface=\"if-{index}\" \
                 address=\"10.{index}.0.2\" mac=\"52:54:00:00:01:0{index}\"/>"
            ))
            .collect();
        let document = format!(
            "<configuration><interfaces>{ifaces}</interfaces>\
             <neighbours>{neigh}</neighbours><rules/>\
             <management enabled=\"true\" mac=\"52:54:00:12:34:52\" \
             address=\"192.168.42.15\" prefix-length=\"24\"/></configuration>"
        );
        // A port used twice is refused, which is a fixture limit rather than a
        // property: only the documents that read are about anything here.
        if let Ok(model) = load(document.as_bytes()) {
            let stated = rendered(&model);
            let again = load(stated.as_bytes()).expect("the appliance's own statement");
            prop_assert!(model.has_same_content(&again));
        }
    }

    /// Whatever the storage, rendering either writes a whole document or claims
    /// nothing: a partial length would be a truncated policy presented as a
    /// complete one.
    #[test]
    fn rendering_into_arbitrary_storage_is_whole_or_refused(capacity in 0usize..4096) {
        let model = load(SHIPPED.as_bytes()).expect("shipped");
        let mut out = vec![0u8; capacity];
        match render(&model, &mut out) {
            Ok(len) => {
                prop_assert_eq!(len, rendered_len(&model));
                prop_assert!(len <= capacity);
            }
            Err(refused) => {
                prop_assert_eq!(refused.capacity, capacity);
                prop_assert!(capacity < rendered_len(&model));
            }
        }
    }
}

/// Every attribute name this writes is one the reader accepts, checked by name
/// rather than by a successful parse: a reader that silently skipped an unknown
/// attribute would satisfy the round trip and lose a criterion.
#[test]
fn every_attribute_written_is_one_the_reader_names() {
    let stated = rendered(&load(SHIPPED.as_bytes()).expect("shipped"));
    let mut names: Vec<&str> = Vec::new();
    for line in stated.lines() {
        for token in line.split(' ') {
            if let Some((name, _)) = token.split_once("=\"") {
                names.push(name);
            }
        }
    }
    names.sort_unstable();
    names.dedup();
    let known: Vec<&str> = Field::ALL
        .iter()
        .map(|field| field.name())
        .chain(["id", "version", "encoding"])
        .collect();
    for name in names {
        assert!(
            known.contains(&name),
            "{name} is not an attribute the reader names"
        );
    }
    assert!(
        Identifier::new(b"any").is_ok(),
        "the wildcard is renderable"
    );
}
