//! The one document shape this crate admits, bound to the model.
//!
//! The schema is closed in both directions: an element or an attribute the
//! grammar below does not name is refused rather than skipped, and one it names
//! and the document omits is refused rather than defaulted. Both directions
//! matter for the same reason — `enabled` misspelled as `enable` is an
//! interface an operator believes is up, and there is no second channel through
//! which they would find out otherwise.
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <configuration>
//!   <interfaces>
//!     <interface id="wan" port="0" enabled="true"
//!                mac="52:54:00:12:34:50" address="10.0.0.1" prefix-length="24"/>
//!   </interfaces>
//!   <neighbours>
//!     <neighbour id="gateway-a" interface="wan"
//!                address="10.0.0.2" mac="52:54:00:00:00:0a"/>
//!   </neighbours>
//!   <rules>
//!     <rule id="allow-web" ingress="wan" egress="any" source="any"
//!           destination="10.0.1.0/24" protocol="tcp" source-port="any"
//!           destination-port="443" icmp-type="any" action="accept"/>
//!   </rules>
//!   <management mac="52:54:00:12:34:52" address="10.0.2.15"
//!               prefix-length="24" enabled="true" gateway="10.0.2.2"/>
//! </configuration>
//! ```
//!
//! `<management>` is a sibling of `<interfaces>`, not an entry inside it: that
//! port is not a dataplane one — no `port` number, not in the router's set.
//! Required like the other three; `enabled="false"` means no address.
//!
//! It is also the one element with a `gateway`, and the asymmetry is deliberate.
//! A gateway is read only by the outbound dial of the port that holds it, and
//! this is the only port that dials; a gateway on an `<interface>` would be a
//! value nothing in this build could read. A port that reaches only its own
//! link writes `gateway="none"` — the absence is a word, on `any`'s terms and
//! for `enabled`'s reason.
//!
//! `<rules>` is required and may be empty, and an empty one is not the absence
//! of a policy: the appliance is default-deny, so `<rules/>` forwards nothing.
//! Its children are ordered — first match wins — which is the one place in this
//! schema where where a line was written changes what the document means.
//!
//! What lives here is the *document's* shape: which elements the root admits,
//! that each appears once, that a section's children are all of one kind, and
//! that nothing follows the root. Which attributes an object carries is the
//! object's own business and is declared with it, in [`crate::entity`], so an
//! object added to the schema adds a section here and a declaration there
//! rather than a reader.

use crate::{
    entity::{InterfaceEntry, ManagementEntry, NeighbourEntry, RuleEntry, unknown_attribute},
    model::Model,
    xml::{DocumentError, DocumentFault, Element, Event, Reader},
};

/// Read a document into a model, checking nothing about what the values mean.
///
/// Shape only, deliberately: nothing here reads what a value *means*, so no
/// syntax rule can come to rest on an address, and no byte offset can reach a
/// decision that has to be a function of the model alone.
///
/// # Errors
/// [`DocumentError`], naming the fault and the byte it was decided at.
pub fn parse(document: &[u8]) -> Result<Model, DocumentError> {
    let mut reader = Reader::new(document)?;
    let mut model = Model::EMPTY;

    let root = match next(&mut reader)? {
        Some(Event::Start(element)) => element,
        _ => return Err(DocumentError::at(DocumentFault::MissingRootElement, 0)),
    };
    if root.name != b"configuration" {
        return Err(unknown_element(&root));
    }
    reject_attributes(&root)?;

    let mut interfaces_read = false;
    let mut neighbours_read = false;
    let mut rules_read = false;
    let mut management_read = false;
    loop {
        match next(&mut reader)? {
            Some(Event::Start(section)) => {
                if section.name == ManagementEntry::ELEMENT {
                    if management_read {
                        return Err(duplicate_element(&section));
                    }
                    management_read = true;
                    let entry = ManagementEntry::read(&section)?;
                    model.set_management(entry).map_err(|_| DocumentError {
                        fault: DocumentFault::CapacityExceeded,
                        offset: section.offset,
                    })?;
                    expect_empty(&mut reader)?;
                    continue;
                }
                reject_attributes(&section)?;
                // Which of the three faults it is, kept apart: an element the
                // schema does not name at all, and a second one it does, are
                // different things to go and do about the document.
                if section.name == b"interfaces" {
                    if interfaces_read {
                        return Err(duplicate_element(&section));
                    }
                    interfaces_read = true;
                    read_section(
                        &mut reader,
                        &mut model,
                        InterfaceEntry::ELEMENT,
                        InterfaceEntry::read,
                        Model::push_interface,
                    )?;
                } else if section.name == b"neighbours" {
                    if neighbours_read {
                        return Err(duplicate_element(&section));
                    }
                    neighbours_read = true;
                    read_section(
                        &mut reader,
                        &mut model,
                        NeighbourEntry::ELEMENT,
                        NeighbourEntry::read,
                        Model::push_neighbour,
                    )?;
                } else if section.name == b"rules" {
                    if rules_read {
                        return Err(duplicate_element(&section));
                    }
                    rules_read = true;
                    read_section(
                        &mut reader,
                        &mut model,
                        RuleEntry::ELEMENT,
                        RuleEntry::read,
                        Model::push_rule,
                    )?;
                } else {
                    return Err(unknown_element(&section));
                }
            }
            Some(Event::End { .. }) => break,
            None => return Err(DocumentError::at(DocumentFault::UnclosedElement, 0)),
        }
    }
    end_of_document(&mut reader)?;

    if interfaces_read && neighbours_read && rules_read && management_read {
        return Ok(model);
    }
    Err(DocumentError {
        fault: DocumentFault::MissingElement,
        offset: root.offset,
    })
}

/// One repeated element inside its section, read into the model until the
/// section closes.
///
/// The element name and the attribute grammar are the entity's own, declared
/// once beside its value; what is left here is what a *section* is — that its
/// children are all of one kind, that each is a leaf, and that a model with no
/// room for one refuses rather than truncates.
fn read_section<T, F>(
    reader: &mut Reader<'_>,
    model: &mut Model,
    element_name: &[u8],
    read_entry: fn(&Element<'_>) -> Result<T, DocumentError>,
    push: F,
) -> Result<(), DocumentError>
where
    F: Fn(&mut Model, T) -> Result<(), crate::model::Full>,
{
    loop {
        match next(reader)? {
            Some(Event::Start(element)) => {
                if element.name != element_name {
                    return Err(unknown_element(&element));
                }
                let entry = read_entry(&element)?;
                push(model, entry).map_err(|_| DocumentError {
                    fault: DocumentFault::CapacityExceeded,
                    offset: element.offset,
                })?;
                expect_empty(reader)?;
            }
            Some(Event::End { .. }) => return Ok(()),
            None => return Err(DocumentError::at(DocumentFault::UnclosedElement, 0)),
        }
    }
}

/// The element that follows a start tag must be its own end tag: no element in
/// this schema has children, so a start here is a nesting the grammar does not
/// admit rather than a deeper object.
fn expect_empty(reader: &mut Reader<'_>) -> Result<(), DocumentError> {
    match next(reader)? {
        Some(Event::End { .. }) => Ok(()),
        Some(Event::Start(element)) => Err(unknown_element(&element)),
        None => Err(DocumentError::at(DocumentFault::UnclosedElement, 0)),
    }
}

/// Only `None` ends a document. Stopping at the root's end tag leaves every
/// fault past it unasked — a second `<configuration>`, character data, a DTD —
/// and accepts a document as the first half of itself.
fn end_of_document(reader: &mut Reader<'_>) -> Result<(), DocumentError> {
    let offset = match next(reader)? {
        None => return Ok(()),
        Some(Event::Start(element)) => element.offset,
        Some(Event::End { offset, .. }) => offset,
    };
    Err(DocumentError {
        fault: DocumentFault::TrailingContent,
        offset,
    })
}

fn reject_attributes(element: &Element<'_>) -> Result<(), DocumentError> {
    match element.attributes().next() {
        Some(attribute) => Err(unknown_attribute(attribute)),
        None => Ok(()),
    }
}

fn unknown_element(element: &Element<'_>) -> DocumentError {
    DocumentError {
        fault: DocumentFault::UnknownElement,
        offset: element.offset,
    }
}

/// A section the schema names, appearing a second time. Reported at the second
/// one, which is the one to delete.
fn duplicate_element(element: &Element<'_>) -> DocumentError {
    DocumentError {
        fault: DocumentFault::DuplicateElement,
        offset: element.offset,
    }
}

fn next<'a>(reader: &mut Reader<'a>) -> Result<Option<Event<'a>>, DocumentError> {
    reader.next().transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_headers::{Ipv4Address, MacAddress};
    use proptest::prelude::*;
    use std::{string::String, vec::Vec};

    /// The `<management>` element every document below carries, addressing the
    /// management port on a prefix no interface here claims.
    ///
    /// A macro rather than a `const` so it expands to a literal, which is what
    /// `concat!` takes.
    macro_rules! management {
        () => {
            concat!(
                "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" ",
                "address=\"192.168.42.15\" prefix-length=\"24\" gateway=\"none\"/>"
            )
        };
    }

    const MANAGEMENT: &str = management!();

    /// The canonical contract configuration document, verbatim. Every negative test below
    /// is a single edit to it, so what each proves is that *that* edit is
    /// caught rather than that some fragment fails for its own reasons.
    pub(crate) const CONTRACT_DOCUMENT: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<configuration>\n",
        "  <interfaces>\n",
        "    <interface id=\"wan\" port=\"0\" enabled=\"true\"\n",
        "               mac=\"52:54:00:12:34:50\" address=\"10.0.0.1\" prefix-length=\"24\"/>\n",
        "  </interfaces>\n",
        "  <neighbours>\n",
        "    <neighbour id=\"gateway-a\" interface=\"wan\"\n",
        "               address=\"10.0.0.2\" mac=\"52:54:00:00:00:0a\"/>\n",
        "  </neighbours>\n  <rules/>\n",
        "  <management mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" ",
        "prefix-length=\"24\" enabled=\"true\" gateway=\"none\"/>\n",
        "</configuration>\n"
    );

    /// The contract document with one substring replaced, asserting the edit
    /// applied: a replacement that matched nothing would leave a document that
    /// parses, and the test would prove the opposite of what it claims.
    pub(crate) fn edited(from: &str, to: &str) -> String {
        assert!(
            CONTRACT_DOCUMENT.contains(from),
            "the test edits {from:?}, which the contract document does not contain"
        );
        CONTRACT_DOCUMENT.replacen(from, to, 1)
    }

    fn fault_of(document: &str) -> DocumentFault {
        match parse(document.as_bytes()) {
            Err(error) => error.fault,
            Ok(model) => panic!(
                "expected a rejection, parsed {} interfaces",
                model.interface_count()
            ),
        }
    }

    #[test]
    fn the_contract_document_parses_to_exactly_what_it_says() {
        let model = parse(CONTRACT_DOCUMENT.as_bytes()).expect("the contract document");
        assert_eq!(model.interface_count(), 1);
        assert_eq!(model.neighbour_count(), 1);

        let interface = model.interfaces().next().expect("one interface");
        assert_eq!(interface.id.as_str(), "wan");
        assert_eq!(interface.port, 0);
        assert!(interface.enabled);
        assert_eq!(
            interface.mac,
            MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50])
        );
        assert_eq!(interface.address, Ipv4Address::from_octets([10, 0, 0, 1]));
        assert_eq!(interface.prefix_length, 24);

        let neighbour = model.neighbours().next().expect("one neighbour");
        assert_eq!(neighbour.id.as_str(), "gateway-a");
        assert_eq!(neighbour.interface.as_str(), "wan");
        assert_eq!(neighbour.address, Ipv4Address::from_octets([10, 0, 0, 2]));
        assert_eq!(
            neighbour.mac,
            MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a])
        );
    }

    #[test]
    fn both_sections_may_be_empty_and_both_must_be_present() {
        let empty = concat!(
            "<configuration><interfaces/><neighbours/><rules/>",
            management!(),
            "</configuration>"
        );
        let model = parse(empty.as_bytes()).expect("empty sections are a configuration");
        assert_eq!(model.interface_count(), 0);
        assert_eq!(model.neighbour_count(), 0);
        assert!(
            model.management().is_some(),
            "the management element is not one of the two that may be empty"
        );
        // Every one of the four sections is required, so each of them missing
        // is a rejection rather than a default.
        for partial in [
            concat!(
                "<configuration><interfaces/><rules/>",
                management!(),
                "</configuration>"
            ),
            concat!(
                "<configuration><neighbours/><rules/>",
                management!(),
                "</configuration>"
            ),
            concat!(
                "<configuration><interfaces/><neighbours/>",
                management!(),
                "</configuration>"
            ),
            "<configuration><interfaces/><neighbours/><rules/></configuration>",
            "<configuration/>",
        ] {
            assert_eq!(
                parse(partial.as_bytes())
                    .expect_err("every section is required")
                    .fault,
                DocumentFault::MissingElement,
                "{partial}"
            );
        }
    }

    #[test]
    fn the_sections_may_be_written_in_either_order_and_neither_twice() {
        let swapped = concat!(
            "<configuration>",
            management!(),
            "<rules/><neighbours/><interfaces/></configuration>"
        );
        assert!(parse(swapped.as_bytes()).is_ok());
        // A second section is refused for *being* a second one. It is not an
        // unknown element — the schema names all three — and telling an
        // operator that `<interfaces>` is unknown when their document has two
        // of them sends them to the wrong edit.
        for twice in [
            concat!(
                "<configuration><interfaces/><interfaces/><neighbours/><rules/>",
                management!(),
                "</configuration>"
            ),
            concat!(
                "<configuration><interfaces/><neighbours/><rules/><rules/>",
                management!(),
                "</configuration>"
            ),
            concat!(
                "<configuration><interfaces/><neighbours/><rules/><neighbours/>",
                management!(),
                "</configuration>"
            ),
            concat!(
                "<configuration><interfaces/><neighbours/><rules/>",
                management!(),
                management!(),
                "</configuration>"
            ),
        ] {
            assert_eq!(
                parse(twice.as_bytes()).expect_err("one each").fault,
                DocumentFault::DuplicateElement,
                "{twice}"
            );
        }
    }

    #[test]
    fn an_element_the_schema_does_not_name_is_refused_wherever_it_sits() {
        assert_eq!(
            fault_of(&edited("<configuration>", "<config>")),
            DocumentFault::UnknownElement
        );
        assert_eq!(
            fault_of(&edited("  <interfaces>", "  <zones>")),
            DocumentFault::UnknownElement
        );
        assert_eq!(
            fault_of(&edited("    <interface id", "    <iface id")),
            DocumentFault::UnknownElement
        );
        assert_eq!(
            fault_of(&edited("    <neighbour id", "    <peer id")),
            DocumentFault::UnknownElement
        );
    }

    #[test]
    fn the_management_element_parses_to_the_port_it_addresses() {
        let model = parse(CONTRACT_DOCUMENT.as_bytes()).expect("the contract document");
        let management = model.management().expect("the element is required");
        assert!(management.enabled);
        assert_eq!(
            management.mac,
            MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52])
        );
        assert_eq!(
            management.address,
            Ipv4Address::from_octets([192, 168, 42, 15])
        );
        assert_eq!(management.prefix_length, 24);
    }

    #[test]
    fn the_management_elements_vocabulary_is_as_closed_as_every_other() {
        // An attribute the schema does not name, including one that belongs to
        // an `<interface>` but not here: the management port has no port number.
        for extra in ["port=\"0\"", "id=\"mgmt\"", "mtu=\"1500\""] {
            assert_eq!(
                fault_of(&edited(
                    "<management ",
                    &std::format!("<management {extra} ")
                )),
                DocumentFault::UnknownAttribute,
                "{extra}"
            );
        }
        // Each attribute it does name, omitted. Every substring below is
        // unique to the management element: `enabled="true"` alone would edit
        // the interface, which is the first line that carries one.
        for (removed, replacement) in [
            ("mac=\"52:54:00:12:34:52\" ", ""),
            ("address=\"192.168.42.15\" ", ""),
            ("prefix-length=\"24\" enabled", "enabled"),
            (" enabled=\"true\" gateway", " gateway"),
            (" gateway=\"none\"/>", "/>"),
        ] {
            assert_eq!(
                fault_of(&edited(removed, replacement)),
                DocumentFault::MissingAttribute,
                "without {removed:?}"
            );
        }
        // And each of them malformed, reported at the value.
        for (from, to) in [
            ("mac=\"52:54:00:12:34:52\"", "mac=\"52-54-00-12-34-52\""),
            ("address=\"192.168.42.15\"", "address=\"192.168.42\""),
            (
                "prefix-length=\"24\" enabled",
                "prefix-length=\"x\" enabled",
            ),
            ("enabled=\"true\" gateway", "enabled=\"1\" gateway"),
            // Neither an address nor the one word that stands for its
            // absence, so it is the wrong shape rather than a wrong value.
            ("gateway=\"none\"", "gateway=\"any\""),
            ("gateway=\"none\"", "gateway=\"10.0.0\""),
        ] {
            let document = edited(from, to);
            let error = parse(document.as_bytes()).expect_err(to);
            assert_eq!(error.fault, DocumentFault::MalformedValue, "{to}");
            assert_eq!(
                document.as_bytes().get(error.offset as usize),
                Some(&b'"'),
                "the offset points at the value's opening quote: {to}"
            );
        }
        // A child inside it is a nesting the grammar does not admit.
        assert_eq!(
            fault_of(&edited(
                "gateway=\"none\"/>",
                "gateway=\"none\"><x/></management>"
            )),
            DocumentFault::UnknownElement
        );
    }

    #[test]
    fn a_nested_element_inside_a_leaf_is_refused() {
        let nested = edited(
            "prefix-length=\"24\"/>",
            "prefix-length=\"24\"><x/></interface>",
        );
        assert_eq!(fault_of(&nested), DocumentFault::UnknownElement);
    }

    #[test]
    fn an_attribute_the_schema_does_not_name_is_refused_and_its_position_reported() {
        let document = edited("id=\"wan\"", "id=\"wan\" mtu=\"1500\"");
        let error = parse(document.as_bytes()).expect_err("mtu is not in the schema");
        assert_eq!(error.fault, DocumentFault::UnknownAttribute);
        assert_eq!(
            document
                .as_bytes()
                .get(error.offset as usize..error.offset as usize + 3),
            Some(&b"mtu"[..])
        );
    }

    #[test]
    fn an_unknown_attribute_on_a_neighbour_is_refused_too() {
        assert_eq!(
            fault_of(&edited("id=\"gateway-a\"", "id=\"gateway-a\" port=\"0\"")),
            DocumentFault::UnknownAttribute
        );
    }

    #[test]
    fn a_misspelled_attribute_is_refused_rather_than_defaulted() {
        // The whole point of the closed schema: `enable` would leave `enabled`
        // absent, and a reader that defaulted it would report an interface as
        // up that an operator wrote down.
        assert_eq!(
            fault_of(&edited("enabled=\"true\"", "enable=\"true\"")),
            DocumentFault::UnknownAttribute
        );
    }

    #[test]
    fn an_attribute_the_schema_requires_and_the_document_omits_is_refused() {
        for removed in [
            "id=\"wan\" ",
            "port=\"0\" ",
            "enabled=\"true\"",
            "mac=\"52:54:00:12:34:50\" ",
            "address=\"10.0.0.1\" ",
            " prefix-length=\"24\"",
        ] {
            assert_eq!(
                fault_of(&edited(removed, "")),
                DocumentFault::MissingAttribute,
                "without {removed:?}"
            );
        }
        for removed in [
            "id=\"gateway-a\" ",
            "interface=\"wan\"",
            "address=\"10.0.0.2\" ",
            " mac=\"52:54:00:00:00:0a\"",
        ] {
            assert_eq!(
                fault_of(&edited(removed, "")),
                DocumentFault::MissingAttribute,
                "without {removed:?}"
            );
        }
    }

    #[test]
    fn a_section_element_carrying_an_attribute_is_refused() {
        assert_eq!(
            fault_of(&edited("<configuration>", "<configuration version=\"1\">")),
            DocumentFault::UnknownAttribute
        );
        assert_eq!(
            fault_of(&edited("  <interfaces>", "  <interfaces count=\"1\">")),
            DocumentFault::UnknownAttribute
        );
    }

    #[test]
    fn a_value_that_is_not_its_attributes_shape_is_refused_where_the_value_is() {
        for (from, to) in [
            ("id=\"wan\"", "id=\"WAN\""),
            ("port=\"0\"", "port=\"999\""),
            ("enabled=\"true\"", "enabled=\"1\""),
            ("mac=\"52:54:00:12:34:50\"", "mac=\"52-54-00-12-34-50\""),
            ("address=\"10.0.0.1\"", "address=\"10.0.0\""),
            ("prefix-length=\"24\"", "prefix-length=\"x\""),
            ("interface=\"wan\"", "interface=\"\""),
        ] {
            let document = edited(from, to);
            let error = parse(document.as_bytes()).expect_err(to);
            assert_eq!(error.fault, DocumentFault::MalformedValue, "{to}");
            assert_eq!(
                document.as_bytes().get(error.offset as usize),
                Some(&b'"'),
                "the offset points at the value's opening quote: {to}"
            );
        }
    }

    #[test]
    fn attribute_order_does_not_change_the_model() {
        let reordered = edited(
            "id=\"wan\" port=\"0\" enabled=\"true\"",
            "enabled=\"true\" port=\"0\" id=\"wan\"",
        );
        assert_eq!(
            parse(reordered.as_bytes()).expect("reordered"),
            parse(CONTRACT_DOCUMENT.as_bytes()).expect("original")
        );
    }

    #[test]
    fn whitespace_and_comments_do_not_change_the_model() {
        let noisy = edited(
            "  <neighbours>",
            "  <!-- the hosts we can resolve -->\n\n  <neighbours>   ",
        );
        assert_eq!(
            parse(noisy.as_bytes()).expect("noisy"),
            parse(CONTRACT_DOCUMENT.as_bytes()).expect("original")
        );
    }

    #[test]
    fn a_value_written_with_references_is_the_value_it_expands_to() {
        let escaped = edited("id=\"wan\"", "id=\"&#119;an\"");
        assert_eq!(
            parse(escaped.as_bytes()).expect("references expand"),
            parse(CONTRACT_DOCUMENT.as_bytes()).expect("original")
        );
    }

    #[test]
    fn more_objects_than_the_image_holds_are_refused_rather_than_truncated() {
        fn document(interfaces: usize, neighbours: usize) -> String {
            let mut text = String::from("<configuration><interfaces>");
            for index in 0..interfaces {
                text.push_str(&std::format!(
                    "<interface id=\"i{index}\" port=\"0\" enabled=\"true\" \
                     mac=\"52:54:00:00:00:01\" address=\"10.0.0.1\" prefix-length=\"24\"/>"
                ));
            }
            text.push_str("</interfaces><neighbours>");
            for index in 0..neighbours {
                text.push_str(&std::format!(
                    "<neighbour id=\"n{index}\" interface=\"i0\" address=\"10.0.0.2\" \
                     mac=\"52:54:00:00:00:02\"/>"
                ));
            }
            text.push_str("</neighbours><rules/>");
            text.push_str(MANAGEMENT);
            text.push_str("</configuration>");
            text
        }
        let at_limit = document(wire::MAX_INTERFACES, wire::MAX_NEIGHBOURS);
        let model = parse(at_limit.as_bytes()).expect("exactly the capacity fits");
        assert_eq!(model.interface_count(), wire::MAX_INTERFACES);
        assert_eq!(model.neighbour_count(), wire::MAX_NEIGHBOURS);

        assert_eq!(
            fault_of(&document(wire::MAX_INTERFACES + 1, 0)),
            DocumentFault::CapacityExceeded
        );
        assert_eq!(
            fault_of(&document(1, wire::MAX_NEIGHBOURS + 1)),
            DocumentFault::CapacityExceeded
        );
    }

    #[test]
    fn a_document_with_no_root_element_is_refused_before_the_schema_is_consulted() {
        assert_eq!(fault_of(""), DocumentFault::MissingRootElement);
        assert_eq!(
            fault_of("<!-- nothing -->"),
            DocumentFault::MissingRootElement
        );
    }

    #[test]
    fn a_document_whose_root_never_closes_is_refused() {
        assert_eq!(
            fault_of("<configuration><interfaces>"),
            DocumentFault::UnclosedElement
        );
        assert_eq!(
            fault_of("<configuration><neighbours>"),
            DocumentFault::UnclosedElement
        );
        assert_eq!(fault_of("<configuration>"), DocumentFault::UnclosedElement);
    }

    /// The complete document, with nothing after its root: the base every
    /// trailing-content case below appends to, so each rejection's offset is
    /// this length and the edit is the only thing under test.
    const CLOSED_DOCUMENT: &str = concat!(
        "<configuration><interfaces/><neighbours/><rules/>",
        management!(),
        "</configuration>"
    );

    /// Every fault the reader raises past the root, which a parse that stopped
    /// at the root's end tag never asked for. Each one made `load` accept a
    /// document it had read only the first half of; the second case is the
    /// differential — two configurations with different addresses, of which
    /// only the first was returned.
    #[test]
    fn nothing_may_follow_the_root_element() {
        let second_configuration = concat!(
            "<configuration><interfaces>",
            "<interface id=\"lan\" port=\"1\" enabled=\"true\" mac=\"52:54:00:00:00:02\" ",
            "address=\"192.168.0.1\" prefix-length=\"24\"/>",
            "</interfaces><neighbours/><rules/>",
            management!(),
            "</configuration>"
        );
        for (trailing, fault) in [
            ("<x/>", DocumentFault::TrailingContent),
            (second_configuration, DocumentFault::TrailingContent),
            ("oops", DocumentFault::CharacterData),
            ("<!DOCTYPE x>", DocumentFault::Doctype),
            ("<!ENTITY a \"b\">", DocumentFault::EntityDeclaration),
            ("<![CDATA[x]]>", DocumentFault::CdataSection),
            ("<!-- forever", DocumentFault::UnterminatedComment),
        ] {
            let document = std::format!("{CLOSED_DOCUMENT}{trailing}");
            let error = parse(document.as_bytes()).expect_err(trailing);
            assert_eq!(error.fault, fault, "trailing {trailing:?}");
            assert_eq!(
                error.offset as usize,
                CLOSED_DOCUMENT.len(),
                "the offset points at the first byte past the root: {trailing:?}"
            );
        }
    }

    /// The one a differential is built out of: the first document is complete
    /// and valid on its own, so nothing before the root's end tag can refuse
    /// it, and the addresses differ so a reader taking the last one disagrees
    /// about what the file says.
    #[test]
    fn a_document_that_parsed_whole_is_the_whole_document() {
        let single = parse(CLOSED_DOCUMENT.as_bytes()).expect("a complete document");
        assert_eq!(single.interface_count(), 0);
        assert_eq!(single.neighbour_count(), 0);
        assert_eq!(
            parse(std::format!("{CLOSED_DOCUMENT}{CLOSED_DOCUMENT}").as_bytes())
                .expect_err("two documents are not one")
                .fault,
            DocumentFault::TrailingContent
        );
    }

    /// Trailing whitespace is not trailing content: a file ending in a newline
    /// is the ordinary case, and the contract document is one.
    #[test]
    fn whitespace_after_the_root_ends_the_document() {
        assert!(parse(std::format!("{CLOSED_DOCUMENT}\n  \n").as_bytes()).is_ok());
        assert!(parse(CONTRACT_DOCUMENT.as_bytes()).is_ok());
    }

    proptest! {
        /// Total: arbitrary bytes yield a model or a typed rejection, never a
        /// panic and never a hang.
        #[test]
        fn parsing_arbitrary_bytes_is_total(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let _ = parse(&bytes);
        }

        /// The same over bytes that look like this schema, which reaches the
        /// element and attribute dispatch that uniform noise never does.
        #[test]
        fn parsing_arbitrary_schema_shaped_text_is_total(
            text in r#"(<configuration>|</configuration>|<interfaces/>|<neighbours/>|<interface id="[a-z]{1,3}" port="[0-9]"/>|<neighbour id="[a-z]{1,3}"/>| ){0,30}"#,
        ) {
            let _ = parse(text.as_bytes());
        }

        /// No document, however written, produces more entries than the
        /// handover image has slots for.
        #[test]
        fn no_accepted_document_exceeds_the_image_capacity(
            interfaces in 0usize..12,
            neighbours in 0usize..40,
        ) {
            let mut text = String::from("<configuration><interfaces>");
            for index in 0..interfaces {
                text.push_str(&std::format!(
                    "<interface id=\"i{index}\" port=\"0\" enabled=\"true\" \
                     mac=\"52:54:00:00:00:01\" address=\"10.0.0.1\" prefix-length=\"24\"/>"
                ));
            }
            text.push_str("</interfaces><neighbours>");
            for index in 0..neighbours {
                text.push_str(&std::format!(
                    "<neighbour id=\"n{index}\" interface=\"i0\" address=\"10.0.0.2\" \
                     mac=\"52:54:00:00:00:02\"/>"
                ));
            }
            text.push_str("</neighbours><rules/>");
            text.push_str(MANAGEMENT);
            text.push_str("</configuration>");

            match parse(text.as_bytes()) {
                Ok(model) => {
                    prop_assert!(model.interface_count() <= wire::MAX_INTERFACES);
                    prop_assert!(model.neighbour_count() <= wire::MAX_NEIGHBOURS);
                    prop_assert_eq!(model.interface_count(), interfaces);
                    prop_assert_eq!(model.neighbour_count(), neighbours);
                }
                Err(error) => {
                    prop_assert_eq!(error.fault, DocumentFault::CapacityExceeded);
                    prop_assert!(
                        interfaces > wire::MAX_INTERFACES || neighbours > wire::MAX_NEIGHBOURS
                    );
                }
            }
        }

        /// Parsing is a function of the bytes alone.
        #[test]
        fn parsing_is_deterministic(
            text in r#"[<>/?!&;="'a-z0-9 \n#.:-]{0,300}"#,
        ) {
            prop_assert_eq!(parse(text.as_bytes()), parse(text.as_bytes()));
        }

        /// Reordering the objects leaves the same set of objects, which is what
        /// makes an id the identity a later diff can key on.
        #[test]
        fn reordering_the_objects_yields_the_same_set(
            names in proptest::collection::vec("[a-z]{1,4}", 1..5),
        ) {
            let entry = |name: &str| std::format!(
                "<interface id=\"{name}\" port=\"0\" enabled=\"true\" \
                 mac=\"52:54:00:00:00:01\" address=\"10.0.0.1\" prefix-length=\"24\"/>"
            );
            let document = |ordered: &[String]| {
                let mut text = String::from("<configuration><interfaces>");
                for name in ordered {
                    text.push_str(&entry(name));
                }
                text.push_str("</interfaces><neighbours/><rules/>");
                text.push_str(MANAGEMENT);
                text.push_str("</configuration>");
                text
            };
            let mut reversed = names.clone();
            reversed.reverse();

            let forwards = parse(document(&names).as_bytes()).expect("well formed");
            let backwards = parse(document(&reversed).as_bytes()).expect("well formed");
            let mut left: Vec<&str> = forwards.interfaces().map(|e| e.id.as_str()).collect();
            let mut right: Vec<&str> = backwards.interfaces().map(|e| e.id.as_str()).collect();
            left.sort_unstable();
            right.sort_unstable();
            prop_assert_eq!(left, right);
        }
    }
}
