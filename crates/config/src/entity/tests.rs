//! What the declarations owe the rest of the crate, asserted against the three
//! that exist rather than against the macro.

use super::*;
use crate::xml::{Event, Reader};
use std::{vec, vec::Vec};

/// Read one element out of a one-element document, so a test states the
/// attributes it is about and nothing else.
fn element_of<T>(
    text: &str,
    read: fn(&Element<'_>) -> Result<T, DocumentError>,
) -> Result<T, DocumentError> {
    let mut reader = Reader::new(text.as_bytes()).expect("the document is within every bound");
    match reader.next().expect("an element").expect("well formed") {
        Event::Start(element) => read(&element),
        Event::End { .. } => panic!("the document opens with a start tag"),
    }
}

const INTERFACE: &str = concat!(
    "<interface id=\"wan\" port=\"0\" enabled=\"true\" mac=\"52:54:00:12:34:50\" ",
    "address=\"10.0.0.1\" prefix-length=\"24\"/>"
);

#[test]
fn an_element_reads_into_exactly_the_value_its_attributes_name() {
    let entry = element_of(INTERFACE, InterfaceEntry::read).expect("every attribute is present");
    assert_eq!(entry.id.as_str(), "wan");
    assert_eq!(entry.port, 0);
    assert!(entry.enabled);
    assert_eq!(entry.prefix_length, 24);
    assert_eq!(entry.mac, MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]));
    assert_eq!(entry.address, Ipv4Address::from_octets([10, 0, 0, 1]));
}

/// Every attribute but the key is named by its field's console token, so the
/// text an operator edits and the text a change record prints are one string.
/// Asserted over the attributes the reader accepts, which is what would drift.
#[test]
fn every_attribute_but_the_key_is_named_by_the_field_it_records() {
    for (field, spelling) in [
        (Field::Port, "port"),
        (Field::Enabled, "enabled"),
        (Field::Mac, "mac"),
        (Field::Address, "address"),
        (Field::PrefixLength, "prefix-length"),
        (Field::Interface, "interface"),
    ] {
        assert_eq!(field.name(), spelling);
        // Matched with the `="` so a field name that is also an element name
        // edits the attribute rather than the tag.
        let renamed = INTERFACE.replace(&std::format!("{spelling}=\""), "renamed=\"");
        if renamed != INTERFACE {
            assert_eq!(
                element_of(&renamed, InterfaceEntry::read)
                    .expect_err("the attribute is no longer one the object names")
                    .fault,
                DocumentFault::UnknownAttribute,
                "{spelling}"
            );
        }
    }
}

/// The key produces no change record of its own: every record about an object
/// already names it, so recording the id would report an object's identity as
/// one of its own changes.
#[test]
fn the_key_is_not_a_field_and_every_declared_field_is_one() {
    let entry = element_of(INTERFACE, InterfaceEntry::read).expect("a sound element");
    let reported: Vec<Field> = Field::ALL
        .into_iter()
        .filter(|field| entry.field_value(*field).is_some())
        .collect();
    assert_eq!(
        reported,
        vec![
            Field::Port,
            Field::Enabled,
            Field::Mac,
            Field::Address,
            Field::PrefixLength
        ]
    );
    assert_eq!(entry.key(), entry.id);
    assert_eq!(entry.field_value(Field::Interface), None);
}

#[test]
fn a_neighbour_reports_the_interface_it_names_and_a_management_entry_has_no_id() {
    let neighbour = element_of(
        "<neighbour id=\"gw\" interface=\"wan\" address=\"10.0.0.2\" mac=\"52:54:00:00:00:0a\"/>",
        NeighbourEntry::read,
    )
    .expect("a sound element");
    assert_eq!(
        neighbour.field_value(Field::Interface),
        Some(Value::Id(neighbour.interface))
    );
    assert_eq!(neighbour.field_value(Field::Port), None);
    assert_eq!(neighbour.key(), neighbour.id);

    let management = element_of(
        "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" address=\"10.9.0.1\" \
         prefix-length=\"24\"/>",
        ManagementEntry::read,
    )
    .expect("a sound element");
    assert_eq!(management.key(), Identifier::MANAGEMENT);
    assert_eq!(management.field_value(Field::Port), None);
}

/// Two objects differing in one field fold to two hashes: a field left out of
/// the fold is an edit that commits nothing, and nothing else here would say so.
#[test]
fn every_declared_field_moves_the_hash_and_the_mark_separates_two_objects() {
    let entry = element_of(INTERFACE, InterfaceEntry::read).expect("a sound element");
    let base = entry.fold(0);
    for (from, to) in [
        ("id=\"wan\"", "id=\"lan\""),
        ("port=\"0\"", "port=\"1\""),
        ("enabled=\"true\"", "enabled=\"false\""),
        ("mac=\"52:54:00:12:34:50\"", "mac=\"52:54:00:12:34:51\""),
        ("address=\"10.0.0.1\"", "address=\"10.0.0.2\""),
        ("prefix-length=\"24\"", "prefix-length=\"25\""),
    ] {
        let edited = INTERFACE.replace(from, to);
        let moved = element_of(&edited, InterfaceEntry::read).expect("still sound");
        assert_ne!(
            base,
            moved.fold(0),
            "{from} -> {to} left the hash where it was"
        );
    }
    // Two kinds of object with the same field values still fold apart, which is
    // the whole of what a mark is for.
    assert_ne!(InterfaceEntry::MARK, NeighbourEntry::MARK);
    assert_ne!(NeighbourEntry::MARK, ManagementEntry::MARK);
    assert_ne!(InterfaceEntry::MARK, ManagementEntry::MARK);
}

/// A declared attribute the document omits is refused rather than defaulted,
/// for every one of them.
#[test]
fn an_attribute_the_object_names_and_the_document_omits_is_refused() {
    for removed in [
        "id=\"wan\" ",
        "port=\"0\" ",
        "enabled=\"true\" ",
        "mac=\"52:54:00:12:34:50\" ",
        "address=\"10.0.0.1\" ",
        " prefix-length=\"24\"",
    ] {
        let without = INTERFACE.replace(removed, "");
        assert_ne!(without, INTERFACE, "the test edits {removed:?}");
        assert_eq!(
            element_of(&without, InterfaceEntry::read)
                .expect_err("every attribute is required")
                .fault,
            DocumentFault::MissingAttribute,
            "without {removed:?}"
        );
    }
}

/// The element name each object answers to is the one the schema dispatches on,
/// and no two objects answer to the same one.
#[test]
fn each_object_names_one_element_and_no_two_name_the_same() {
    assert_eq!(InterfaceEntry::ELEMENT, b"interface");
    assert_eq!(NeighbourEntry::ELEMENT, b"neighbour");
    assert_eq!(ManagementEntry::ELEMENT, b"management");
    assert_eq!(InterfaceEntry::OBJECT, ObjectKind::Interface);
    assert_eq!(NeighbourEntry::OBJECT, ObjectKind::Neighbour);
    assert_eq!(ManagementEntry::OBJECT, ObjectKind::Management);
}
