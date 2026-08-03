//! One declaration per configurable object, and the four mechanical faces each
//! one has to present.
//!
//! An object the document can name is not one thing but five: a value in the
//! model, the attributes a reader accepts for it, the change records a commit
//! writes about it, the bytes it folds into a content hash, and the rules it is
//! held to. Four of those are a transcription of the same field list, and a
//! transcription is where the list stops being one list — an attribute added to
//! the reader and not to the hash is a document whose edit commits nothing, and
//! nothing about either half says so. [`configuration_entity`] takes the list
//! once and writes all four.
//!
//! The fifth stays hand-written, deliberately and without exception. A
//! semantic rule is the interesting part of this crate and the part a reviewer
//! is here to read; a macro that could hide one would buy a few lines with the
//! one thing the crate is for. Nothing below decides whether a value is
//! *allowed* — only what it is called, how it is parsed into its type, how it
//! is reported and how it is folded.
//!
//! # The document's attribute names are not written here
//!
//! Every attribute but the key names its [`Field`], and the field's console
//! token *is* the attribute name — one string, so a change record and the text
//! an operator edits cannot come to disagree. The key is the exception and is
//! spelled: it names an object rather than describing one, so it has no field
//! and produces no change record of its own.

use lfw_log::{Field, Identifier, ObjectKind, Value};
use net_headers::{Ipv4Address, MacAddress};

use crate::{
    rule::{AddressMatch, IcmpTypeMatch, InterfaceMatch, PortMatch, ProtocolMatch, RuleAction},
    value,
    xml::{Attribute, DocumentError, DocumentFault, Element},
};

/// The Rust type one attribute kind parses to.
///
/// This and the four tables below are one arm per attribute kind, laid out as a
/// table because reading them down the column is what shows that a kind means
/// the same thing to the parser, to a change record and to the hash. rustfmt
/// would put each arm on three lines and there would be no column left.
#[rustfmt::skip]
macro_rules! value_type {
    (identifier)    => { Identifier };
    (boolean)       => { bool };
    (port)          => { u8 };
    (prefix_length) => { u8 };
    (ipv4)          => { Ipv4Address };
    (mac)           => { MacAddress };
    (interface_match) => { InterfaceMatch };
    (address_match)   => { AddressMatch };
    (protocol_match)  => { ProtocolMatch };
    (port_match)      => { PortMatch };
    (icmp_type_match) => { IcmpTypeMatch };
    (action)          => { RuleAction };
}

/// How a value of one kind reaches a change record. Closed by construction: the
/// record vocabulary has a variant per kind and no way to carry a value that
/// has not been parsed into one.
#[rustfmt::skip]
macro_rules! value_record {
    (identifier, $value:expr)    => { Value::Id($value) };
    (boolean, $value:expr)       => { Value::Bool($value) };
    (port, $value:expr)          => { Value::Port($value) };
    (prefix_length, $value:expr) => { Value::PrefixLength($value) };
    (ipv4, $value:expr)          => { Value::Ipv4($value) };
    (mac, $value:expr)           => { Value::Mac($value) };
    (interface_match, $value:expr) => { $value.record() };
    (address_match, $value:expr)   => { $value.record() };
    (protocol_match, $value:expr)  => { $value.record() };
    (port_match, $value:expr)      => { $value.record() };
    (icmp_type_match, $value:expr) => { $value.record() };
    (action, $value:expr)          => { $value.record() };
}

/// The bytes a value of one kind folds into the content hash. Every kind but an
/// identifier is fixed-width; an identifier is closed by a terminator its own
/// alphabet excludes, so the folded sequence has exactly one reading whatever
/// the values are.
#[rustfmt::skip]
macro_rules! value_fold {
    (identifier, $hash:expr, $value:expr)    => { $crate::hash::fold_identifier($hash, $value) };
    (boolean, $hash:expr, $value:expr)       => { $crate::hash::fold($hash, &[u8::from($value)]) };
    (port, $hash:expr, $value:expr)          => { $crate::hash::fold($hash, &[$value]) };
    (prefix_length, $hash:expr, $value:expr) => { $crate::hash::fold($hash, &[$value]) };
    (ipv4, $hash:expr, $value:expr)          => { $crate::hash::fold($hash, &$value.octets()) };
    (mac, $hash:expr, $value:expr)           => { $crate::hash::fold($hash, &$value.0) };
    (interface_match, $hash:expr, $value:expr) => { $value.fold($hash) };
    (address_match, $hash:expr, $value:expr)   => { $value.fold($hash) };
    (protocol_match, $hash:expr, $value:expr)  => { $value.fold($hash) };
    (port_match, $hash:expr, $value:expr)      => { $value.fold($hash) };
    (icmp_type_match, $hash:expr, $value:expr) => { $value.fold($hash) };
    (action, $hash:expr, $value:expr)          => { $value.fold($hash) };
}

/// The attribute name one role answers to. A field's is its console token, so
/// the two cannot drift; a key's is spelled here because it has no field.
#[rustfmt::skip]
macro_rules! attribute_name {
    (key)                  => { b"id".as_slice() };
    (field($field:ident))  => { Field::$field.name().as_bytes() };
}

/// The identifier a change record is keyed on: a field of the object where it
/// has one, and a reserved name where it does not — the management element
/// names one port and has no id to give.
#[rustfmt::skip]
macro_rules! entity_key {
    (field($name:ident), $entry:expr)  => { $entry.$name };
    (reserved($value:expr), $entry:expr) => { $value };
    (positional, $entry:expr) => { compile_error!("a positional object is keyed by its caller") };
}

/// The `key` accessor, for an object that has one. A positional object does
/// not: what files its records is where it sits, which is the walk's to say and
/// not the entry's, so it is given no accessor to be asked for one by mistake.
macro_rules! entity_key_fn {
    (positional) => {};
    ($role:ident ($($arg:tt)*)) => {
        /// The identifier every change record about this object is keyed
        /// on, and the one an operator edits it by.
        pub(crate) const fn key(&self) -> Identifier {
            $crate::entity::entity_key!($role($($arg)*), self)
        }
    };
}

/// One change record's worth of a field, or nothing at all where the role
/// carries none. A key names the object every record about it already names, so
/// recording it would report an object's identity as one of its own changes.
macro_rules! field_probe {
    (key, $kind:ident, $entry:expr, $wanted:expr, $field:ident) => {};
    (field($named:ident), $kind:ident, $entry:expr, $wanted:expr, $field:ident) => {
        if $wanted == Field::$named {
            return Some($crate::entity::value_record!($kind, $entry.$field));
        }
    };
}

/// Declare a configurable object: its value, its reader, its change records and
/// its contribution to the content hash.
///
/// The header names the element the document writes it as, the object kind a
/// change record names it by, the identifier a record is keyed on, and the byte
/// that marks where one of these objects begins in the hash. Each attribute
/// names its role — `key` for the identity, `field(X)` for a value a change
/// record can report — the model field it lands in, and the kind that decides
/// how it is parsed, reported and folded.
///
/// **The attributes are declared in hash order**, which is the one order that
/// is an ABI: a change record's position comes from the field vocabulary and a
/// reader accepts attributes in any order, so neither constrains this list —
/// but the fold is a byte sequence, and re-ordering it is a content hash that
/// no longer recognises a configuration it has already committed.
macro_rules! configuration_entity {
    (
        $(#[$entity_meta:meta])*
        $entity:ident reads $element:literal as $object:expr,
            keyed by $keyrole:ident$(($($keyarg:tt)*))?, marked $mark:literal {
            $(
                $(#[$field_meta:meta])*
                @$role:ident $(($($role_arg:tt)*))? $field:ident: $kind:ident,
            )+
        }
    ) => {
        $(#[$entity_meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $entity {
            $(
                $(#[$field_meta])*
                pub $field: $crate::entity::value_type!($kind),
            )+
        }

        impl $entity {
            /// The element name the document writes this object as.
            pub(crate) const ELEMENT: &'static [u8] = $element;

            /// Which kind of object a change record names this one.
            pub(crate) const OBJECT: ObjectKind = $object;

            /// Where one of these objects begins in the content hash, so the
            /// last field of one cannot read as the first field of the next.
            const MARK: u8 = $mark;

            /// Read one element's attributes into a value, refusing an
            /// attribute this object does not name and one it names that the
            /// document omits.
            ///
            /// Shape only: nothing here reads what a value *means*, so no rule
            /// about the configuration can come to rest on where in the file
            /// something was written.
            ///
            /// # Errors
            /// [`DocumentError`], naming the fault and the byte it was decided
            /// at.
            pub(crate) fn read(element: &Element<'_>) -> Result<Self, DocumentError> {
                $( let mut $field = None; )+
                for attribute in element.attributes() {
                    $(
                        if attribute.name == $crate::entity::attribute_name!($role $(($($role_arg)*))?) {
                            $field = Some($crate::entity::attribute_value(
                                attribute,
                                value::$kind,
                            )?);
                            continue;
                        }
                    )+
                    return Err($crate::entity::unknown_attribute(attribute));
                }
                Ok(Self {
                    $( $field: $crate::entity::required_attribute($field, element)?, )+
                })
            }

            $crate::entity::entity_key_fn!($keyrole $(($($keyarg)*))?);

            /// What this object says about one field, or `None` where it has no
            /// such field. Answering per field rather than per position is what
            /// leaves a record's place in a commit a property of the field
            /// vocabulary alone.
            pub(crate) fn field_value(&self, field: Field) -> Option<Value> {
                $( $crate::entity::field_probe!($role $(($($role_arg)*))?, $kind, self, field, $field); )+
                None
            }

            /// Fold this object into a content hash, mark first.
            pub(crate) fn fold(&self, hash: u32) -> u32 {
                let hash = $crate::hash::fold(hash, &[Self::MARK]);
                $( let hash = $crate::entity::value_fold!($kind, hash, self.$field); )+
                hash
            }
        }
    };
}

configuration_entity! {
    /// One `<interface>`: the appliance's own presence on a directly attached
    /// subnet, keyed by the id an operator gave it.
    InterfaceEntry reads b"interface" as ObjectKind::Interface,
        keyed by field(id), marked 0x01 {
        @key id: identifier,
        @field(Port) port: port,
        @field(Enabled) enabled: boolean,
        @field(PrefixLength) prefix_length: prefix_length,
        @field(Mac) mac: mac,
        @field(Address) address: ipv4,
    }
}

configuration_entity! {
    /// One `<neighbour>`, naming its interface by that interface's id rather
    /// than by a port number.
    ///
    /// An id survives an operator renumbering ports, and it is the reference
    /// whose resolution is a real validation step: a port number would resolve
    /// to whatever happened to be configured there.
    NeighbourEntry reads b"neighbour" as ObjectKind::Neighbour,
        keyed by field(id), marked 0x02 {
        @key id: identifier,
        @field(Interface) interface: identifier,
        @field(Address) address: ipv4,
        @field(Mac) mac: mac,
    }
}

configuration_entity! {
    /// The `<management>` element: the appliance's own presence on the port the
    /// design keeps out of the dataplane. It carries no `id` and no `port` —
    /// one such port, not in the router's set, so neither has anything to
    /// select, and its records are keyed by the name the vocabulary reserves
    /// for it.
    ManagementEntry reads b"management" as ObjectKind::Management,
        keyed by reserved(Identifier::MANAGEMENT), marked 0x03 {
        @field(Enabled) enabled: boolean,
        @field(PrefixLength) prefix_length: prefix_length,
        @field(Mac) mac: mac,
        @field(Address) address: ipv4,
    }
}

configuration_entity! {
    /// One `<rule>`: one line of the filter policy, keyed by the id its metric
    /// is labelled with.
    ///
    /// Every criterion is required and the wildcard is spelled `any`, so a rule
    /// says in full what it matches. A `<rules>` section's order is the policy —
    /// first match wins — which is why this is the one object whose place in
    /// the document means something.
    RuleEntry reads b"rule" as ObjectKind::Rule,
        keyed by positional, marked 0x04 {
        @field(Id) id: identifier,
        @field(Ingress) ingress: interface_match,
        @field(Egress) egress: interface_match,
        @field(Source) source: address_match,
        @field(Destination) destination: address_match,
        @field(Protocol) protocol: protocol_match,
        @field(SourcePort) source_port: port_match,
        @field(DestinationPort) destination_port: port_match,
        @field(IcmpType) icmp_type: icmp_type_match,
        @field(Action) action: action,
    }
}

/// Parse one attribute's value, reporting a refusal at the value rather than at
/// the element: the byte an operator has to go and look at is the one that did
/// not parse.
pub(crate) fn attribute_value<T>(
    attribute: &Attribute<'_>,
    parse: fn(&[u8]) -> Result<T, value::ValueError>,
) -> Result<T, DocumentError> {
    parse(attribute.value.as_bytes()).map_err(|_| DocumentError {
        fault: DocumentFault::MalformedValue,
        offset: attribute.value_offset,
    })
}

/// An attribute the schema names and the document omits, refused rather than
/// defaulted: `enabled` misspelled as `enable` is an interface an operator
/// believes is up, and there is no second channel to find out through.
pub(crate) fn required_attribute<T>(
    read: Option<T>,
    element: &Element<'_>,
) -> Result<T, DocumentError> {
    read.ok_or(DocumentError {
        fault: DocumentFault::MissingAttribute,
        offset: element.offset,
    })
}

pub(crate) fn unknown_attribute(attribute: &Attribute<'_>) -> DocumentError {
    DocumentError {
        fault: DocumentFault::UnknownAttribute,
        offset: attribute.name_offset,
    }
}

pub(crate) use {
    attribute_name, entity_key, entity_key_fn, field_probe, value_fold, value_record, value_type,
};

#[cfg(test)]
mod tests;
