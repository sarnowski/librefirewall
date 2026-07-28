//! What a call site says happened, and the closed vocabularies it says it in.

use core::fmt;

use net_headers::{Ipv4Address, MacAddress};

use crate::detail::DomainDetail;
use crate::identifier::Identifier;

/// Declares an enum whose variants, their `ALL` array and their console tokens
/// come from one list, so a variant cannot exist without a slot in `ALL` and a
/// name — the exhaustiveness a hand-written pair of the two only asks review to
/// notice.
macro_rules! closed_vocabulary {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $token:literal,)+
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)+
        }

        impl $name {
            /// Every variant, in discriminant order.
            pub const ALL: [Self; [$(stringify!($variant),)+].len()] = [$(Self::$variant,)+];

            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $token,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

closed_vocabulary! {
    /// Which protection domain an [`Event::Domain`] record is about. The names
    /// are the domain names in the Microkit system description, so a console
    /// line and the capability topology use one identity.
    Domain {
        Forwarder => "forwarder",
        NicDriver => "nic-driver",
        Config => "config",
        Console => "console",
    }
}

closed_vocabulary! {
    /// The lifecycle points a domain reports. `Negotiated` sits between the
    /// other two because a device that answered and a device whose queues are
    /// primed are different failures to be looking at: one is a bring-up
    /// handshake, the other a mapping or a pool.
    DomainState {
        Starting => "starting",
        Negotiated => "negotiated",
        Ready => "ready",
        Refused => "refused",
    }
}

closed_vocabulary! {
    ChangeKind {
        Added => "added",
        Removed => "removed",
        Modified => "modified",
    }
}

closed_vocabulary! {
    ObjectKind {
        Interface => "interface",
        Neighbour => "neighbour",
    }
}

closed_vocabulary! {
    /// Which attribute of an object changed. The tokens are the configuration
    /// document's own attribute names, so a change record points at the text an
    /// operator edits rather than at an internal field name.
    Field {
        Port => "port",
        Enabled => "enabled",
        Mac => "mac",
        Address => "address",
        PrefixLength => "prefix-length",
        Interface => "interface",
    }
}

closed_vocabulary! {
    GenerationOutcome {
        Applied => "applied",
        Refused => "refused",
        Unchanged => "unchanged",
    }
}

closed_vocabulary! {
    /// Why a configuration document was refused, at the granularity an operator
    /// acts on: each token names one thing to go and fix.
    ///
    /// The first group is the document's syntax and the hardening bounds a
    /// hostile document is held to; the second is semantic validation over the
    /// parsed model. A reason never carries the offending bytes — the record
    /// pairs it with a byte offset instead (OBS-5).
    RejectReason {
        Malformed => "malformed",
        Doctype => "doctype",
        EntityDeclaration => "entity-declaration",
        UnknownEntityReference => "unknown-entity-reference",
        InvalidCharacterReference => "invalid-character-reference",
        DocumentTooLarge => "document-too-large",
        DepthExceeded => "depth-exceeded",
        TooManyAttributes => "too-many-attributes",
        NameTooLong => "name-too-long",
        ValueTooLong => "value-too-long",
        UnexpectedCharacterData => "unexpected-character-data",
        DuplicateAttribute => "duplicate-attribute",
        UnknownElement => "unknown-element",
        UnknownAttribute => "unknown-attribute",
        MissingElement => "missing-element",
        MissingAttribute => "missing-attribute",
        MalformedValue => "malformed-value",
        DuplicateIdentifier => "duplicate-identifier",
        DuplicatePort => "duplicate-port",
        PortOutOfRange => "port-out-of-range",
        PrefixLengthOutOfRange => "prefix-length-out-of-range",
        /// The address is the prefix's network or broadcast address, which no
        /// host may hold.
        AddressNotAHostAddress => "address-not-a-host-address",
        AddressNotUnicast => "address-not-unicast",
        MacNotUnicast => "mac-not-unicast",
        OverlappingPrefixes => "overlapping-prefixes",
        UnknownInterfaceReference => "unknown-interface-reference",
        NeighbourOutsidePrefix => "neighbour-outside-prefix",
        NeighbourIsInterfaceAddress => "neighbour-is-interface-address",
        DuplicateNeighbourAddress => "duplicate-neighbour-address",
        /// More interfaces or neighbours than the handover image holds.
        CapacityExceeded => "capacity-exceeded",
    }
}

/// A value an event may carry.
///
/// Closed by construction: every variant is an already-parsed domain type, so a
/// byte string out of a configuration document has no representation here and
/// cannot reach a rendered line as itself (OBS-5). [`Value::Id`] is the one
/// route text takes, and only through [`Identifier`], whose alphabet is what
/// makes it renderable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Value {
    Port(u8),
    Ipv4(Ipv4Address),
    Mac(MacAddress),
    PrefixLength(u8),
    Bool(bool),
    Generation(u32),
    Count(u32),
    Id(Identifier),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(port) => write!(f, "{port}"),
            Self::Ipv4(address) => write!(f, "{address}"),
            Self::Mac(mac) => write!(f, "{mac}"),
            Self::PrefixLength(length) => write!(f, "{length}"),
            Self::Bool(flag) => write!(f, "{flag}"),
            Self::Generation(generation) => write!(f, "{generation}"),
            Self::Count(count) => write!(f, "{count}"),
            Self::Id(id) => f.write_str(id.as_str()),
        }
    }
}

/// One thing that happened, named rather than rendered.
///
/// A call site emits this and a [`Sink`](crate::Sink) decides how it reads. The
/// alternative — a call site that formats its own line — throws away the
/// attribute structure an OpenTelemetry record is, and there is no way to
/// recover it afterwards short of rewriting every site.
///
/// `C` is the refusal cause text in the two forms [`Refusal`](crate::Refusal)
/// documents; the default is the one a call site mints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<C = &'static str> {
    Domain {
        domain: Domain,
        state: DomainState,
        detail: DomainDetail<C>,
    },
    /// One configuration value changed as part of a commit. Unchanged values
    /// produce no record, so the volume of a commit is the size of its diff.
    ConfigChange {
        generation: u32,
        sequence: u32,
        change: ChangeKind,
        object: ObjectKind,
        key: Identifier,
        field: Field,
        /// Absent exactly when the object was added.
        from: Option<Value>,
        /// Absent exactly when the object was removed.
        to: Option<Value>,
    },
    ConfigGeneration {
        generation: u32,
        outcome: GenerationOutcome,
        changes: u32,
    },
    /// A document was refused. Names where and why, never the bytes (OBS-5).
    ConfigRejected {
        generation: u32,
        reason: RejectReason,
        offset: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// The property every console vocabulary owes an operator: `ALL` is the
    /// variants in discriminant order — so nothing is missing from the middle
    /// of it — and no two of them read the same.
    fn assert_vocabulary<const N: usize>(slots: [usize; N], names: [&str; N]) {
        for (index, slot) in slots.into_iter().enumerate() {
            assert_eq!(slot, index, "ALL is not in discriminant order");
        }
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), count, "two variants share a console token");
        assert!(
            names.iter().all(|name| !name.is_empty()),
            "a variant renders as nothing"
        );
    }

    macro_rules! check_vocabulary {
        ($name:ident) => {
            assert_vocabulary(
                $name::ALL.map(|variant| variant as usize),
                $name::ALL.map(|variant| variant.name()),
            )
        };
    }

    #[test]
    fn every_console_vocabulary_names_each_variant_once() {
        check_vocabulary!(Domain);
        check_vocabulary!(DomainState);
        check_vocabulary!(ChangeKind);
        check_vocabulary!(ObjectKind);
        check_vocabulary!(Field);
        check_vocabulary!(GenerationOutcome);
        check_vocabulary!(RejectReason);
    }

    #[test]
    fn a_vocabulary_displays_as_its_console_token() {
        for reason in RejectReason::ALL {
            assert_eq!(std::format!("{reason}"), reason.name());
        }
        assert_eq!(std::format!("{}", Domain::NicDriver), "nic-driver");
        assert_eq!(std::format!("{}", Field::PrefixLength), "prefix-length");
    }

    #[test]
    fn every_value_variant_renders_its_own_shape() {
        let id = Identifier::new(b"wan").expect("the alphabet accepts it");
        let cases = [
            (Value::Port(3), "3"),
            (
                Value::Ipv4(Ipv4Address::from_octets([10, 0, 0, 1])),
                "10.0.0.1",
            ),
            (
                Value::Mac(MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50])),
                "52:54:00:12:34:50",
            ),
            (Value::PrefixLength(24), "24"),
            (Value::Bool(true), "true"),
            (Value::Bool(false), "false"),
            (Value::Generation(7), "7"),
            (Value::Count(0), "0"),
            (Value::Id(id), "wan"),
        ];
        for (value, expected) in cases {
            assert_eq!(std::format!("{value}"), expected);
        }
    }
}
