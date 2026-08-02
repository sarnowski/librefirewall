//! Turning a configuration document into a running configuration, or refusing
//! it: the reader, the rules, the datastore that versions what passed them, and
//! the handover image a dataplane is given.
//!
//! Reading the document is two steps that never mix: [`schema::parse`] decides
//! what the bytes *say* and produces a [`Model`], and [`validate::validate`]
//! decides whether what they say is something this appliance can hold. Keeping
//! them apart is what makes each one reviewable — a syntax rule cannot come to
//! depend on an address, and a topology rule cannot come to depend on where in
//! the file something was written. Everything downstream reads the model and
//! never the bytes, which is what leaves an operator free to reformat a
//! document without committing anything ([`hash`], [`diff`]).
//!
//! # Adversary
//!
//! The management-plane attacker. Today the document arrives
//! compiled into the image, which makes the threat theoretical; it is written
//! against a fully attacker-controlled byte string anyway, because the whole
//! reason this crate is separate from the domain that applies its output is
//! that the document will one day arrive over a network, and a parser hardened
//! afterwards is a parser rewritten.
//!
//! # Constraints, and what was given up to meet them
//!
//! * **No allocator.** The crate is `no_std` with nothing behind it, so the
//!   model is a fixed-capacity value sized by [`wire::MAX_INTERFACES`] and
//!   [`wire::MAX_NEIGHBOURS`], and a document naming more objects than that is
//!   refused rather than truncated.
//! * **Not quite zero-copy, in one place.** Names are borrowed out of the
//!   document, but an attribute value is expanded into a fixed buffer: a
//!   reference does not appear in the document as the bytes it means, so there
//!   is nothing there to borrow. Refusing references instead would have kept
//!   the borrow and made some legal identifiers unwritable.
//! * **No `Display` for a rejection.** Every error names a position or an
//!   already-parsed [`Identifier`] and never the offending attacker-chosen bytes, and
//!   rendering one is [`lfw_log`]'s business rather than this crate's.
//! * **The document's own vocabulary is closed.** An element or attribute the
//!   schema does not name is refused; nothing is skipped, and nothing is
//!   defaulted. A misspelling an operator cannot see is the failure this is
//!   built to prevent, there being no shell and no second channel to discover
//!   it through.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod diff;
pub mod hash;
pub mod model;
pub mod report;
pub mod runtime;
pub mod schema;
pub mod store;
pub mod validate;
pub mod value;
pub mod xml;

use lfw_log::RejectReason;

pub use diff::{Change, DiffSummary, diff};
pub use hash::{ContentHash, content_hash};
pub use lfw_log::Identifier;
pub use model::{Full, InterfaceEntry, Model, NeighbourEntry};
pub use report::{CommitReport, commit_and_report};
pub use runtime::{BuildError, image_from};
pub use schema::parse;
pub use store::{CommitError, CommitOutcome, Datastore, Generation, Staged};
pub use validate::{SemanticError, validate};
pub use value::ValueError;
pub use xml::{
    Attribute, AttributeValue, DocumentError, DocumentFault, Element, Event,
    MAX_ATTRIBUTE_VALUE_LEN, MAX_ATTRIBUTES, MAX_DEPTH, MAX_DOCUMENT_BYTES, MAX_NAME_LEN, Reader,
};

/// How many dataplane ports this build has, and so the ports a configuration
/// may name.
///
/// A property of the build rather than of the document: it is what the system
/// description declares driver instances for, so a document naming port 2 is
/// naming hardware that is not there.
pub const PORT_COUNT: u8 = 2;

/// Why a document was refused, from either half of reading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Document(DocumentError),
    Semantic(SemanticError),
}

impl ConfigError {
    /// The token an operator reads. There is deliberately no `offset()` beside
    /// it: only half of these rejections have one, and a semantic refusal
    /// reporting offset zero would be pointing at a byte that has nothing to do
    /// with it. A caller that needs both takes them from the variant, where the
    /// document half carries a position and the semantic half carries an id.
    #[must_use]
    pub const fn reason(self) -> RejectReason {
        match self {
            Self::Document(error) => error.reason(),
            Self::Semantic(error) => error.reason(),
        }
    }
}

/// Read a document and hold it to every rule.
///
/// # Errors
/// [`ConfigError`], from whichever half refused it first.
pub fn load(document: &[u8]) -> Result<Model, ConfigError> {
    let model = parse(document).map_err(ConfigError::Document)?;
    validate(&model).map_err(ConfigError::Semantic)?;
    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The canonical contract configuration document, which must survive both halves.
    const CONTRACT_DOCUMENT: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<configuration>\n",
        "  <interfaces>\n",
        "    <interface id=\"wan\" port=\"0\" enabled=\"true\"\n",
        "               mac=\"52:54:00:12:34:50\" address=\"10.0.0.1\" prefix-length=\"24\"/>\n",
        "  </interfaces>\n",
        "  <neighbours>\n",
        "    <neighbour id=\"gateway-a\" interface=\"wan\"\n",
        "               address=\"10.0.0.2\" mac=\"52:54:00:00:00:0a\"/>\n",
        "  </neighbours>\n",
        "  <management mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\"\n",
        "              prefix-length=\"24\" enabled=\"true\"/>\n",
        "</configuration>\n"
    );

    #[test]
    fn the_contract_document_survives_both_halves() {
        let model = load(CONTRACT_DOCUMENT.as_bytes()).expect("the contract document");
        assert_eq!(model.interface_count(), 1);
        assert_eq!(model.neighbour_count(), 1);
    }

    #[test]
    fn a_document_fault_and_a_semantic_fault_are_distinguishable_and_both_carry_a_reason() {
        let malformed = load(b"<configuration>").expect_err("unclosed");
        assert!(matches!(malformed, ConfigError::Document(_)));
        assert_eq!(malformed.reason(), RejectReason::Malformed);

        let unresolvable = CONTRACT_DOCUMENT.replacen("interface=\"wan\"", "interface=\"dmz\"", 1);
        let semantic = load(unresolvable.as_bytes()).expect_err("dangling reference");
        assert!(matches!(semantic, ConfigError::Semantic(_)));
        assert_eq!(semantic.reason(), RejectReason::UnknownInterfaceReference);
    }

    #[test]
    fn a_document_is_parsed_before_it_is_judged() {
        // Both halves would refuse this one: the reader will not read it at
        // all, so the semantic rules never see a model to judge.
        let both = load(b"<!DOCTYPE x><configuration/>").expect_err("a doctype");
        assert_eq!(both.reason(), RejectReason::Doctype);
    }

    /// The management element crosses both halves too: the reader gives it to
    /// the model and the rules hold it apart from the dataplane.
    #[test]
    fn a_management_interface_colliding_with_a_dataplane_prefix_is_refused_by_the_rules() {
        let collides = CONTRACT_DOCUMENT.replacen("192.168.42.15", "10.0.0.9", 1);
        let error = load(collides.as_bytes()).expect_err("one address, two ways to reach it");
        assert!(matches!(error, ConfigError::Semantic(_)));
        assert_eq!(error.reason(), RejectReason::OverlappingPrefixes);
    }

    #[test]
    fn the_port_count_is_what_the_build_has_rather_than_what_a_document_claims() {
        let past_the_ports =
            CONTRACT_DOCUMENT.replacen("port=\"0\"", &std::format!("port=\"{PORT_COUNT}\""), 1);
        assert_eq!(
            load(past_the_ports.as_bytes())
                .expect_err("port 2 is not on this build")
                .reason(),
            RejectReason::PortOutOfRange
        );
    }

    proptest! {
        /// The headline property: reading a document is total. Arbitrary bytes
        /// yield either a model that satisfies every rule or one typed reason,
        /// and never a panic.
        #[test]
        fn loading_arbitrary_bytes_is_total(
            bytes in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            match load(&bytes) {
                Ok(model) => {
                    prop_assert!(model.interface_count() <= wire::MAX_INTERFACES);
                    prop_assert!(model.neighbour_count() <= wire::MAX_NEIGHBOURS);
                    prop_assert!(validate(&model).is_ok());
                }
                Err(error) => {
                    prop_assert!(RejectReason::ALL.contains(&error.reason()));
                }
            }
        }

        /// The same over bytes that reach the schema, and deterministic with it.
        #[test]
        fn loading_document_shaped_text_is_total_and_deterministic(
            text in r#"[<>/?!&;="'a-z0-9 \n#.:-]{0,400}"#,
        ) {
            prop_assert_eq!(load(text.as_bytes()), load(text.as_bytes()));
        }
    }
}
