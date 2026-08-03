//! The rules a configuration is held to, named once so that both sides of the
//! handover can be made to answer for each of them.
//!
//! Every rule about a configuration is decided twice: once over the parsed
//! model, in the domain that reads an attacker's document, and once over the
//! byte image, in the domain that will forward under it. That duplication is
//! deliberate and is not being removed — a rule only the parsing domain
//! enforced is a rule a compromise of that domain lifts, which is the whole
//! reason the two domains are separate. What it costs is that the two rule sets
//! are parallel structures with nothing but review holding them together, and
//! review is exactly what a thirty-first rule slips past.
//!
//! [`ConfigRule`] is that list, written once. Each side answers, exhaustively,
//! what it does about every rule on it, so a rule added here does not compile
//! until both sides have been told about it. Neither answer is a claim that the
//! rule is *correct*, and neither is generated from the code that enforces it:
//! what the compiler guarantees is that no rule can be added to one side alone,
//! which is the failure this list exists to make impossible. That the answers
//! are true of the running code is a property, held by the differential tests
//! that put arbitrary images through both sides.

/// What one side of the handover does about one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enforcement {
    /// The side refuses a configuration that breaks the rule, and names which
    /// one it broke.
    Refuses,
    /// Refused, but only of an entry that is enabled: a disabled one leaves
    /// every other field of itself uninterpreted, so there is no value left for
    /// a rule to be about.
    RefusesWhenEnabled,
    /// The rule cannot be broken on this side, because no value there can
    /// express breaking it — a decoded `bool`, a checked identifier, an array
    /// with no room for one more entry.
    Unrepresentable,
    /// The side cannot decide the rule at all. Every use of this is an
    /// asymmetry between the two sides and carries its reason where it is
    /// written.
    CannotDecide,
}

/// One list, one arm per rule, so the enum and the array cannot come apart.
macro_rules! config_rules {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            $($(#[$rule_meta:meta])* $rule:ident,)+
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$rule_meta])* $rule,)+
        }

        impl $name {
            /// Every rule, in declaration order.
            pub const ALL: [Self; [$(stringify!($rule),)+].len()] = [$(Self::$rule,)+];
        }
    };
}

config_rules! {
    /// Every rule a configuration is held to, whichever side decides it.
    ///
    /// A rule is one thing an operator can go and fix, at the granularity a
    /// refusal names — so a rule here is not a function, and neither side is
    /// obliged to have a function per rule. Names are prefixed by the object
    /// they are about, because two objects held to the same-sounding rule are
    /// held to it against different values.
    ConfigRule {
        /// More interfaces than the image has slots for.
        InterfaceCountWithinCapacity,
        /// More neighbours than the image has slots for.
        NeighbourCountWithinCapacity,

        InterfaceEnabledIsBoolean,
        InterfaceIdIsWellFormed,
        InterfacePortExists,
        InterfacePrefixLengthInRange,
        InterfaceMacIsUnicast,
        InterfaceAddressIsUnicast,
        InterfaceAddressIsAHostAddress,
        InterfaceIdIsUnique,
        InterfacePortIsUnique,
        InterfaceMacIsUnique,
        InterfacePrefixesDoNotOverlap,

        /// The interface a neighbour names is one the configuration has.
        NeighbourInterfaceResolves,
        NeighbourPortExists,
        NeighbourMacIsUnicast,
        NeighbourAddressIsUnicast,
        NeighbourAddressIsAHostAddress,
        NeighbourIsInsideItsPrefix,
        NeighbourIsNotTheInterfaceAddress,
        NeighbourAddressIsUnique,
        /// Two neighbours under one id, which is the one rule the image cannot
        /// re-decide.
        NeighbourIdIsUnique,

        ManagementEnabledIsBoolean,
        ManagementPrefixLengthInRange,
        ManagementMacIsUnicast,
        ManagementAddressIsUnicast,
        ManagementAddressIsAHostAddress,
        ManagementPrefixDoesNotCollideWithInterface,
        ManagementMacDoesNotCollideWithInterface,

        /// More filter rules than the image has slots for.
        RuleCountWithinCapacity,
        RuleIdIsWellFormed,
        RuleIdIsUnique,
        RuleActionIsKnown,
        /// A criterion is stated or it is not; there is no third byte.
        RuleCriterionIsStatedOrNot,
        /// The interface a rule's `ingress` names is one the configuration has,
        /// and the same for its `egress`.
        RuleIngressResolves,
        RuleEgressResolves,
        RulePrefixLengthInRange,
        /// A block written as the block it names, rather than with host bits an
        /// operator would read back as part of the address.
        RulePrefixIsCanonical,
        RulePortRangeIsOrdered,
        /// A port criterion on a rule that names ICMP.
        RuleNoPortCriterionOnIcmp,
        /// An ICMP type criterion on a rule that names another protocol.
        RuleNoIcmpTypeOnAnotherProtocol,

        /// The appliance can state the configuration back as a document it would
        /// itself accept.
        ///
        /// The one rule here about the configuration as a whole rather than about
        /// an object in it, and the one whose subject is the *appliance* rather
        /// than the document: a configuration whose canonical form outgrows the
        /// document bound is one a node could commit and then be unable to answer
        /// `GET /config` with. Reading the running configuration is the first step
        /// of changing it, so a policy an operator can read and cannot resubmit is
        /// one they cannot edit.
        ConfigurationIsStatable,
    }
}

impl ConfigRule {
    /// What the byte image's own checker does about this rule.
    ///
    /// Exhaustive, which is the point: a rule added to the list above does not
    /// compile until this side has said what it does about it.
    #[must_use]
    pub const fn image_enforcement(self) -> Enforcement {
        match self {
            Self::InterfaceCountWithinCapacity
            | Self::NeighbourCountWithinCapacity
            | Self::InterfaceEnabledIsBoolean
            | Self::InterfaceIdIsWellFormed
            | Self::InterfacePortExists
            | Self::InterfacePrefixLengthInRange
            | Self::InterfaceMacIsUnicast
            | Self::InterfaceAddressIsUnicast
            | Self::InterfaceAddressIsAHostAddress
            | Self::InterfaceIdIsUnique
            | Self::InterfacePortIsUnique
            | Self::InterfaceMacIsUnique
            | Self::InterfacePrefixesDoNotOverlap
            | Self::NeighbourInterfaceResolves
            | Self::NeighbourPortExists
            | Self::NeighbourMacIsUnicast
            | Self::NeighbourAddressIsUnicast
            | Self::NeighbourAddressIsAHostAddress
            | Self::NeighbourIsInsideItsPrefix
            | Self::NeighbourIsNotTheInterfaceAddress
            | Self::NeighbourAddressIsUnique
            | Self::ManagementEnabledIsBoolean
            | Self::RuleCountWithinCapacity
            | Self::RuleIdIsWellFormed
            | Self::RuleIdIsUnique
            | Self::RuleActionIsKnown
            | Self::RuleCriterionIsStatedOrNot
            | Self::RuleIngressResolves
            | Self::RuleEgressResolves
            | Self::RulePrefixLengthInRange
            | Self::RulePrefixIsCanonical
            | Self::RulePortRangeIsOrdered
            | Self::RuleNoPortCriterionOnIcmp
            | Self::RuleNoIcmpTypeOnAnotherProtocol => Enforcement::Refuses,

            // A disabled management entry is refused for nothing: `enabled == 0`
            // leaves every other field of it uninterpreted, so a zeroed region
            // — the fail-closed generation every domain starts under — stays a
            // valid image. The model side has the enable flag *and* the values
            // beside it, so it holds a disabled entry to these anyway; that
            // asymmetry is what these four words record.
            Self::ManagementPrefixLengthInRange
            | Self::ManagementMacIsUnicast
            | Self::ManagementAddressIsUnicast
            | Self::ManagementAddressIsAHostAddress
            | Self::ManagementPrefixDoesNotCollideWithInterface
            | Self::ManagementMacDoesNotCollideWithInterface => Enforcement::RefusesWhenEnabled,

            // A neighbour's identity is absent from the image — the entry
            // carries a port, a MAC and an address — so two neighbours under
            // one id are indistinguishable here. Nothing downstream of the
            // image consumes such an id, so nothing downstream can be misled by
            // one; it is a handle for editing the document.
            //
            // And whether the configuration can be *stated back* is a question
            // about the document form, which is the reading domain's business and
            // not this one's: the image is the model as POD and carries no
            // rendering. The asymmetry costs the consumer nothing, and that is the
            // test of whether an asymmetry is admissible here — a rule the image
            // cannot decide is one a compromise of the reader lifts, so it may only
            // ever be a rule the *consumer has no stake in*. This one is about
            // whether an operator can read the policy back, which decides no frame.
            Self::NeighbourIdIsUnique | Self::ConfigurationIsStatable => Enforcement::CannotDecide,
        }
    }
}

/// The image side re-decides every rule but one, and that one is named where it
/// is declared. A rule that quietly became undecidable here would be a rule a
/// compromised writer could break with nothing downstream noticing, so the
/// count is a compile error rather than a claim in a comment.
const _: () = {
    let mut index = 0;
    let mut undecidable = 0;
    while index < ConfigRule::ALL.len() {
        if matches!(
            ConfigRule::ALL[index].image_enforcement(),
            Enforcement::CannotDecide
        ) {
            undecidable += 1;
        }
        index += 1;
    }
    assert!(undecidable == 2);
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, vec::Vec};

    #[test]
    fn every_rule_appears_once_in_the_list_and_answers_for_itself() {
        let named: BTreeSet<ConfigRule> = ConfigRule::ALL.into_iter().collect();
        assert_eq!(named.len(), ConfigRule::ALL.len(), "a rule is listed twice");
        for rule in ConfigRule::ALL {
            // The answer is a total function, which the exhaustive match makes
            // true by construction; this is what fails if it ever stops being.
            let _ = rule.image_enforcement();
        }
    }

    /// The image cannot invent an enforcement it does not have, and the two rules
    /// it cannot decide are named: a neighbour's identity, which the image does not
    /// carry, and whether the configuration can be stated back, which is a question
    /// about a document form the image is not one of.
    ///
    /// Both are admissible for the same reason and it is the only reason that ever
    /// makes one admissible: the consumer has no stake in either. A rule the image
    /// cannot re-decide is a rule a compromise of the reading domain lifts, so it
    /// may only ever be a rule about something that decides no frame.
    #[test]
    fn the_rules_the_image_cannot_decide_are_the_two_the_consumer_has_no_stake_in() {
        let undecidable: Vec<ConfigRule> = ConfigRule::ALL
            .into_iter()
            .filter(|rule| rule.image_enforcement() == Enforcement::CannotDecide)
            .collect();
        assert_eq!(
            undecidable,
            [
                ConfigRule::NeighbourIdIsUnique,
                ConfigRule::ConfigurationIsStatable
            ]
        );
    }

    /// Only the management entry's rules are conditional on an enable flag,
    /// because it is the only entry whose absence is expressed by one.
    #[test]
    fn only_the_management_entry_is_held_to_its_rules_conditionally() {
        for rule in ConfigRule::ALL {
            if rule.image_enforcement() == Enforcement::RefusesWhenEnabled {
                assert!(
                    std::format!("{rule:?}").starts_with("Management"),
                    "{rule:?} is conditional on an enable flag it does not have"
                );
            }
        }
    }
}
