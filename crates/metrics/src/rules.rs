//! The identity of each rule the running policy declares, which is the per-rule
//! hit family's one label.
//!
//! # Why identity travels separately from the number
//!
//! A rule's hit counter is written by the forwarding domain into its own shard,
//! at the slot its **position** in the running generation gives it. Its `rule`
//! label is text, and no domain counts text: the id comes out of the committed
//! configuration, which the management domain maps read-only. So the two halves
//! of one series arrive from two places and are joined on the position — a
//! number only the forwarder could have written under an id only the
//! configuration could have named, which is the same argument the `domain` label
//! rests on.
//!
//! That join is also why a position no generation declared exposes nothing.
//! The shard reserves a slot for every rule the ABI admits, and the running
//! document says how many of them mean anything; a series for the rest would be
//! a counter under no operator's name.

use wire::{CheckedIdentifier, MAX_RULES};

/// Series the per-rule hit family can carry, and so the bound on its
/// cardinality: one per rule a generation may declare.
///
/// The configuration ABI's own bound rather than a number chosen here. It is
/// what the exposition is sized by, so a policy an operator is entitled to write
/// can never be one the endpoint cannot answer for.
pub const MAX_RULE_SERIES: usize = MAX_RULES;

/// The inventory is full. Unreachable from a checked configuration image, which
/// holds at most [`MAX_RULES`] rules; a typed error rather than a silently
/// dropped series all the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RulesFull;

/// Every rule the committed generation declares, in document order — which is
/// the order the filter decides in *and* the order its counters sit in.
///
/// A fixed array with `Option` slots filled from the front, so a slot's index is
/// the rule's position and the length is carried by the data. `Copy`, on
/// [`InterfaceInventory`](crate::InterfaceInventory)'s terms: a snapshot holds
/// one and the endpoint that renders it owns it outright.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleInventory {
    ids: [Option<CheckedIdentifier>; MAX_RULE_SERIES],
}

impl RuleInventory {
    /// No rule at all, which is what generation 0 — the fail-closed empty
    /// configuration — declares, and what a node that has committed none is in.
    /// Under default deny that posture forwards nothing, and it exposes no rule
    /// series to say so: the counter that moves is the default deny's.
    pub const EMPTY: Self = Self {
        ids: [None; MAX_RULE_SERIES],
    };

    /// Append the rule at the next position.
    ///
    /// # Errors
    /// [`RulesFull`] once [`MAX_RULE_SERIES`] rules are held.
    pub fn push(&mut self, id: CheckedIdentifier) -> Result<(), RulesFull> {
        match self.ids.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(id);
                Ok(())
            }
            None => Err(RulesFull),
        }
    }

    /// Every declared rule with the position its counter occupies, which is what
    /// the renderer walks.
    pub fn entries(&self) -> impl Iterator<Item = (usize, CheckedIdentifier)> {
        self.ids
            .iter()
            .enumerate()
            .filter_map(|(position, id)| id.map(|id| (position, id)))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries().count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RuleInventory {
    fn default() -> Self {
        Self::EMPTY
    }
}
