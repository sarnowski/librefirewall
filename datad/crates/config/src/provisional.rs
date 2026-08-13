//! The provisional-commit lifecycle: a commit that can still be undone, the
//! confirmation that makes it permanent, and the rollback that puts back what it
//! displaced.
//!
//! Its own module rather than more of [`crate::store`], because it is the one part
//! of the datastore whose correctness is about *time* rather than about a
//! document: a commit is applied at once and is only settled later, and what
//! settles it is a fact about connections that this crate cannot see. So the
//! store holds the displaced configuration and the two operations over it, and the
//! deadline lives with whoever holds the sessions.
//!
//! # At most one, which is what makes a rollback one step
//!
//! A commit made while one is outstanding takes the earlier one's place as the
//! thing that can be undone, so there is never a chain of undos to walk and never
//! a history to bound. Losing the ability to undo an unconfirmed change by making
//! another is the right trade: the second commit is a decision, and an operator
//! who makes one has taken responsibility for what it replaced.

use crate::{
    diff::{Records, diff},
    hash::ContentHash,
    model::Model,
    store::{CommitError, CommitOutcome, Datastore, Generation},
};

/// Why a confirmation or a rollback did not happen.
///
/// Its own vocabulary rather than [`CommitError`]'s, because the two act on
/// different things: a commit acts on a candidate and these act on a commit
/// already made. Folding them would give an operator one token covering "you
/// staged nothing" and "you have nothing to confirm", which are different
/// mistakes with different next steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionalError {
    /// No provisional commit is outstanding — either none was made, or the one
    /// that was has already been confirmed or rolled back.
    NotProvisional,
    /// A confirmation naming a generation that is not the provisional one.
    /// `provisional` is the generation actually awaiting confirmation.
    ///
    /// Refused rather than taken as a confirmation of whatever is outstanding: a
    /// server that has lost track of which commit it made must not be allowed to
    /// make a stale confirmation permanent, that being precisely the state
    /// commit-confirm exists to catch.
    GenerationMismatch { provisional: Generation },
    /// A rollback that would need a generation the counter cannot assign. The
    /// provisional commit survives, so a store whose counter was rescued still
    /// rolls back.
    GenerationsExhausted { latest: Generation },
}

/// The configuration a provisional commit displaced, kept so it can be put back.
///
/// Held as a model rather than as a document: the bytes a commit was read from
/// are not kept ([`Datastore`]'s header says why), and a model is what a commit
/// and an artifact build both take their input from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Displaced {
    /// The generation the provisional commit assigned, which is the generation a
    /// confirmation must name.
    pub(crate) provisional: Generation,
    /// What was running before it, to go back to.
    pub(crate) generation: Generation,
    pub(crate) hash: ContentHash,
    pub(crate) model: Model,
}

/// What a rollback put back in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RolledBack {
    /// The generation the restored configuration now runs under — a new one, not
    /// the number it had before: a configuration going back into force is a
    /// change the dataplane takes like any other, and its handover admits only a
    /// strictly newer generation.
    pub generation: Generation,
    /// The provisional generation that was given up.
    pub abandoned: Generation,
    /// Values the restoration moved, as the diff counted them.
    pub changes: usize,
}

impl Datastore {
    /// Make the candidate the running configuration **provisionally**: what it
    /// displaces is kept until [`Datastore::confirm`] gives it up or
    /// [`Datastore::roll_back`] puts it back.
    ///
    /// A commit that assigned no generation — the content was already running —
    /// leaves nothing provisional, and that is the whole of the difference: there
    /// is nothing to undo, so there is nothing to confirm either, and a caller
    /// that armed a deadline on it would roll back a configuration that never
    /// changed.
    ///
    /// # Errors
    /// [`CommitError`], exactly as [`Datastore::commit`] would have refused it,
    /// and leaving whatever was already provisional in place: a commit that did
    /// not happen has displaced nothing.
    pub fn commit_provisionally(
        &mut self,
        records: &mut dyn Records,
    ) -> Result<CommitOutcome, CommitError> {
        self.apply(records, true)
    }

    /// Keep the provisional commit `generation` names, giving up what it
    /// displaced.
    ///
    /// # Errors
    /// [`ProvisionalError::NotProvisional`] with nothing outstanding, and
    /// [`ProvisionalError::GenerationMismatch`] for a confirmation of another
    /// generation — which leaves the provisional commit outstanding, so the
    /// deadline it was made under still rolls it back.
    pub fn confirm(&mut self, generation: Generation) -> Result<Generation, ProvisionalError> {
        let displaced = self.displaced.ok_or(ProvisionalError::NotProvisional)?;
        if displaced.provisional != generation {
            return Err(ProvisionalError::GenerationMismatch {
                provisional: displaced.provisional,
            });
        }
        self.displaced = None;
        Ok(displaced.provisional)
    }

    /// The generation awaiting confirmation, or `None` where none is.
    #[must_use]
    pub const fn provisional(&self) -> Option<Generation> {
        match self.displaced {
            Some(Displaced { provisional, .. }) => Some(provisional),
            None => None,
        }
    }

    /// The generation a commit would assign, or `None` where the counter has no
    /// successor.
    ///
    /// The same number [`Datastore::stage`] hands back, answered without staging
    /// anything: a caller that commits as a separate request holds it to the
    /// generation the staging named, and one fact beats two.
    #[must_use]
    pub const fn next_generation(&self) -> Option<Generation> {
        let next = self.generation.next();
        if next.to_bits() == self.generation.to_bits() {
            None
        } else {
            Some(next)
        }
    }

    /// The candidate, or `None` where nothing is staged.
    #[must_use]
    pub const fn candidate_model(&self) -> Option<Model> {
        self.candidate
    }

    /// The configuration the outstanding provisional commit displaced, or `None`
    /// where no commit is awaiting confirmation.
    #[must_use]
    pub const fn displaced_model(&self) -> Option<Model> {
        match self.displaced {
            Some(Displaced { model, .. }) => Some(model),
            None => None,
        }
    }

    /// Put the configuration the provisional commit displaced back in force,
    /// under a new generation, handing every value that moved to `records`.
    ///
    /// The candidate is left alone: it is a version somebody staged and the
    /// rollback says nothing about it, so a commit after a rollback still has
    /// something to commit.
    ///
    /// # Errors
    /// [`ProvisionalError::NotProvisional`] with nothing outstanding, and
    /// [`ProvisionalError::GenerationsExhausted`] where the counter has no
    /// successor — which keeps the provisional commit, so nothing is lost.
    pub fn roll_back(&mut self, records: &mut dyn Records) -> Result<RolledBack, ProvisionalError> {
        let displaced = self.displaced.ok_or(ProvisionalError::NotProvisional)?;
        let generation = self.generation.next();
        if generation == self.generation {
            return Err(ProvisionalError::GenerationsExhausted {
                latest: self.generation,
            });
        }
        let changes = diff(&self.model, &displaced.model, records);
        self.generation = generation;
        self.hash = displaced.hash;
        self.model = displaced.model;
        self.displaced = None;
        Ok(RolledBack {
            generation,
            abandoned: displaced.provisional,
            changes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitOutcome, diff::Change};
    use lfw_log::GenerationOutcome;
    use proptest::prelude::*;
    use std::{format, string::String, vec::Vec};

    /// One interface whose address `variant` chooses, so two variants are two
    /// configurations rather than two spellings of one.
    fn document(variant: usize) -> String {
        format!(
            "<configuration><interfaces>\
             <interface id=\"wan\" port=\"0\" enabled=\"true\" \
             mac=\"52:54:00:00:00:01\" address=\"10.0.{variant}.1\" prefix-length=\"24\"/>\
             </interfaces><neighbours/><rules/><management enabled=\"true\" \
             mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" prefix-length=\"24\" \
             gateway=\"none\"/></configuration>"
        )
    }

    fn discard() -> impl Records {
        |_change: Change| {}
    }

    /// A store running `variant` and nothing provisional.
    fn running(variant: usize) -> Datastore {
        let mut store = Datastore::new();
        store.stage(document(variant).as_bytes()).expect("sound");
        store.commit(&mut discard()).expect("a candidate");
        store
    }

    /// Stage `variant` and commit it provisionally.
    fn provisionally(store: &mut Datastore, variant: usize) -> CommitOutcome {
        store.stage(document(variant).as_bytes()).expect("sound");
        store
            .commit_provisionally(&mut discard())
            .expect("a candidate")
    }

    #[test]
    fn a_provisional_commit_is_in_force_and_still_undoable() {
        let mut store = running(0);
        let outcome = provisionally(&mut store, 1);

        assert_eq!(outcome.outcome(), GenerationOutcome::Applied);
        assert_eq!(store.running(), Generation::from_bits(2));
        assert_eq!(store.provisional(), Some(Generation::from_bits(2)));
        // What it displaced is what a rollback would put back.
        assert!(store.displaced_model().is_some());
    }

    #[test]
    fn confirming_gives_up_the_configuration_the_commit_displaced() {
        let mut store = running(0);
        provisionally(&mut store, 1);

        assert_eq!(
            store.confirm(Generation::from_bits(2)),
            Ok(Generation::from_bits(2))
        );
        assert_eq!(store.provisional(), None);
        assert!(store.displaced_model().is_none());
        // And nothing can be put back afterwards, which is the whole of what
        // confirming means.
        assert_eq!(
            store.roll_back(&mut discard()),
            Err(ProvisionalError::NotProvisional)
        );
        assert_eq!(store.running(), Generation::from_bits(2));
    }

    #[test]
    fn a_confirmation_of_another_generation_leaves_the_commit_outstanding() {
        let mut store = running(0);
        provisionally(&mut store, 1);

        assert_eq!(
            store.confirm(Generation::from_bits(7)),
            Err(ProvisionalError::GenerationMismatch {
                provisional: Generation::from_bits(2),
            })
        );
        // Still undoable, so the deadline it was made under still means something.
        assert_eq!(store.provisional(), Some(Generation::from_bits(2)));
        let rolled = store.roll_back(&mut discard()).expect("still outstanding");
        assert_eq!(rolled.abandoned, Generation::from_bits(2));
    }

    #[test]
    fn a_rollback_puts_the_previous_configuration_back_under_a_new_generation() {
        let mut store = running(0);
        let before = *store.running_model();
        let hash = store.running_hash();
        provisionally(&mut store, 1);

        let rolled = store.roll_back(&mut discard()).expect("outstanding");

        // A NEW generation, not the old number: the dataplane's handover admits
        // only a strictly newer one, so going back is a change like any other.
        assert_eq!(rolled.generation, Generation::from_bits(3));
        assert_eq!(rolled.abandoned, Generation::from_bits(2));
        assert!(rolled.changes > 0);
        assert_eq!(store.running(), Generation::from_bits(3));
        assert_eq!(*store.running_model(), before);
        assert_eq!(store.running_hash(), hash);
        assert_eq!(store.provisional(), None);
    }

    #[test]
    fn a_rollback_hands_out_every_value_it_moved() {
        let mut store = running(0);
        provisionally(&mut store, 1);

        let mut moved: Vec<Change> = Vec::new();
        let rolled = store
            .roll_back(&mut |change: Change| moved.push(change))
            .expect("outstanding");

        assert_eq!(moved.len(), rolled.changes);
        assert_eq!(rolled.changes, 1, "only the address went back");
    }

    #[test]
    fn nothing_is_confirmable_or_undoable_before_a_provisional_commit() {
        let mut store = running(0);

        assert_eq!(store.provisional(), None);
        assert_eq!(
            store.confirm(Generation::from_bits(1)),
            Err(ProvisionalError::NotProvisional)
        );
        assert_eq!(
            store.roll_back(&mut discard()),
            Err(ProvisionalError::NotProvisional)
        );
        // A plain commit is never provisional, whichever way round the two are
        // used.
        store.stage(document(1).as_bytes()).expect("sound");
        store.commit(&mut discard()).expect("a candidate");
        assert_eq!(store.provisional(), None);
    }

    /// A commit whose content was already running displaces nothing, so there is
    /// nothing to confirm — and a caller that armed a deadline on it would revert
    /// a configuration that never moved.
    #[test]
    fn a_provisional_commit_of_the_running_content_leaves_nothing_outstanding() {
        let mut store = running(0);
        let outcome = provisionally(&mut store, 0);

        assert_eq!(
            outcome,
            CommitOutcome::Unchanged {
                generation: Generation::from_bits(1)
            }
        );
        assert_eq!(store.provisional(), None);
    }

    /// Committing over an unconfirmed change is a decision, so what the earlier
    /// commit displaced is given up and the new one is what a rollback undoes.
    #[test]
    fn a_plain_commit_over_a_provisional_one_settles_it() {
        let mut store = running(0);
        provisionally(&mut store, 1);
        store.stage(document(2).as_bytes()).expect("sound");
        store.commit(&mut discard()).expect("a candidate");

        assert_eq!(store.provisional(), None);
        assert_eq!(store.running(), Generation::from_bits(3));
    }

    /// And a second provisional commit takes the first one's place: at most one is
    /// outstanding, which is what makes a rollback one step.
    #[test]
    fn a_second_provisional_commit_displaces_the_first_as_the_undoable_one() {
        let mut store = running(0);
        provisionally(&mut store, 1);
        let second = *store.running_model();
        provisionally(&mut store, 2);

        assert_eq!(store.provisional(), Some(Generation::from_bits(3)));
        let rolled = store.roll_back(&mut discard()).expect("outstanding");
        assert_eq!(rolled.abandoned, Generation::from_bits(3));
        // Back to generation 2's configuration and not to generation 1's.
        assert_eq!(*store.running_model(), second);
    }

    #[test]
    fn an_exhausted_counter_refuses_a_rollback_and_keeps_the_commit() {
        let mut store = running(0);
        provisionally(&mut store, 1);
        store.generation = Generation::from_bits(u32::MAX);

        assert_eq!(
            store.roll_back(&mut discard()),
            Err(ProvisionalError::GenerationsExhausted {
                latest: Generation::from_bits(u32::MAX),
            })
        );
        assert_eq!(store.provisional(), Some(Generation::from_bits(2)));
        // A store whose counter was rescued still rolls back.
        store.generation = Generation::from_bits(5);
        assert_eq!(
            store
                .roll_back(&mut discard())
                .expect("nothing happened to it")
                .generation,
            Generation::from_bits(6)
        );
    }

    #[test]
    fn the_next_generation_is_the_one_a_commit_assigns() {
        let mut store = running(0);
        assert_eq!(store.next_generation(), Some(Generation::from_bits(2)));
        let staged = store.stage(document(1).as_bytes()).expect("sound");
        assert_eq!(store.next_generation(), Some(staged.generation));

        store.generation = Generation::from_bits(u32::MAX);
        assert_eq!(store.next_generation(), None);
    }

    #[test]
    fn a_rollback_leaves_a_staged_candidate_alone() {
        let mut store = running(0);
        provisionally(&mut store, 1);
        store.stage(document(2).as_bytes()).expect("sound");

        store.roll_back(&mut discard()).expect("outstanding");

        // The candidate survived, so a commit after a rollback still has something
        // to commit — and it takes the generation after the rollback's.
        assert_eq!(
            store
                .commit(&mut discard())
                .expect("a candidate")
                .generation(),
            Generation::from_bits(4)
        );
    }

    proptest! {
        /// Whatever sequence of provisional commits, confirmations and rollbacks a
        /// peer drives, nothing panics, the generation never goes backwards, and at
        /// most one commit is ever outstanding.
        #[test]
        fn any_sequence_of_provisional_operations_keeps_generations_monotonic(
            steps in proptest::collection::vec(0u8..4, 0..32),
        ) {
            let mut store = Datastore::new();
            let mut seen = Generation::ZERO;
            let mut records = discard();

            for (at, step) in steps.into_iter().enumerate() {
                match step {
                    0 => {
                        store.stage(document(at % 5).as_bytes()).expect("sound");
                        if let Ok(outcome) = store.commit_provisionally(&mut records) {
                            prop_assert!(outcome.generation() >= seen);
                            seen = outcome.generation();
                        }
                    }
                    1 => {
                        // The generation a confirmation names is the peer's choice,
                        // so it is deliberately not always the right one.
                        let named = Generation::from_bits(seen.to_bits().saturating_sub(u32::from(at as u8 % 2)));
                        let _ = store.confirm(named);
                    }
                    2 => {
                        if let Ok(rolled) = store.roll_back(&mut records) {
                            prop_assert!(rolled.generation > seen);
                            seen = rolled.generation;
                        }
                    }
                    _ => {
                        store.stage(document(at % 5).as_bytes()).expect("sound");
                        if let Ok(outcome) = store.commit(&mut records) {
                            prop_assert!(outcome.generation() >= seen);
                            seen = outcome.generation();
                        }
                        prop_assert_eq!(store.provisional(), None);
                    }
                }
                prop_assert_eq!(store.running(), seen);
                // At most one outstanding, always: the type carries one and the
                // property is that nothing accumulates beside it.
                if let Some(provisional) = store.provisional() {
                    prop_assert_eq!(provisional, seen);
                }
            }
        }
    }
}
