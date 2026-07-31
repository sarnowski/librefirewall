//! The candidate/running datastore of CONCEPT §12.1.
//!
//! Two operations and one shape: a candidate is assembled and validated
//! without touching what is running, and a commit swaps it in under a new
//! generation. Which of those changed anything is in the return type rather
//! than in a caller's bookkeeping — [`Datastore::validate_document`] takes
//! `&self`, so "an operation that changes nothing" is a property the signature
//! carries.
//!
//! # The bytes are not kept, and the §12 property still holds
//!
//! CONCEPT §12 requires that the exact bytes validated are the bytes applied.
//! Keeping the document beside the model was rejected: 64 KiB of it
//! ([`MAX_DOCUMENT_BYTES`](crate::MAX_DOCUMENT_BYTES)) has no allocator to live
//! in and no 16 KiB stack to sit on. What makes the property hold is structural
//! instead: a [`Model`] is produced by one reading of one byte string and is
//! what the commit and the artifact builder both take their input from, so
//! there is no second reading for the first to disagree with.

use lfw_log::GenerationOutcome;

use crate::{
    ConfigError,
    diff::{Change, DiffSummary, diff},
    hash::{ContentHash, content_hash},
    load,
    model::Model,
};

/// Which configuration, in the order they were committed.
///
/// A newtype rather than a `u32` because a generation and a [`ContentHash`] are
/// both 32-bit numbers describing a configuration, and the one question this
/// crate answers by comparing them — has anything changed — is answered wrong
/// if the two are swapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u32);

impl Generation {
    /// The fail-closed configuration every domain starts under.
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn to_bits(self) -> u32 {
        self.0
    }

    /// Saturating, so the counter has no wrap to be pushed through: a successor
    /// equal to its own generation is no progress, and the commit is refused.
    const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// A candidate a document became, and the generation a commit would assign it.
///
/// Handed back by [`Datastore::stage`] rather than fetched again afterwards, so
/// there is no second question to ask and no absent answer to it (ENG-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Staged {
    pub generation: Generation,
    pub model: Model,
}

/// Why a commit did not happen.
///
/// Separate from [`ConfigError`] because the console vocabulary keeps them
/// apart: a refused *document* names the rule it broke, while a refused
/// *generation* has no reason token because nothing about the configuration is
/// wrong. A commit cannot fail for a document reason at all — staging is where
/// a document is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitError {
    /// Nothing has been staged since the last commit.
    NoCandidate,
    /// The counter has reached [`u32::MAX`] and there is no successor to
    /// assign.
    GenerationsExhausted { latest: Generation },
}

/// What a commit did.
///
/// An enum rather than an outcome field, so the third [`GenerationOutcome`] —
/// `Refused` — is unrepresentable here: a refusal is an `Err`, and a value that
/// could say both would let a caller log one while holding the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The configuration is now `generation`, and `changes` is what moved.
    Applied {
        generation: Generation,
        changes: DiffSummary,
    },
    /// The candidate's content was already running, so no generation was
    /// assigned and no record was written (CONCEPT §12.2).
    Unchanged { generation: Generation },
}

impl CommitOutcome {
    #[must_use]
    pub const fn generation(self) -> Generation {
        match self {
            Self::Applied { generation, .. } | Self::Unchanged { generation } => generation,
        }
    }

    #[must_use]
    pub const fn outcome(self) -> GenerationOutcome {
        match self {
            Self::Applied { .. } => GenerationOutcome::Applied,
            Self::Unchanged { .. } => GenerationOutcome::Unchanged,
        }
    }

    #[must_use]
    pub const fn changes(self) -> DiffSummary {
        match self {
            Self::Applied { changes, .. } => changes,
            Self::Unchanged { .. } => DiffSummary::NONE,
        }
    }
}

/// The running configuration and an optional candidate.
///
/// The hash beside the generation is what recognises a commit of the content
/// already running (CONCEPT §12.2); the model is what a diff is taken against.
#[derive(Clone, Debug)]
pub struct Datastore {
    generation: Generation,
    hash: ContentHash,
    model: Model,
    candidate: Option<Model>,
}

impl Datastore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: Generation::ZERO,
            hash: ContentHash::EMPTY,
            model: Model::EMPTY,
            candidate: None,
        }
    }

    #[must_use]
    pub const fn running(&self) -> Generation {
        self.generation
    }

    #[must_use]
    pub const fn running_model(&self) -> &Model {
        &self.model
    }

    #[must_use]
    pub const fn running_hash(&self) -> ContentHash {
        self.hash
    }

    /// Read a document and hold it as the candidate, changing nothing that is
    /// running.
    ///
    /// # Errors
    /// [`ConfigError`] from either half of reading it, leaving any previous
    /// candidate in place: a document that could not be read has replaced
    /// nothing.
    pub fn stage(&mut self, document: &[u8]) -> Result<Staged, ConfigError> {
        let model = load(document)?;
        self.candidate = Some(model);
        Ok(Staged {
            generation: self.generation.next(),
            model,
        })
    }

    /// Read a document and keep nothing — the operation CONCEPT §12.1 requires
    /// to change nothing, which `&self` is the whole of the proof of.
    ///
    /// # Errors
    /// [`ConfigError`], exactly as [`Datastore::stage`] would have refused it.
    pub fn validate_document(&self, document: &[u8]) -> Result<(), ConfigError> {
        load(document).map(|_| ())
    }

    /// Make the candidate the running configuration, writing what changed into
    /// `changes`.
    ///
    /// # Errors
    /// [`CommitError::NoCandidate`] with nothing staged, or
    /// [`CommitError::GenerationsExhausted`]; the candidate survives either,
    /// nothing having happened to it.
    pub fn commit(&mut self, changes: &mut [Option<Change>]) -> Result<CommitOutcome, CommitError> {
        let next = self.candidate.ok_or(CommitError::NoCandidate)?;
        let hash = content_hash(&next);
        if hash == self.hash {
            // Emptied on this path too, so a reused buffer holds this commit's
            // records whichever way it went rather than the last one's.
            for slot in changes.iter_mut() {
                *slot = None;
            }
            self.candidate = None;
            return Ok(CommitOutcome::Unchanged {
                generation: self.generation,
            });
        }
        let generation = self.generation.next();
        if generation == self.generation {
            return Err(CommitError::GenerationsExhausted {
                latest: self.generation,
            });
        }

        let summary = diff(&self.model, &next, changes);
        self.generation = generation;
        self.hash = hash;
        self.model = next;
        self.candidate = None;
        Ok(CommitOutcome::Applied {
            generation,
            changes: summary,
        })
    }
}

impl Default for Datastore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PORT_COUNT;
    use lfw_log::{ObjectKind, RejectReason};
    use proptest::prelude::*;
    use std::{format, string::String, vec::Vec};

    const ROOMY: usize = 256;

    /// One interface whose address `variant` chooses, so two variants are two
    /// configurations rather than two lengths — and `variant` at or above
    /// [`REFUSED`] names a port this build does not have, which is how a test
    /// reaches the staging failure without a malformed byte anywhere.
    fn document(variant: usize, enabled: bool) -> String {
        let port = if variant >= REFUSED { PORT_COUNT } else { 0 };
        format!(
            "<configuration><interfaces>\
             <interface id=\"wan\" port=\"{port}\" enabled=\"{enabled}\" \
             mac=\"52:54:00:00:00:01\" address=\"10.0.{variant}.1\" prefix-length=\"24\"/>\
             </interfaces><neighbours/><management enabled=\"true\" mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" prefix-length=\"24\"/></configuration>"
        )
    }

    /// The first variant a semantic rule refuses.
    const REFUSED: usize = 5;

    /// The configuration every store test below starts from.
    fn one() -> String {
        document(0, true)
    }

    fn store() -> Datastore {
        Datastore::new()
    }

    fn commit(store: &mut Datastore, text: &str) -> CommitOutcome {
        store.stage(text.as_bytes()).expect("a sound document");
        store
            .commit(&mut [None; ROOMY])
            .expect("a staged candidate commits")
    }

    #[test]
    fn a_fresh_store_runs_the_fail_closed_configuration() {
        let store = store();
        assert_eq!(store.running(), Generation::ZERO);
        assert_eq!(store.running().to_bits(), 0);
        assert_eq!(*store.running_model(), Model::EMPTY);
        assert_eq!(store.running_hash(), ContentHash::EMPTY);
        assert_eq!(Datastore::default().running(), Generation::ZERO);
    }

    #[test]
    fn staging_hands_back_the_candidate_and_changes_nothing_that_is_running() {
        let mut store = store();
        let staged = store.stage(one().as_bytes()).expect("a sound document");

        assert_eq!(staged.generation, Generation::from_bits(1));
        assert_eq!(staged.model.interface_count(), 1);
        assert_eq!(store.running(), Generation::ZERO);
        assert_eq!(*store.running_model(), Model::EMPTY);
    }

    #[test]
    fn a_document_that_will_not_read_replaces_no_candidate() {
        let mut store = store();
        store.stage(one().as_bytes()).expect("a sound document");
        let refused = store
            .stage(b"<!DOCTYPE x><configuration/>")
            .expect_err("a doctype");
        assert_eq!(refused.reason(), RejectReason::Doctype);

        // The candidate is only observable through what a commit makes of it,
        // which is the whole of what holding one is for.
        let outcome = store.commit(&mut [None; ROOMY]).expect("the first one");
        assert_eq!(outcome.generation(), Generation::from_bits(1));
        assert_eq!(store.running_model().interface_count(), 1);
    }

    #[test]
    fn validating_a_document_changes_nothing_at_all() {
        let mut store = store();
        commit(&mut store, &one());
        let before = store.clone();

        store
            .validate_document(document(2, true).as_bytes())
            .expect("a sound document");
        store
            .validate_document(document(REFUSED, true).as_bytes())
            .expect_err("a port this build does not have");
        assert_eq!(
            store.validate_document(b"<configuration/>"),
            Err(ConfigError::Document(crate::DocumentError::at(
                crate::DocumentFault::MissingElement,
                0
            )))
        );

        assert_eq!(store.running(), before.running());
        assert_eq!(store.running_hash(), before.running_hash());
        assert_eq!(*store.running_model(), *before.running_model());
        // Nothing was staged either, which a commit is what asks.
        assert_eq!(
            store.commit(&mut [None; ROOMY]),
            Err(CommitError::NoCandidate)
        );
    }

    #[test]
    fn committing_with_nothing_staged_is_refused() {
        let mut store = store();
        assert_eq!(
            store.commit(&mut [None; ROOMY]),
            Err(CommitError::NoCandidate)
        );
        assert_eq!(store.running(), Generation::ZERO);
    }

    #[test]
    fn a_commit_takes_the_candidate_with_it() {
        let mut store = store();
        commit(&mut store, &one());
        assert_eq!(
            store.commit(&mut [None; ROOMY]),
            Err(CommitError::NoCandidate)
        );

        // Including the commit that assigned nothing: a candidate that has been
        // judged is spent whichever way the judgement went.
        store.stage(one().as_bytes()).expect("sound");
        assert_eq!(
            store
                .commit(&mut [None; ROOMY])
                .expect("a candidate")
                .outcome(),
            GenerationOutcome::Unchanged
        );
        assert_eq!(
            store.commit(&mut [None; ROOMY]),
            Err(CommitError::NoCandidate)
        );
    }

    #[test]
    fn generations_are_assigned_in_order_and_the_diff_is_reported() {
        let mut store = store();
        let mut changes = [None; ROOMY];

        store.stage(one().as_bytes()).expect("sound");
        let first = store.commit(&mut changes).expect("a candidate");
        assert_eq!(first.generation(), Generation::from_bits(1));
        assert_eq!(first.outcome(), GenerationOutcome::Applied);
        // Five interface fields and the management element's four.
        assert_eq!(first.changes().written(), 9);
        assert_eq!(changes.iter().flatten().count(), 9);

        store.stage(document(1, true).as_bytes()).expect("sound");
        let second = store.commit(&mut changes).expect("a candidate");
        assert_eq!(second.generation(), Generation::from_bits(2));
        assert_eq!(second.changes().written(), 1, "only the address moved");
        assert_eq!(store.running(), Generation::from_bits(2));
    }

    #[test]
    fn committing_the_running_content_again_assigns_nothing() {
        let mut store = store();
        commit(&mut store, &one());

        let mut changes = [None; ROOMY];
        // The same configuration, written differently: whitespace and the
        // attribute order are exactly what the content hash must not see.
        let rewritten = one().replacen("id=\"wan\" port=\"0\"", "port=\"0\"   id=\"wan\"", 1);
        store.stage(rewritten.as_bytes()).expect("sound");
        let outcome = store.commit(&mut changes).expect("a candidate");

        assert_eq!(
            outcome,
            CommitOutcome::Unchanged {
                generation: Generation::from_bits(1)
            }
        );
        assert_eq!(outcome.outcome(), GenerationOutcome::Unchanged);
        assert_eq!(outcome.changes(), DiffSummary::NONE);
        assert_eq!(store.running(), Generation::from_bits(1));
        assert_eq!(changes.iter().flatten().count(), 0);
    }

    #[test]
    fn a_reused_buffer_never_shows_an_earlier_generations_records() {
        let mut store = store();
        let mut changes = [None; ROOMY];

        store.stage(one().as_bytes()).expect("sound");
        assert_eq!(
            store
                .commit(&mut changes)
                .expect("a candidate")
                .changes()
                .written(),
            9
        );

        store.stage(one().as_bytes()).expect("sound");
        let outcome = store.commit(&mut changes).expect("a candidate");
        assert_eq!(outcome.outcome(), GenerationOutcome::Unchanged);
        assert_eq!(changes.iter().flatten().count(), 0);
    }

    #[test]
    fn an_exhausted_counter_refuses_the_commit_and_keeps_the_candidate() {
        let mut store = store();
        store.generation = Generation::from_bits(u32::MAX);
        store.stage(one().as_bytes()).expect("sound");

        assert_eq!(
            store.commit(&mut [None; ROOMY]),
            Err(CommitError::GenerationsExhausted {
                latest: Generation::from_bits(u32::MAX),
            })
        );
        assert_eq!(store.running(), Generation::from_bits(u32::MAX));
        // The candidate survived, so a store whose counter was rescued would
        // still commit it.
        store.generation = Generation::from_bits(1);
        assert_eq!(
            store
                .commit(&mut [None; ROOMY])
                .expect("nothing happened to it")
                .generation(),
            Generation::from_bits(2)
        );
    }

    #[test]
    fn a_commit_whose_records_do_not_fit_still_commits_and_says_so() {
        let mut store = store();
        let mut changes = [None; 2];
        store.stage(one().as_bytes()).expect("sound");
        let outcome = store.commit(&mut changes).expect("a candidate");

        assert_eq!(outcome.generation(), Generation::from_bits(1));
        assert_eq!(outcome.changes().written(), 2);
        assert_eq!(outcome.changes().dropped(), 7);
        assert!(outcome.changes().overflowed());
        assert_eq!(store.running(), Generation::from_bits(1));
    }

    #[test]
    fn a_generation_survives_the_round_trip_through_its_bits() {
        for bits in [0, 1, 7, u32::MAX] {
            assert_eq!(Generation::from_bits(bits).to_bits(), bits);
        }
        assert!(Generation::ZERO < Generation::from_bits(1));
    }

    #[test]
    fn the_diff_a_commit_reports_names_the_object_kinds_it_touched() {
        let mut store = store();
        let text = concat!(
            "<configuration><interfaces>",
            "<interface id=\"wan\" port=\"0\" enabled=\"true\" mac=\"52:54:00:00:00:01\" ",
            "address=\"10.0.0.1\" prefix-length=\"24\"/>",
            "</interfaces><neighbours>",
            "<neighbour id=\"gw\" interface=\"wan\" address=\"10.0.0.2\" ",
            "mac=\"52:54:00:00:00:02\"/>",
            "</neighbours>",
            "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" prefix-length=\"24\"/>",
            "</configuration>"
        );
        let mut changes = [None; ROOMY];
        store.stage(text.as_bytes()).expect("sound");
        let outcome = store.commit(&mut changes).expect("a candidate");

        assert_eq!(outcome.changes().total(), 12);
        let kinds: Vec<ObjectKind> = changes
            .iter()
            .flatten()
            .map(|change| change.object)
            .collect();
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == ObjectKind::Interface)
                .count(),
            5
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == ObjectKind::Neighbour)
                .count(),
            3
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == ObjectKind::Management)
                .count(),
            4
        );
    }

    proptest! {
        /// The invariant a caller relies on across any sequence of operations:
        /// nothing panics, the generation never goes backwards, and it moves
        /// exactly when something was applied.
        #[test]
        fn any_sequence_of_commits_leaves_generations_monotonic(
            steps in proptest::collection::vec((0usize..7, any::<bool>()), 0..24),
        ) {
            let mut store = store();
            let mut changes = [None; ROOMY];
            let mut seen = Generation::ZERO;

            for (variant, commit_without_staging) in steps {
                let outcome = if commit_without_staging {
                    store.commit(&mut changes)
                } else {
                    match store.stage(document(variant, true).as_bytes()) {
                        Ok(staged) => {
                            prop_assert_eq!(store.running(), seen);
                            prop_assert!(staged.generation > seen);
                            store.commit(&mut changes)
                        }
                        Err(error) => {
                            prop_assert!(matches!(error, ConfigError::Document(_) | ConfigError::Semantic(_)));
                            continue;
                        }
                    }
                };

                match outcome {
                    Ok(CommitOutcome::Applied { generation, changes: summary }) => {
                        prop_assert!(generation > seen);
                        prop_assert!(!summary.is_empty(), "an applied generation moved something");
                        seen = generation;
                    }
                    Ok(CommitOutcome::Unchanged { generation }) => {
                        prop_assert_eq!(generation, seen);
                    }
                    Err(_) => {}
                }
                prop_assert_eq!(store.running(), seen);
            }
        }

        /// Idempotence, stated the way CONCEPT §12.2 keys it: the same content
        /// committed twice moves the configuration once.
        #[test]
        fn committing_one_configuration_twice_applies_it_once(variant in 0usize..4) {
            let mut store = store();
            let text = document(variant, true);
            let mut changes = [None; ROOMY];

            store.stage(text.as_bytes()).expect("sound");
            let first = store.commit(&mut changes).expect("a candidate");
            store.stage(text.as_bytes()).expect("sound");
            let second = store.commit(&mut changes).expect("a candidate");

            prop_assert_eq!(second.outcome(), GenerationOutcome::Unchanged);
            prop_assert_eq!(second.generation(), first.generation());
            prop_assert!(second.changes().is_empty());
        }

        /// What a commit applied is what the store then runs: the model, its
        /// hash and the generation it was assigned all say the same thing.
        #[test]
        fn an_applied_commit_is_what_the_store_runs(
            first in 0usize..4,
            second in 0usize..4,
        ) {
            prop_assume!(first != second);
            let mut store = store();
            commit(&mut store, &document(first, true));

            let staged = store
                .stage(document(second, false).as_bytes())
                .expect("sound");
            let outcome = store.commit(&mut [None; ROOMY]).expect("a candidate");

            prop_assert_eq!(outcome.generation(), staged.generation);
            prop_assert_eq!(store.running(), staged.generation);
            prop_assert_eq!(*store.running_model(), staged.model);
            prop_assert_eq!(store.running_hash(), content_hash(&staged.model));
        }

        /// The store holds one configuration however many it is given: a commit
        /// replaces what is running rather than accumulating beside it, so the
        /// generation counts the commits that moved something and nothing else
        /// is kept.
        #[test]
        fn a_store_holds_only_what_is_running(commits in 1usize..8) {
            let mut store = store();
            let mut applied = 0u32;
            for variant in 0..commits {
                store
                    .stage(document(variant % REFUSED, true).as_bytes())
                    .expect("sound");
                if let Ok(CommitOutcome::Applied { .. }) = store.commit(&mut [None; ROOMY]) {
                    applied = applied.saturating_add(1);
                }
            }

            prop_assert_eq!(store.running(), Generation::from_bits(applied));
            prop_assert_eq!(store.running_hash(), content_hash(store.running_model()));
            prop_assert_eq!(store.running_model().interface_count(), 1);
        }
    }
}
