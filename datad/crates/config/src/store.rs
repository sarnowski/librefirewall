//! The candidate/running configuration datastore.
//!
//! Two operations and one shape: a candidate is assembled and validated
//! without touching what is running, and a commit swaps it in under a new
//! generation. Which of those changed anything is in the return type rather
//! than in a caller's bookkeeping — [`Datastore::validate_document`] takes
//! `&self`, so "an operation that changes nothing" is a property the signature
//! carries.
//!
//! # The bytes are not kept, and the validated-is-applied property still holds
//!
//! The design requires that the exact bytes validated are the bytes applied.
//! Keeping the document beside the model was rejected: 64 KiB of it
//! ([`MAX_DOCUMENT_BYTES`](crate::MAX_DOCUMENT_BYTES)) has no allocator to live
//! in and no 16 KiB stack to sit on. What makes the property hold is structural
//! instead: a [`Model`] is produced by one reading of one byte string and is
//! what the commit and the artifact builder both take their input from, so
//! there is no second reading for the first to disagree with.

use lfw_log::GenerationOutcome;

use crate::{
    ConfigError,
    diff::{Records, diff},
    hash::{ContentHash, content_hash},
    load,
    model::Model,
    provisional::Displaced,
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
    pub(crate) const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// What observing the medium's newest recorded version did to the numbering. Three
/// outcomes and not a `bool`: the third is one an operator has to be told about, as
/// every later commit is then refused as exhausted for a reason nothing says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableFloor {
    Unchanged,
    Raised {
        recorded: Generation,
    },
    /// Wider than a [`Generation`], so nothing is left above it: the exhausted state.
    BeyondWidth {
        recorded: u64,
    },
}

/// A candidate a document became, and the generation a commit would assign it.
///
/// Handed back by [`Datastore::stage`] rather than fetched again afterwards, so
/// there is no second question to ask and no absent answer to it.
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
    /// The configuration is now `generation`, and `changes` records went to
    /// the caller's sink describing what moved.
    Applied {
        generation: Generation,
        changes: usize,
    },
    /// The candidate's content was already running, so no generation was
    /// assigned and no record was written: a commit is keyed by content.
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
    pub const fn changes(self) -> usize {
        match self {
            Self::Applied { changes, .. } => changes,
            Self::Unchanged { .. } => 0,
        }
    }
}

/// The running configuration and an optional candidate.
///
/// The hash beside the generation is what recognises a commit of the content
/// already running; the model is what a diff is taken against.
#[derive(Clone, Debug)]
pub struct Datastore {
    // Crate-visible rather than private, and only to the one module that carries
    // the provisional-commit lifecycle: those operations are this store's own and
    // sit in a module of their own because they are about time rather than about a
    // document. Nothing outside the crate reaches a field.
    pub(crate) generation: Generation,
    pub(crate) hash: ContentHash,
    pub(crate) model: Model,
    pub(crate) candidate: Option<Model>,
    /// What the outstanding provisional commit displaced, or `None` where no
    /// commit is awaiting confirmation.
    ///
    /// At most one; the provisional module's header is why.
    pub(crate) displaced: Option<Displaced>,
    /// The newest version some medium already records, which every generation this
    /// store assigns must be past. **Not a second running generation:** setting the
    /// counter to it would claim the document being enforced is the one on the
    /// medium, which after a boot it is not.
    pub(crate) durable: Generation,
}

impl Datastore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: Generation::ZERO,
            hash: ContentHash::EMPTY,
            model: Model::EMPTY,
            candidate: None,
            displaced: None,
            durable: Generation::ZERO,
        }
    }

    #[must_use]
    pub const fn running(&self) -> Generation {
        self.generation
    }

    /// Raise the floor to the newest version `recorded` on a medium, so the next
    /// configuration is numbered past every version that already exists. Monotone,
    /// so a reading that went backwards cannot walk the numbering back onto
    /// versions already spoken for. A version wider than a [`Generation`] is
    /// answered rather than narrowed: a truncated mark would be a floor *below*
    /// versions the medium holds, which is the numbering this prevents.
    pub fn observe_durable(&mut self, recorded: u64) -> DurableFloor {
        let Ok(bits) = u32::try_from(recorded) else {
            self.durable = Generation::from_bits(u32::MAX);
            return DurableFloor::BeyondWidth { recorded };
        };
        let recorded = Generation::from_bits(bits);
        if recorded <= self.durable {
            return DurableFloor::Unchanged;
        }
        self.durable = recorded;
        DurableFloor::Raised { recorded }
    }

    /// The one running or the one a medium records, whichever is further on —
    /// private, so no caller may mistake it for what the appliance enforces.
    pub(crate) const fn latest(&self) -> Generation {
        if self.durable.to_bits() > self.generation.to_bits() {
            self.durable
        } else {
            self.generation
        }
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
            generation: self.latest().next(),
            model,
        })
    }

    /// Read a document and keep nothing — validation must change nothing,
    /// which `&self` is the whole of the proof of.
    ///
    /// # Errors
    /// [`ConfigError`], exactly as [`Datastore::stage`] would have refused it.
    pub fn validate_document(&self, document: &[u8]) -> Result<(), ConfigError> {
        load(document).map(|_| ())
    }

    /// Make the candidate the running configuration, handing every value that
    /// moved to `records`. Nothing reaches `records` unless the commit happens.
    ///
    /// # Errors
    /// [`CommitError::NoCandidate`] with nothing staged, or
    /// [`CommitError::GenerationsExhausted`]; the candidate survives either,
    /// nothing having happened to it.
    pub fn commit(&mut self, records: &mut dyn Records) -> Result<CommitOutcome, CommitError> {
        let outcome = self.apply(records, false)?;
        // Final the instant it happens, so a previous provisional commit's
        // displaced configuration is given up: an operator who commits over an
        // unconfirmed change has decided.
        self.displaced = None;
        Ok(outcome)
    }

    /// The commit both public forms run, `provisional` deciding only whether what
    /// it displaces is kept.
    pub(crate) fn apply(
        &mut self,
        records: &mut dyn Records,
        provisional: bool,
    ) -> Result<CommitOutcome, CommitError> {
        let next = self.candidate.ok_or(CommitError::NoCandidate)?;
        let hash = content_hash(&next);
        // The digest is a fast path and never the decision: `Unchanged` assigns
        // no generation and publishes nothing, so a configuration reaching it
        // wrongly is one silently suppressed.
        if hash == self.hash && next.has_same_content(&self.model) {
            self.candidate = None;
            return Ok(CommitOutcome::Unchanged {
                generation: self.generation,
            });
        }
        let latest = self.latest();
        let generation = latest.next();
        if generation == latest {
            return Err(CommitError::GenerationsExhausted { latest });
        }

        let changes = diff(&self.model, &next, records);
        if provisional {
            self.displaced = Some(Displaced {
                provisional: generation,
                generation: self.generation,
                hash: self.hash,
                model: self.model,
            });
        }
        self.generation = generation;
        self.hash = hash;
        self.model = next;
        self.candidate = None;
        Ok(CommitOutcome::Applied {
            generation,
            changes,
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
    use crate::diff::Change;
    use lfw_log::{ObjectKind, RejectReason};
    use proptest::prelude::*;
    use std::{format, string::String, vec::Vec};

    /// A sink that keeps every record, so a test can assert what a commit
    /// handed out as well as how many.
    #[derive(Default)]
    struct Collected(Vec<Change>);

    impl Records for Collected {
        fn record(&mut self, change: Change) {
            self.0.push(change);
        }
    }

    /// A sink that keeps nothing, for the commits a test only counts.
    fn discard() -> impl Records {
        |_change: Change| {}
    }

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
             </interfaces><neighbours/><rules/><management enabled=\"true\" mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" prefix-length=\"24\" gateway=\"none\"/></configuration>"
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
            .commit(&mut discard())
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
        let outcome = store.commit(&mut discard()).expect("the first one");
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
        assert_eq!(store.commit(&mut discard()), Err(CommitError::NoCandidate));
    }

    #[test]
    fn committing_with_nothing_staged_is_refused() {
        let mut store = store();
        assert_eq!(store.commit(&mut discard()), Err(CommitError::NoCandidate));
        assert_eq!(store.running(), Generation::ZERO);
    }

    #[test]
    fn a_commit_takes_the_candidate_with_it() {
        let mut store = store();
        commit(&mut store, &one());
        assert_eq!(store.commit(&mut discard()), Err(CommitError::NoCandidate));

        // Including the commit that assigned nothing: a candidate that has been
        // judged is spent whichever way the judgement went.
        store.stage(one().as_bytes()).expect("sound");
        assert_eq!(
            store.commit(&mut discard()).expect("a candidate").outcome(),
            GenerationOutcome::Unchanged
        );
        assert_eq!(store.commit(&mut discard()), Err(CommitError::NoCandidate));
    }

    #[test]
    fn generations_are_assigned_in_order_and_the_diff_is_reported() {
        let mut store = store();
        let mut changes = Collected::default();

        store.stage(one().as_bytes()).expect("sound");
        let first = store.commit(&mut changes).expect("a candidate");
        assert_eq!(first.generation(), Generation::from_bits(1));
        assert_eq!(first.outcome(), GenerationOutcome::Applied);
        // Five interface fields and the management element's five.
        assert_eq!(first.changes(), 10);
        assert_eq!(changes.0.len(), 10);

        let mut second_changes = Collected::default();
        store.stage(document(1, true).as_bytes()).expect("sound");
        let second = store.commit(&mut second_changes).expect("a candidate");
        assert_eq!(second.generation(), Generation::from_bits(2));
        assert_eq!(second.changes(), 1, "only the address moved");
        assert_eq!(second_changes.0.len(), 1);
        assert_eq!(store.running(), Generation::from_bits(2));
    }

    #[test]
    fn committing_the_running_content_again_assigns_nothing() {
        let mut store = store();
        commit(&mut store, &one());

        let mut changes = Collected::default();
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
        assert_eq!(outcome.changes(), 0);
        assert_eq!(store.running(), Generation::from_bits(1));
        assert!(changes.0.is_empty());
    }

    /// A commit is keyed by content, and the content is what decides — not the
    /// 32-bit digest of it.
    ///
    /// The collision is forged rather than searched for: what matters is the
    /// behaviour when two distinct configurations share a hash, and finding a
    /// real FNV-1a collision would prove nothing this does not. `Unchanged`
    /// here would leave the previous configuration in force with nothing said
    /// about it, which is a suppression rather than a no-op.
    #[test]
    fn a_configuration_that_collides_with_the_running_hash_still_applies() {
        let mut store = store();
        commit(&mut store, &one());
        let running = *store.running_model();

        store.stage(document(1, true).as_bytes()).expect("sound");
        let candidate = store.candidate.expect("a candidate");
        assert!(
            !candidate.has_same_content(&running),
            "the two documents really are different configurations"
        );
        store.hash = content_hash(&candidate);

        let outcome = store.commit(&mut discard()).expect("a candidate");
        assert!(
            matches!(outcome, CommitOutcome::Applied { .. }),
            "a different configuration committed as unchanged: {outcome:?}"
        );
        assert_eq!(outcome.generation(), Generation::from_bits(2));
        assert_eq!(*store.running_model(), candidate);
    }

    /// And the reverse still holds: one configuration written in another order
    /// is the same configuration, so it assigns nothing. The equality that
    /// decides has to be over content and not over the document's own order,
    /// which a plain structural comparison of the model would not be.
    #[test]
    fn one_configuration_written_in_another_order_still_assigns_nothing() {
        // One interface, written whole, so the two documents below differ in
        // the order of these and in nothing else.
        let interface = |id: &str, port: u8| {
            format!(
                "<interface id=\"{id}\" port=\"{port}\" enabled=\"true\" \
                 mac=\"52:54:00:00:00:0{port}\" address=\"10.0.{port}.1\" \
                 prefix-length=\"24\"/>"
            )
        };
        let document = |first: &str, second: &str| {
            format!(
                "<configuration><interfaces>{first}{second}</interfaces>\
                 <neighbours/><rules/><management enabled=\"true\" \
                 mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" \
                 prefix-length=\"24\" gateway=\"none\"/></configuration>"
            )
        };
        let (aaa, zzz) = (interface("aaa", 0), interface("zzz", 1));
        let forwards = document(&aaa, &zzz);
        let backwards = document(&zzz, &aaa);

        let mut store = store();
        let first = commit(&mut store, &forwards);
        assert_eq!(first.outcome(), GenerationOutcome::Applied);
        let model = *store.running_model();

        store.stage(backwards.as_bytes()).expect("sound");
        let reordered = store.candidate.expect("a candidate");
        assert_ne!(
            model, reordered,
            "the two documents are written differently"
        );
        assert!(
            model.has_same_content(&reordered),
            "and they are the same configuration"
        );
        assert_eq!(
            store.commit(&mut discard()).expect("a candidate"),
            CommitOutcome::Unchanged {
                generation: Generation::from_bits(1)
            }
        );
    }

    /// A commit that assigns nothing hands out nothing, so a caller that keeps
    /// its sink across commits cannot present an earlier generation's records
    /// as this one's.
    #[test]
    fn a_commit_that_assigns_nothing_hands_out_no_records() {
        let mut store = store();
        let mut changes = Collected::default();

        store.stage(one().as_bytes()).expect("sound");
        assert_eq!(
            store.commit(&mut changes).expect("a candidate").changes(),
            10
        );
        assert_eq!(changes.0.len(), 10);

        store.stage(one().as_bytes()).expect("sound");
        let outcome = store.commit(&mut changes).expect("a candidate");
        assert_eq!(outcome.outcome(), GenerationOutcome::Unchanged);
        assert_eq!(
            changes.0.len(),
            10,
            "nothing was added by the second commit"
        );
    }

    #[test]
    fn an_exhausted_counter_refuses_the_commit_and_keeps_the_candidate() {
        let mut store = store();
        store.generation = Generation::from_bits(u32::MAX);
        store.stage(one().as_bytes()).expect("sound");

        assert_eq!(
            store.commit(&mut discard()),
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
                .commit(&mut discard())
                .expect("nothing happened to it")
                .generation(),
            Generation::from_bits(2)
        );
    }

    /// A commit that refuses hands out nothing: the diff is the last thing a
    /// commit does, so a record a caller sees is a change the running
    /// configuration actually took.
    #[test]
    fn a_refused_commit_hands_out_no_records() {
        let mut store = store();
        let mut changes = Collected::default();

        assert_eq!(store.commit(&mut changes), Err(CommitError::NoCandidate));
        assert!(changes.0.is_empty());

        store.generation = Generation::from_bits(u32::MAX);
        store.stage(one().as_bytes()).expect("sound");
        assert!(matches!(
            store.commit(&mut changes),
            Err(CommitError::GenerationsExhausted { .. })
        ));
        assert!(changes.0.is_empty());
    }

    /// The defect this floor exists for, stated as the sequence that produced it:
    /// a boot comes up on the document its image carries and numbers it one, while
    /// a medium it reloaded already records four. Without the floor the next
    /// commit offers two, which the holder of the medium refuses as a version that
    /// does not advance — so the commit never becomes durable and the appliance
    /// can never be reconfigured again.
    #[test]
    fn a_reloaded_medium_numbers_the_next_commit_past_every_version_it_records() {
        let mut store = store();
        // The boot document, which is not on the medium and is numbered as the
        // running configuration it is.
        assert_eq!(
            commit(&mut store, &one()).generation(),
            Generation::from_bits(1)
        );

        assert_eq!(
            store.observe_durable(4),
            DurableFloor::Raised {
                recorded: Generation::from_bits(4)
            }
        );
        // The running generation is untouched: what is in force is still the
        // document the image carries, and the floor says nothing about it.
        assert_eq!(store.running(), Generation::from_bits(1));

        let staged = store.stage(document(2, true).as_bytes()).expect("sound");
        assert_eq!(staged.generation, Generation::from_bits(5));
        assert_eq!(
            store
                .commit(&mut discard())
                .expect("a candidate")
                .generation(),
            Generation::from_bits(5)
        );
    }

    /// The floor only rises. A reading that went backwards — a medium whose array
    /// a factory reset emptied, a peer publishing a smaller number — must not walk
    /// the numbering back onto versions that already exist.
    #[test]
    fn the_floor_only_rises_and_a_second_reading_of_it_does_nothing() {
        let mut store = store();
        assert_eq!(
            store.observe_durable(9),
            DurableFloor::Raised {
                recorded: Generation::from_bits(9)
            }
        );
        assert_eq!(store.observe_durable(9), DurableFloor::Unchanged);
        assert_eq!(store.observe_durable(0), DurableFloor::Unchanged);
        assert_eq!(store.observe_durable(3), DurableFloor::Unchanged);
        assert_eq!(store.next_generation(), Some(Generation::from_bits(10)));
    }

    /// A medium recording no version constrains nothing, which is every appliance
    /// no management plane has pushed a configuration to.
    #[test]
    fn a_medium_recording_no_version_numbers_from_the_beginning() {
        let mut store = store();
        assert_eq!(store.observe_durable(0), DurableFloor::Unchanged);
        assert_eq!(
            commit(&mut store, &one()).generation(),
            Generation::from_bits(1)
        );
    }

    /// A version wider than the counter is refused rather than narrowed: a
    /// truncated mark would be a floor *below* versions the medium holds, which is
    /// exactly the numbering the floor exists to prevent. What is left is a store
    /// with no number to assign, which is the exhausted state and is reported as
    /// one.
    #[test]
    fn a_recorded_version_wider_than_the_counter_exhausts_it_rather_than_narrowing() {
        let mut store = store();
        let recorded = u64::from(u32::MAX) + 1;
        assert_eq!(
            store.observe_durable(recorded),
            DurableFloor::BeyondWidth { recorded }
        );
        assert_eq!(store.next_generation(), None);

        store.stage(one().as_bytes()).expect("sound");
        assert_eq!(
            store.commit(&mut discard()),
            Err(CommitError::GenerationsExhausted {
                latest: Generation::from_bits(u32::MAX),
            })
        );
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
            "</neighbours><rules/>",
            "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" prefix-length=\"24\" gateway=\"none\"/>",
            "</configuration>"
        );
        let mut changes = Collected::default();
        store.stage(text.as_bytes()).expect("sound");
        let outcome = store.commit(&mut changes).expect("a candidate");

        assert_eq!(outcome.changes(), 13);
        let kinds: Vec<ObjectKind> = changes.0.iter().map(|change| change.object).collect();
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
            5
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
            let mut changes = discard();
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
                    Ok(CommitOutcome::Applied { generation, changes: moved }) => {
                        prop_assert!(generation > seen);
                        prop_assert!(moved > 0, "an applied generation moved something");
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

        /// The floor's whole contract over the space a peer can put in the region
        /// it is read out of: whatever sequence of readings arrives, the number a
        /// commit would assign is past every one of them, and past what is
        /// running. Nothing panics and nothing narrows.
        #[test]
        fn any_sequence_of_readings_leaves_the_numbering_past_all_of_them(
            readings in proptest::collection::vec(0u64..=u64::MAX, 0..12),
        ) {
            let mut store = store();
            commit(&mut store, &one());
            let mut highest = 0u64;
            let mut widened = false;
            for reading in readings {
                match store.observe_durable(reading) {
                    DurableFloor::Unchanged => {}
                    DurableFloor::Raised { recorded } => {
                        prop_assert_eq!(u64::from(recorded.to_bits()), reading);
                    }
                    DurableFloor::BeyondWidth { recorded } => {
                        prop_assert_eq!(recorded, reading);
                        prop_assert!(recorded > u64::from(u32::MAX));
                        widened = true;
                    }
                }
                highest = highest.max(reading);
            }
            match store.next_generation() {
                Some(next) => {
                    prop_assert!(!widened);
                    prop_assert!(u64::from(next.to_bits()) > highest);
                    prop_assert!(next > store.running());
                }
                // The only way there is no successor: a reading wider than the
                // counter, which leaves the store exhausted rather than numbering
                // below what the medium holds.
                None => prop_assert!(widened),
            }
        }

        /// Idempotence, stated the way a content-keyed commit implies: the same
        /// content committed twice moves the configuration once.
        #[test]
        fn committing_one_configuration_twice_applies_it_once(variant in 0usize..4) {
            let mut store = store();
            let text = document(variant, true);
            let mut changes = discard();

            store.stage(text.as_bytes()).expect("sound");
            let first = store.commit(&mut changes).expect("a candidate");
            store.stage(text.as_bytes()).expect("sound");
            let second = store.commit(&mut changes).expect("a candidate");

            prop_assert_eq!(second.outcome(), GenerationOutcome::Unchanged);
            prop_assert_eq!(second.generation(), first.generation());
            prop_assert_eq!(second.changes(), 0);
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
            let outcome = store.commit(&mut discard()).expect("a candidate");

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
                if let Ok(CommitOutcome::Applied { .. }) = store.commit(&mut discard()) {
                    applied = applied.saturating_add(1);
                }
            }

            prop_assert_eq!(store.running(), Generation::from_bits(applied));
            prop_assert_eq!(store.running_hash(), content_hash(store.running_model()));
            prop_assert_eq!(store.running_model().interface_count(), 1);
        }
    }
}
