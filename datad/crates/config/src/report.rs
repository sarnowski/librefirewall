//! Committing the document a domain was built with, deciding what that did,
//! and saying so.
//!
//! Every step can refuse, and which state the domain is left in is decided
//! here rather than in the protection domain that runs it: a domain binary
//! cannot be host-tested, and what happens to a document this build will not
//! accept is the behaviour that most needs testing.
//!
//! A refusal publishes nothing and the consumer stays on generation 0, which
//! forwards nothing. There is deliberately no default configuration behind the
//! document: a fallback would make a typo indistinguishable from a
//! working appliance until traffic went somewhere nobody intended.

use lfw_log::{DomainState, Event, GenerationOutcome, RejectReason, Sink};
use wire::ConfigImage;

use crate::{
    ConfigError,
    diff::{Change, Records},
    provisional::ProvisionalError,
    runtime::{BuildError, image_from},
    store::{CommitOutcome, Datastore, Generation},
};

/// What committing a document did.
///
/// Four outcomes rather than the two an `Option` carries: a commit whose content
/// was already running assigned nothing and refused nothing, and folding the two
/// together had a domain announce `state=refused` for a document it had accepted
/// — a console must carry the system's true state. The refusals are two because
/// the vocabularies are two: a refused *document* names the rule it broke, while
/// a commit that could not proceed has no reason token, nothing about the
/// configuration being wrong.
///
/// Every variant carries what a caller answering a submitter needs, so the
/// records this type's producer wrote to the console are not the only account of
/// what happened: a domain that must also answer the party that submitted the
/// document reads it off the report rather than out of its own log ring.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing needs an allocator; the value is a temporary destructured at once"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitReport {
    /// The configuration moved, and this is the image the consumer is handed.
    Published { image: ConfigImage, changes: u32 },
    /// Committed, and already running — a commit is keyed by content: nothing to publish.
    Unchanged,
    /// The document broke a rule. Nothing is in force from it.
    Rejected {
        reason: RejectReason,
        /// The number `reason` names: a byte position in the document, where the
        /// refusal has one, and zero where it names an object instead.
        detail: u32,
    },
    /// Every rule passed and the generation counter has no successor to assign,
    /// so nothing is in force from this document either.
    Exhausted,
    /// A commit with nothing staged. Unreachable through
    /// [`commit_and_report`], which stages the document it is given; it is what a
    /// caller that commits as a separate step meets, and it is a variant rather
    /// than folded into [`Self::Exhausted`] because the two are different
    /// mistakes — one is an appliance with no numbers left, the other a requester
    /// that has not sent a document.
    NoCandidate,
}

impl CommitReport {
    #[must_use]
    pub const fn image(self) -> Option<ConfigImage> {
        match self {
            Self::Published { image, .. } => Some(image),
            Self::Unchanged | Self::Rejected { .. } | Self::Exhausted | Self::NoCandidate => None,
        }
    }

    /// The generation now in force from this document, and 0 where none is:
    /// this type says what *this commit* did, and a commit of content already
    /// running assigned nothing.
    #[must_use]
    pub const fn generation(self) -> u32 {
        match self {
            Self::Published { image, .. } => image.generation,
            Self::Unchanged | Self::Rejected { .. } | Self::Exhausted | Self::NoCandidate => 0,
        }
    }

    /// The state the domain announces, decided here so that it is host-tested.
    /// `Unchanged` is `Ready` because the configuration in force *is*
    /// the one the document names; which of the two got there is the `LFW-CFG`
    /// record before it, and an operator is expected to read both.
    #[must_use]
    pub const fn state(self) -> DomainState {
        match self {
            Self::Published { .. } | Self::Unchanged => DomainState::Ready,
            Self::Rejected { .. } | Self::Exhausted | Self::NoCandidate => DomainState::Refused,
        }
    }
}

/// Read `document`, commit it, and report every value it moved. `sink` is told
/// which of the three outcomes it was before this returns.
pub fn commit_and_report(store: &mut Datastore, document: &[u8], sink: &dyn Sink) -> CommitReport {
    let staged = match store.stage(document) {
        Ok(staged) => staged,
        Err(error) => return refuse(store.running(), rejection(error), offset(error), sink),
    };
    // Before the commit, and from the model `stage` handed back: the image
    // carries the generation the commit is about to assign, and a model that
    // cannot become one must not move the configuration somewhere unpublishable.
    let image = match image_from(&staged.model, staged.generation) {
        Ok(image) => image,
        Err(error) => return refuse(store.running(), build_rejection(error), 0, sink),
    };

    // The change records are emitted as the commit produces them rather than
    // buffered and replayed: a generation is not a quantity of stack, and the
    // numbering is the walk's own so it cannot come to disagree with the order
    // the records went out in.
    let mut emitted = ChangeRecords {
        generation: staged.generation.to_bits(),
        sequence: 0,
        sink,
    };
    let outcome = match store.commit(&mut emitted) {
        Ok(outcome) => outcome,
        // Nothing about the configuration is wrong, so this has no reason token
        // — see `CommitError`'s own note on the two vocabularies.
        Err(_) => {
            sink.emit(&Event::ConfigGeneration {
                generation: store.running().to_bits(),
                outcome: GenerationOutcome::Refused,
                changes: 0,
            });
            return CommitReport::Exhausted;
        }
    };

    report_commit(outcome, image, sink)
}

/// What staging a document did.
///
/// Two outcomes and no third: a document either becomes the candidate or names
/// the rule it broke. There is no "unchanged" here — staging is not keyed by
/// content, because whether a candidate matches what is running is a question the
/// commit asks and answering it early would refuse a document an operator has
/// every right to stage and then commit alongside another change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageReport {
    /// The document is the candidate, and `generation` is the one committing it
    /// would assign.
    Staged { generation: u32 },
    /// The document broke a rule; nothing is staged from it and whatever was
    /// staged before is untouched.
    Rejected { reason: RejectReason, detail: u32 },
}

/// Read `document` and hold it as the candidate, committing nothing. `sink` is
/// told which of the two outcomes it was before this returns.
///
/// The same reader, the same rules and the same refusals as a one-step
/// submission: this exists so a caller that commits separately can be told what
/// validating produced, and not so a second set of rules can apply. A document
/// whose model cannot become a handover artifact is refused **here** rather than
/// at the commit, so a staging that succeeded is one a commit will not turn down
/// for a reason the operator was never told.
pub fn stage_and_report(store: &mut Datastore, document: &[u8], sink: &dyn Sink) -> StageReport {
    let staged = match store.stage(document) {
        Ok(staged) => staged,
        Err(error) => {
            let (reason, detail) = (rejection(error), offset(error));
            refuse(store.running(), reason, detail, sink);
            return StageReport::Rejected { reason, detail };
        }
    };
    if let Err(error) = image_from(&staged.model, staged.generation) {
        let reason = build_rejection(error);
        refuse(store.running(), reason, 0, sink);
        return StageReport::Rejected { reason, detail: 0 };
    }
    let generation = staged.generation.to_bits();
    sink.emit(&Event::ConfigGeneration {
        generation,
        outcome: GenerationOutcome::Staged,
        changes: 0,
    });
    StageReport::Staged { generation }
}

/// Commit the candidate provisionally, reporting it exactly as a one-step
/// submission is reported.
///
/// The image is rebuilt from the model the commit applied rather than from the
/// one staging held: a caller may have staged and committed across two requests,
/// and an image built at staging time would be an artifact for a generation the
/// commit may since have numbered differently.
pub fn commit_provisionally_and_report(store: &mut Datastore, sink: &dyn Sink) -> CommitReport {
    let Some(generation) = store.next_generation() else {
        sink.emit(&Event::ConfigGeneration {
            generation: store.running().to_bits(),
            outcome: GenerationOutcome::Refused,
            changes: 0,
        });
        return CommitReport::Exhausted;
    };
    let Some(model) = store.candidate_model() else {
        // Nothing staged. Reported as a refusal against the generation that
        // therefore stays running, with no reason token — nothing about a
        // configuration is wrong, there being no configuration.
        sink.emit(&Event::ConfigGeneration {
            generation: store.running().to_bits(),
            outcome: GenerationOutcome::Refused,
            changes: 0,
        });
        return CommitReport::NoCandidate;
    };
    // Before the commit, on `commit_and_report`'s terms: a model that cannot
    // become an artifact must not move the configuration somewhere unpublishable.
    let image = match image_from(&model, generation) {
        Ok(image) => image,
        Err(error) => return refuse(store.running(), build_rejection(error), 0, sink),
    };
    let mut emitted = ChangeRecords {
        generation: generation.to_bits(),
        sequence: 0,
        sink,
    };
    let outcome = match store.commit_provisionally(&mut emitted) {
        Ok(outcome) => outcome,
        // Unreachable: both of `CommitError`'s causes were decided above off the
        // same store. Answered rather than asserted, this running on a path a
        // peer paces.
        Err(_) => {
            sink.emit(&Event::ConfigGeneration {
                generation: store.running().to_bits(),
                outcome: GenerationOutcome::Refused,
                changes: 0,
            });
            return CommitReport::Exhausted;
        }
    };
    report_commit(outcome, image, sink)
}

/// What confirming or reverting a provisional commit did.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing needs an allocator; the value is a temporary destructured at once"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionalReport {
    /// The provisional commit is permanent under `generation`.
    Confirmed { generation: u32 },
    /// What the provisional commit displaced is in force again under
    /// `generation`, and this is the image the consumer is handed. `abandoned` is
    /// the generation given up.
    Reverted {
        image: ConfigImage,
        generation: u32,
        abandoned: u32,
        changes: u32,
    },
    /// Nothing was awaiting confirmation. `generation` is what stays running.
    NotProvisional { generation: u32 },
    /// A confirmation of a generation that is not the provisional one.
    /// `provisional` is the one that is, and it stays outstanding.
    GenerationMismatch { provisional: u32 },
}

/// Keep the provisional commit `generation` names, and say so.
pub fn confirm_and_report(
    store: &mut Datastore,
    generation: u32,
    sink: &dyn Sink,
) -> ProvisionalReport {
    match store.confirm(Generation::from_bits(generation)) {
        Ok(confirmed) => {
            let generation = confirmed.to_bits();
            sink.emit(&Event::ConfigGeneration {
                generation,
                outcome: GenerationOutcome::Confirmed,
                changes: 0,
            });
            ProvisionalReport::Confirmed { generation }
        }
        Err(ProvisionalError::NotProvisional) => {
            let generation = store.running().to_bits();
            sink.emit(&Event::ConfigGeneration {
                generation,
                outcome: GenerationOutcome::Refused,
                changes: 0,
            });
            ProvisionalReport::NotProvisional { generation }
        }
        Err(ProvisionalError::GenerationMismatch { provisional }) => {
            sink.emit(&Event::ConfigGeneration {
                generation: provisional.to_bits(),
                outcome: GenerationOutcome::Refused,
                changes: 0,
            });
            ProvisionalReport::GenerationMismatch {
                provisional: provisional.to_bits(),
            }
        }
        // A rollback's refusal, which a confirmation cannot reach: `confirm`
        // assigns no generation. Reported as the mismatch it amounts to rather
        // than asserted away, this running on a path a peer paces.
        Err(ProvisionalError::GenerationsExhausted { latest }) => {
            ProvisionalReport::GenerationMismatch {
                provisional: latest.to_bits(),
            }
        }
    }
}

/// Put back whatever the provisional commit displaced, and say so.
///
/// The image is built **before** the store is moved, exactly as a commit's is: a
/// restored configuration that could not become an artifact must not leave the
/// consumer running a generation nobody can publish.
pub fn revert_and_report(store: &mut Datastore, sink: &dyn Sink) -> ProvisionalReport {
    let running = store.running().to_bits();
    let Some(displaced) = store.displaced_model() else {
        sink.emit(&Event::ConfigGeneration {
            generation: running,
            outcome: GenerationOutcome::Refused,
            changes: 0,
        });
        return ProvisionalReport::NotProvisional {
            generation: running,
        };
    };
    let Some(generation) = store.next_generation() else {
        sink.emit(&Event::ConfigGeneration {
            generation: running,
            outcome: GenerationOutcome::Refused,
            changes: 0,
        });
        return ProvisionalReport::NotProvisional {
            generation: running,
        };
    };
    let image = match image_from(&displaced, generation) {
        Ok(image) => image,
        Err(error) => {
            refuse(store.running(), build_rejection(error), 0, sink);
            return ProvisionalReport::NotProvisional {
                generation: running,
            };
        }
    };
    let mut emitted = ChangeRecords {
        generation: generation.to_bits(),
        sequence: 0,
        sink,
    };
    match store.roll_back(&mut emitted) {
        Ok(rolled) => {
            let changes = saturating(rolled.changes);
            sink.emit(&Event::ConfigGeneration {
                generation: rolled.generation.to_bits(),
                outcome: GenerationOutcome::Reverted,
                changes,
            });
            ProvisionalReport::Reverted {
                image,
                generation: rolled.generation.to_bits(),
                abandoned: rolled.abandoned.to_bits(),
                changes,
            }
        }
        // Unreachable: both refusals were decided above, off the same store.
        // Answered rather than asserted, this running on a path a peer paces.
        Err(_) => ProvisionalReport::NotProvisional {
            generation: running,
        },
    }
}

/// Turn a commit's outcome into the report both commit paths answer with.
fn report_commit(outcome: CommitOutcome, image: ConfigImage, sink: &dyn Sink) -> CommitReport {
    let generation = outcome.generation().to_bits();
    match outcome {
        CommitOutcome::Unchanged { .. } => {
            sink.emit(&Event::ConfigGeneration {
                generation,
                outcome: GenerationOutcome::Unchanged,
                changes: 0,
            });
            CommitReport::Unchanged
        }
        CommitOutcome::Applied { changes, .. } => {
            let changes = saturating(changes);
            sink.emit(&Event::ConfigGeneration {
                generation,
                outcome: GenerationOutcome::Applied,
                changes,
            });
            CommitReport::Published { image, changes }
        }
    }
}

/// Every change a commit produces, numbered and emitted as it arrives.
///
/// The generation it stamps is the one the commit is about to assign, which is
/// known before the diff is walked; a commit that then refuses emits nothing,
/// because the diff is the last thing a commit does.
struct ChangeRecords<'sink> {
    generation: u32,
    sequence: u32,
    sink: &'sink dyn Sink,
}

impl Records for ChangeRecords<'_> {
    fn record(&mut self, change: Change) {
        self.sink.emit(&Event::ConfigChange {
            generation: self.generation,
            sequence: self.sequence,
            change: change.kind,
            object: change.object,
            key: change.key,
            field: change.field,
            from: change.from,
            to: change.to,
        });
        self.sequence = self.sequence.saturating_add(1);
    }
}

/// Record a refusal against the generation that therefore stays running.
fn refuse(running: Generation, reason: RejectReason, offset: u32, sink: &dyn Sink) -> CommitReport {
    sink.emit(&Event::ConfigRejected {
        generation: running.to_bits(),
        reason,
        offset,
    });
    CommitReport::Rejected {
        reason,
        detail: offset,
    }
}

const fn rejection(error: ConfigError) -> RejectReason {
    error.reason()
}

/// Where in the document the refusal was, for the half of them that have a
/// position. A semantic refusal names an object rather than a byte, and
/// reporting zero for it would point at the XML declaration.
const fn offset(error: ConfigError) -> u32 {
    match error {
        ConfigError::Document(fault) => fault.offset,
        ConfigError::Semantic(_) => 0,
    }
}

/// A validated model that will not become an artifact is still a document the
/// operator has to fix, so it is reported in the document's vocabulary.
const fn build_rejection(error: BuildError) -> RejectReason {
    match error {
        BuildError::UnresolvedInterface { .. } | BuildError::UnresolvedRuleInterface { .. } => {
            RejectReason::UnknownInterfaceReference
        }
    }
}

const fn saturating(count: usize) -> u32 {
    if count > u32::MAX as usize {
        u32::MAX
    } else {
        count as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lfw_log::{ChangeKind, Field, ObjectKind, RecordingSink, Value};
    use std::{format, string::String, vec::Vec};

    /// A document naming no object at all — every section present and empty,
    /// which is what generation 0 already is.
    const EMPTY: &str = concat!(
        "<configuration><interfaces/><neighbours/><rules/>",
        "<management enabled=\"false\" mac=\"52:54:00:12:34:52\" ",
        "address=\"192.168.42.15\" prefix-length=\"24\" gateway=\"none\"/>",
        "</configuration>"
    );

    /// Room for every record a commit from generation 0 can produce: every
    /// object the image holds, the one management interface included.
    const CAPACITY: usize = (wire::MAX_INTERFACES + wire::MAX_NEIGHBOURS + 1) * Field::ALL.len();

    const ONE_PORT: &str = concat!(
        "<configuration><interfaces>",
        "<interface id=\"wan\" port=\"0\" enabled=\"true\" mac=\"52:54:00:12:34:50\" ",
        "address=\"10.0.0.1\" prefix-length=\"24\"/>",
        "</interfaces><neighbours>",
        "<neighbour id=\"gw\" interface=\"wan\" address=\"10.0.0.2\" mac=\"52:54:00:00:00:0a\"/>",
        "</neighbours><rules/>",
        "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" prefix-length=\"24\" gateway=\"none\"/>",
        "</configuration>"
    );

    fn run(document: &str) -> (CommitReport, Vec<Event>) {
        let mut store = Datastore::new();
        run_on(&mut store, document)
    }

    fn run_on(store: &mut Datastore, document: &str) -> (CommitReport, Vec<Event>) {
        let sink = RecordingSink::<CAPACITY>::new();
        let report = commit_and_report(store, document.as_bytes(), &sink);
        assert_eq!(sink.dropped(), 0, "the fixture sink overran");
        let events = (0..sink.len())
            .map(|index| sink.get(index).expect("in range"))
            .collect();
        (report, events)
    }

    /// The channel's four steps against one store, each with its own sink so the
    /// records of one step cannot be read as another's.
    fn steps(store: &mut Datastore, document: &str) -> (StageReport, Vec<Event>) {
        let sink = RecordingSink::<CAPACITY>::new();
        let report = stage_and_report(store, document.as_bytes(), &sink);
        assert_eq!(sink.dropped(), 0, "the fixture sink overran");
        let events = (0..sink.len())
            .map(|index| sink.get(index).expect("in range"))
            .collect();
        (report, events)
    }

    fn committed(store: &mut Datastore) -> (CommitReport, Vec<Event>) {
        let sink = RecordingSink::<CAPACITY>::new();
        let report = commit_provisionally_and_report(store, &sink);
        assert_eq!(sink.dropped(), 0, "the fixture sink overran");
        let events = (0..sink.len())
            .map(|index| sink.get(index).expect("in range"))
            .collect();
        (report, events)
    }

    fn settled(store: &mut Datastore, confirm: Option<u32>) -> (ProvisionalReport, Vec<Event>) {
        let sink = RecordingSink::<CAPACITY>::new();
        let report = match confirm {
            Some(generation) => confirm_and_report(store, generation, &sink),
            None => revert_and_report(store, &sink),
        };
        assert_eq!(sink.dropped(), 0, "the fixture sink overran");
        let events = (0..sink.len())
            .map(|index| sink.get(index).expect("in range"))
            .collect();
        (report, events)
    }

    #[test]
    fn staging_holds_the_document_and_moves_nothing() {
        let mut store = Datastore::new();
        let (report, events) = steps(&mut store, ONE_PORT);

        assert_eq!(report, StageReport::Staged { generation: 1 });
        assert_eq!(
            events,
            [Event::ConfigGeneration {
                generation: 1,
                outcome: GenerationOutcome::Staged,
                changes: 0,
            }]
        );
        // Nothing is running from it, which is the whole point of a staging.
        assert_eq!(store.running(), Generation::ZERO);
    }

    #[test]
    fn staging_refuses_a_document_by_the_same_rules_a_submission_does() {
        let mut store = Datastore::new();
        let (report, events) = steps(&mut store, "<!DOCTYPE x><configuration/>");

        assert_eq!(
            report,
            StageReport::Rejected {
                reason: RejectReason::Doctype,
                detail: 0,
            }
        );
        // One record, naming the rule and where: a refused staging says the same
        // thing a refused submission does, in the same vocabulary.
        assert_eq!(
            events,
            [Event::ConfigRejected {
                generation: 0,
                reason: RejectReason::Doctype,
                offset: 0,
            }]
        );
    }

    #[test]
    fn the_four_steps_apply_a_generation_and_then_confirm_it() {
        let mut store = Datastore::new();
        assert_eq!(
            steps(&mut store, ONE_PORT).0,
            StageReport::Staged { generation: 1 }
        );
        let (report, _) = committed(&mut store);
        let image = report.image().expect("a staged candidate publishes");
        assert_eq!(image.generation, 1);
        assert_eq!(store.provisional(), Some(Generation::from_bits(1)));

        let (settled, events) = settled(&mut store, Some(1));
        assert_eq!(settled, ProvisionalReport::Confirmed { generation: 1 });
        assert_eq!(
            events,
            [Event::ConfigGeneration {
                generation: 1,
                outcome: GenerationOutcome::Confirmed,
                changes: 0,
            }]
        );
        assert_eq!(store.provisional(), None);
    }

    #[test]
    fn an_unconfirmed_generation_is_reverted_and_the_image_is_the_one_put_back() {
        let mut store = Datastore::new();
        steps(&mut store, ONE_PORT);
        committed(&mut store);
        steps(&mut store, EMPTY);
        let (report, _) = committed(&mut store);
        assert_eq!(report.generation(), 2);

        let (settled, events) = settled(&mut store, None);
        let ProvisionalReport::Reverted {
            image,
            generation,
            abandoned,
            changes,
        } = settled
        else {
            panic!("a provisional commit reverts: {settled:?}");
        };
        // A new generation carrying the OLD configuration: one interface again.
        assert_eq!(generation, 3);
        assert_eq!(abandoned, 2);
        assert_eq!(image.generation, 3);
        assert_eq!(image.interface_count, 1);
        assert!(changes > 0);
        assert!(matches!(
            events.last(),
            Some(Event::ConfigGeneration {
                generation: 3,
                outcome: GenerationOutcome::Reverted,
                ..
            })
        ));
    }

    #[test]
    fn a_commit_with_nothing_staged_is_told_apart_from_an_exhausted_counter() {
        let mut store = Datastore::new();
        let (report, events) = committed(&mut store);

        assert_eq!(report, CommitReport::NoCandidate);
        assert_eq!(report.image(), None);
        assert_eq!(report.generation(), 0);
        assert_eq!(report.state(), DomainState::Refused);
        assert!(matches!(
            events.first(),
            Some(Event::ConfigGeneration {
                outcome: GenerationOutcome::Refused,
                ..
            })
        ));
    }

    #[test]
    fn confirming_and_reverting_nothing_are_told_apart_by_their_own_report() {
        let mut store = Datastore::new();
        steps(&mut store, ONE_PORT);
        committed(&mut store);
        settled(&mut store, Some(1));

        assert_eq!(
            settled(&mut store, Some(1)).0,
            ProvisionalReport::NotProvisional { generation: 1 }
        );
        assert_eq!(
            settled(&mut store, None).0,
            ProvisionalReport::NotProvisional { generation: 1 }
        );
    }

    #[test]
    fn a_confirmation_of_another_generation_names_the_one_outstanding() {
        let mut store = Datastore::new();
        steps(&mut store, ONE_PORT);
        committed(&mut store);

        assert_eq!(
            settled(&mut store, Some(7)).0,
            ProvisionalReport::GenerationMismatch { provisional: 1 }
        );
        // Still outstanding, so the deadline still reverts it.
        assert!(matches!(
            settled(&mut store, None).0,
            ProvisionalReport::Reverted { abandoned: 1, .. }
        ));
    }

    #[test]
    fn a_first_commit_publishes_an_image_and_reports_every_value_it_added() {
        let (report, events) = run(ONE_PORT);
        let image = report.image().expect("a valid document is published");
        assert_eq!(image.generation, 1);
        assert_eq!(image.interface_count, 1);
        assert_eq!(image.neighbour_count, 1);

        let (summary, records) = events.split_last().expect("at least the summary");
        assert!(!records.is_empty(), "an added configuration moved nothing");
        for (position, record) in records.iter().enumerate() {
            match record {
                Event::ConfigChange {
                    generation,
                    sequence,
                    change,
                    from,
                    ..
                } => {
                    assert_eq!(*generation, 1);
                    assert_eq!(*sequence as usize, position, "records are not in order");
                    assert_eq!(*change, ChangeKind::Added);
                    assert_eq!(*from, None, "an addition came from nothing");
                }
                other => panic!("{other:?} is not a change record"),
            }
        }
        assert_eq!(
            *summary,
            Event::ConfigGeneration {
                generation: 1,
                outcome: GenerationOutcome::Applied,
                changes: records.len() as u32,
            }
        );
    }

    #[test]
    fn every_object_the_document_names_reaches_the_record_by_its_own_id() {
        let (_, events) = run(ONE_PORT);
        let mut keys: Vec<(ObjectKind, String)> = events
            .iter()
            .filter_map(|event| match event {
                Event::ConfigChange { object, key, .. } => {
                    Some((*object, String::from(key.as_str())))
                }
                _ => None,
            })
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(
            keys,
            [
                (ObjectKind::Interface, String::from("wan")),
                (ObjectKind::Neighbour, String::from("gw")),
                (ObjectKind::Management, String::from("management")),
            ]
        );
    }

    /// The whole point of the domain: a document nobody can read publishes
    /// nothing at all, so the consumer stays on the generation that forwards
    /// nothing.
    #[test]
    fn a_refused_document_publishes_nothing_and_names_where_it_broke() {
        let (report, events) = run("<?xml version=\"1.0\"?><!DOCTYPE evil><configuration/>");
        assert_eq!(
            report,
            CommitReport::Rejected {
                reason: RejectReason::Doctype,
                detail: 21,
            }
        );
        assert_eq!(events.len(), 1, "a refusal is one record");
        match events[0] {
            Event::ConfigRejected {
                generation,
                reason,
                offset,
            } => {
                assert_eq!(generation, 0, "nothing was assigned");
                assert_eq!(reason, RejectReason::Doctype);
                assert_eq!(offset, 21, "the position of the doctype, not the start");
            }
            ref other => panic!("{other:?} is not a rejection"),
        }
    }

    #[test]
    fn a_semantically_refused_document_reports_its_rule_and_no_position() {
        let dangling = ONE_PORT.replacen("interface=\"wan\"", "interface=\"dmz\"", 1);
        let (report, events) = run(&dangling);
        assert_eq!(
            report,
            CommitReport::Rejected {
                reason: RejectReason::UnknownInterfaceReference,
                detail: 0,
            }
        );
        assert_eq!(
            events,
            [Event::ConfigRejected {
                generation: 0,
                reason: RejectReason::UnknownInterfaceReference,
                offset: 0,
            }]
        );
    }

    #[test]
    fn every_way_a_document_can_be_refused_leaves_the_running_generation_alone() {
        let cases = [
            ("<configuration>", RejectReason::Malformed),
            ("<!DOCTYPE x><configuration/>", RejectReason::Doctype),
            (
                "<configuration><interfaces/><neighbours/><rules/><management enabled=\"true\" mac=\"52:54:00:12:34:52\" address=\"192.168.42.15\" prefix-length=\"24\" gateway=\"none\"/><extra/></configuration>",
                RejectReason::UnknownElement,
            ),
        ];
        for (document, reason) in cases {
            let mut store = Datastore::new();
            let (first, _) = run_on(&mut store, ONE_PORT);
            assert!(first.image().is_some());
            let running = store.running();

            let (report, events) = run_on(&mut store, document);
            assert_eq!(
                report,
                CommitReport::Rejected {
                    reason,
                    detail: match report {
                        CommitReport::Rejected { detail, .. } => detail,
                        ref other => panic!("{other:?} published something for {document}"),
                    },
                },
                "{document} published something"
            );
            assert_eq!(store.running(), running, "{document} moved the generation");
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    Event::ConfigRejected { reason: seen, generation, .. }
                        if *seen == reason && *generation == running.to_bits()
                )),
                "{document} reported {events:?}"
            );
        }
    }

    #[test]
    fn re_committing_the_running_content_publishes_nothing_and_says_unchanged() {
        let mut store = Datastore::new();
        let (first, _) = run_on(&mut store, ONE_PORT);
        assert!(first.image().is_some());

        // Reformatted, not rewritten: the hash is over the model, so this is
        // the same configuration written differently.
        let reformatted = ONE_PORT.replace("><", ">\n  <");
        let (report, events) = run_on(&mut store, &reformatted);
        assert_eq!(report, CommitReport::Unchanged);
        assert_eq!(
            events,
            [Event::ConfigGeneration {
                generation: 1,
                outcome: GenerationOutcome::Unchanged,
                changes: 0,
            }]
        );
        assert_eq!(store.running().to_bits(), 1);
    }

    /// The reachable one, and the reason the three outcomes are three: a
    /// document whose content is already running assigns nothing and refuses
    /// nothing.
    ///
    /// It takes a *second* commit of one document to reach, and no first commit
    /// can: the schema requires a `<management>` element, so every document a
    /// reader accepts names at least that object and therefore moves the
    /// configuration off the empty generation 0.
    #[test]
    fn a_document_already_running_commits_as_unchanged() {
        let mut store = Datastore::new();
        let (first, _) = run_on(&mut store, EMPTY);
        assert!(
            matches!(first, CommitReport::Published { .. }),
            "a disabled management port is still something a document says"
        );

        let (report, events) = run_on(&mut store, EMPTY);
        assert_eq!(report, CommitReport::Unchanged);
        assert_eq!(
            events,
            [Event::ConfigGeneration {
                generation: 1,
                outcome: GenerationOutcome::Unchanged,
                changes: 0,
            }]
        );
    }

    /// What each outcome tells the domain to announce, which is the whole of
    /// the decision a protection domain used to be making for itself. A commit
    /// that assigned nothing is not a refusal: the configuration in force is
    /// the one the document names, and the `LFW-CFG` record immediately before
    /// is what distinguishes it from a commit that moved something.
    #[test]
    fn each_outcome_announces_the_state_it_actually_is() {
        let published = run(ONE_PORT).0;
        assert!(matches!(published, CommitReport::Published { .. }));
        assert_eq!(published.state(), DomainState::Ready);

        let mut store = Datastore::new();
        run_on(&mut store, EMPTY);
        let unchanged = run_on(&mut store, EMPTY).0;
        assert_eq!(unchanged, CommitReport::Unchanged);
        assert_eq!(unchanged.state(), DomainState::Ready);
        assert_eq!(unchanged.image(), None, "there is nothing to publish");

        let refused = run("<!DOCTYPE x><configuration/>").0;
        assert_eq!(
            refused,
            CommitReport::Rejected {
                reason: RejectReason::Doctype,
                detail: 0,
            }
        );
        assert_eq!(refused.state(), DomainState::Refused);
        assert_eq!(refused.image(), None);
        assert_eq!(refused.generation(), 0);
        // The other refusal, whose vocabulary has no reason token at all: it is
        // still a refusal, still publishes nothing, and still leaves the domain
        // announcing the state it is in.
        assert_eq!(CommitReport::Exhausted.state(), DomainState::Refused);
        assert_eq!(CommitReport::Exhausted.image(), None);
        assert_eq!(CommitReport::Exhausted.generation(), 0);
    }

    #[test]
    fn a_second_commit_reports_only_the_values_that_moved() {
        let mut store = Datastore::new();
        run_on(&mut store, ONE_PORT);
        let changed = ONE_PORT.replacen("prefix-length=\"24\"", "prefix-length=\"25\"", 1);
        let (report, events) = run_on(&mut store, &changed);

        assert_eq!(report.image().expect("published").generation, 2);
        assert_eq!(
            events,
            [
                Event::ConfigChange {
                    generation: 2,
                    sequence: 0,
                    change: ChangeKind::Modified,
                    object: ObjectKind::Interface,
                    key: crate::Identifier::new(b"wan").expect("within the alphabet"),
                    field: Field::PrefixLength,
                    from: Some(Value::PrefixLength(24)),
                    to: Some(Value::PrefixLength(25)),
                },
                Event::ConfigGeneration {
                    generation: 2,
                    outcome: GenerationOutcome::Applied,
                    changes: 1,
                },
            ]
        );
    }

    /// The summary counts the records the commit emitted, and the records the
    /// commit emitted all carry the generation the summary names. Nothing
    /// between the diff and the sink can lose one or renumber one, so the two
    /// halves of a commit's account of itself are held to each other here.
    #[test]
    fn every_change_record_carries_the_generation_the_summary_reports() {
        let (report, events) = run(ONE_PORT);
        assert!(report.image().is_some());

        let Some(Event::ConfigGeneration {
            generation,
            outcome: GenerationOutcome::Applied,
            changes,
        }) = events.last().copied()
        else {
            panic!("a summary is always last: {events:?}");
        };
        assert_eq!(changes as usize, events.len() - 1);

        for (expected, event) in events.iter().take(events.len() - 1).enumerate() {
            match event {
                Event::ConfigChange {
                    generation: stamped,
                    sequence,
                    ..
                } => {
                    assert_eq!(*stamped, generation, "{event:?}");
                    assert_eq!(*sequence as usize, expected, "{event:?}");
                }
                other => panic!("{other:?} is not a change record"),
            }
        }
    }

    #[test]
    fn a_count_past_a_records_width_is_saturated_rather_than_wrapped() {
        assert_eq!(saturating(0), 0);
        assert_eq!(saturating(7), 7);
        assert_eq!(saturating(u32::MAX as usize), u32::MAX);
        assert_eq!(saturating(u32::MAX as usize + 1), u32::MAX);
    }

    #[test]
    fn a_model_that_cannot_become_an_artifact_is_reported_in_the_documents_words() {
        assert_eq!(
            build_rejection(BuildError::UnresolvedInterface {
                neighbour: crate::Identifier::new(b"gw").expect("within the alphabet"),
                interface: crate::Identifier::new(b"dmz").expect("within the alphabet"),
            }),
            RejectReason::UnknownInterfaceReference
        );
    }

    #[test]
    fn the_document_the_appliance_ships_with_commits_and_publishes() {
        // The real file, so a change to it that this domain could not commit
        // fails here rather than at boot with no console to read.
        let document = include_bytes!("../../../systems/qemu-x86_64/configuration.xml");
        let mut store = Datastore::new();
        let sink = RecordingSink::<CAPACITY>::new();
        let image = commit_and_report(&mut store, document, &sink)
            .image()
            .expect("the shipped configuration must commit");
        assert_eq!(image.generation, 1);
        assert_eq!(image.interface_count, 2);
        assert_eq!(image.neighbour_count, 2);
        assert_eq!(sink.dropped(), 0, "{CAPACITY} records is not enough room");
        assert_eq!(
            sink.get(sink.len() - 1),
            Some(Event::ConfigGeneration {
                generation: 1,
                outcome: GenerationOutcome::Applied,
                changes: (sink.len() - 1) as u32,
            })
        );
        // What the consumer is held to, checked from the side that writes it.
        assert!(image.check(crate::PORT_COUNT).is_ok());
    }

    #[test]
    fn a_rejection_reports_the_position_only_where_one_means_anything() {
        let document = crate::parse(b"<configuration><!DOCTYPE x>").expect_err("a doctype");
        assert!(offset(ConfigError::Document(document)) > 0);
        assert_eq!(
            rejection(ConfigError::Document(document)),
            document.reason()
        );

        let semantic = crate::load(
            format!("{}{}", ONE_PORT.replacen("port=\"0\"", "port=\"7\"", 1), "").as_bytes(),
        )
        .expect_err("port 7 is not on this build");
        assert_eq!(offset(semantic), 0);
        assert_eq!(rejection(semantic), RejectReason::PortOutOfRange);
    }
}
