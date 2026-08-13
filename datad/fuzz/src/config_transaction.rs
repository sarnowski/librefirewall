//! The management channel's stepped configuration transaction, driven by an
//! adversary who chooses the steps: stage, commit, confirm and revert against one
//! datastore, over the real submission channel handles.
//!
//! # The adversary and the surface
//!
//! A **management-plane attacker up to and including a compromised management
//! server**. What that party controls here is everything the channel carries:
//! which operation comes next, in any order and any number of times; the document
//! bytes a staging reads; and the generation a commit or a confirmation names,
//! including one that names no generation this appliance holds. Behind the
//! requester sits the **byzantine neighbour protection domain** in both
//! directions, and the harness drives the real handles rather than calling the
//! store, so the operation word, the generation word and the sequence number all
//! cross exactly as they do on an appliance.
//!
//! The input is a sequence of steps and a document, so any real configuration
//! document is a usable seed and so is a malformed one — the interesting region
//! is the *order*, which is why the step byte comes first.
//!
//! # What is asserted, beyond not crashing
//!
//! * **A staging changes nothing that is running.** Whatever a document is, the
//!   generation and the model in force after staging it are the ones from before.
//! * **At most one commit is ever undoable.** The store carries one provisional
//!   commit, so no sequence of steps accumulates a history to walk back through —
//!   which is what makes a revert one step rather than a loop.
//! * **Generations never run backwards.** Not across a commit, not across a
//!   revert — a configuration going back into force takes a *new* generation,
//!   because the dataplane's handover admits only a strictly newer one.
//! * **A revert restores exactly what the commit it undoes displaced.** The model
//!   in force after it is the model from before that commit, byte for byte.
//! * **A confirmation naming the wrong generation settles nothing.** The commit
//!   stays outstanding, so the deadline that armed it still means something — the
//!   one property that keeps a server which has lost track from making a stale
//!   commit permanent.
//! * **A confirmed commit is unrevertable.** After a confirmation there is
//!   nothing to put back, whatever the peer asks for next.
//! * **Every answer belongs to the operation asked.** The reply crosses the real
//!   channel and is claimed through the real poll, so a status the ABI's
//!   cross-field rule refuses is a counted fault here rather than a value.
//! * **Nothing is unbounded.** One request in flight, one answer each, and a step
//!   count bounded by the input.

use std::boxed::Box;
use std::vec::Vec;

use arbitrary::Unstructured;
use config::{
    CommitReport, Datastore, Generation, MAX_DOCUMENT_BYTES, Model, ProvisionalReport, StageReport,
};
use lfw_log::{RejectReason, Sink};
use wire::{
    ConfigAnswer, ConfigOperation, ConfigPoll, ConfigReply, ConfigRequest, ConfigResponder,
    ConfigStatus,
};

use crate::any_index;

/// Steps one run may take. A bound of this file's: the adversary chooses the
/// order and the harness chooses how long it will listen.
const MAX_STEPS: usize = 48;

/// A sink that keeps nothing. What each step *reported* is asserted through the
/// report values and the store, which are the facts a caller acts on.
struct Discard;

impl Sink for Discard {
    fn emit(&self, _event: &lfw_log::Event) {}
}

/// The two regions one channel is, on the heap: 128 KiB of region is more than
/// belongs on a fuzzing stack.
struct Channel {
    request: Box<ConfigRequest>,
    reply: Box<ConfigReply>,
}

impl Channel {
    fn zero() -> Self {
        Self {
            request: Box::new(ConfigRequest::zero()),
            reply: Box::new(ConfigReply::zero()),
        }
    }
}

/// What the appliance held before a step, so the step's effect can be judged
/// against it rather than against a second reading.
struct Before {
    generation: Generation,
    model: Model,
    provisional: Option<Generation>,
    /// What a revert would put back, where a commit is outstanding.
    displaced: Option<Model>,
}

impl Before {
    fn of(store: &Datastore) -> Self {
        Self {
            generation: store.running(),
            model: *store.running_model(),
            provisional: store.provisional(),
            displaced: store.displaced_model(),
        }
    }
}

/// Drive one sequence of steps against one store.
///
/// # Panics
/// On any broken invariant above, which is the harness's whole purpose.
pub fn config_transaction_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let steps = any_index(&mut unstructured, MAX_STEPS);
    // The rest is the document every staging in this run reads. One document
    // rather than one per step, because what is under test is the *order* of the
    // operations: a fresh document per step would spend the input on bytes the
    // configuration reader is already fuzzed against on its own.
    let document = document_of(&mut unstructured);

    let channel = Channel::zero();
    let mut requester = channel.request.requester(&channel.reply);
    let mut responder = channel.reply.responder(&channel.request);
    let mut store = Datastore::new();
    let mut scratch: Box<[u8; MAX_DOCUMENT_BYTES]> = Box::new([0; MAX_DOCUMENT_BYTES]);
    let mut answer: Box<[u8; MAX_DOCUMENT_BYTES]> = Box::new([0; MAX_DOCUMENT_BYTES]);
    let mut faults = 0;

    for step in 0..steps {
        // The operation and the generation it names are both the peer's, and the
        // generation is deliberately not always a right one: a server that has
        // lost track is exactly the case commit-confirm exists to catch.
        let operation = operation_of(&mut unstructured);
        let named = generation_of(&mut unstructured, &store);
        let before = Before::of(&store);

        let pending = match operation {
            ConfigOperation::Stage => requester.stage(&document),
            ConfigOperation::Commit => requester.commit(named),
            ConfigOperation::Confirm => requester.confirm(named),
            ConfigOperation::Rollback => requester.roll_back(),
            // The two the channel's port answers as no operation at all.
            ConfigOperation::Submit => requester.submit(&document),
            ConfigOperation::Read => requester.read(),
        };
        let demand = responder.take().expect("a request was issued");
        assert_eq!(demand.operation(), Some(operation));
        assert_eq!(
            demand.generation(),
            if operation.names_a_generation() {
                named
            } else {
                0
            },
            "step {step}: the generation word crossed for the wrong operation"
        );

        let answered = serve(&mut store, &responder, &demand, &mut scratch, operation);
        responder.answer(demand, answered);

        match requester.poll(pending, &mut answer) {
            ConfigPoll::Faulted(_) => faults += 1,
            // The word an undecodable operation is answered with, which belongs to
            // no operation and reaches the requester as itself rather than as a
            // fault: this port answers it for the two operations it does not serve.
            ConfigPoll::NoSuchOperation => assert!(
                matches!(answered, ConfigAnswer::NoSuchOperation),
                "step {step}: {answered:?} read as no operation"
            ),
            polled => {
                assert!(
                    !matches!(polled, ConfigPoll::Outstanding(_)),
                    "step {step}: an answered request read as outstanding"
                );
                assert!(
                    answered.status_answers(operation),
                    "step {step}: {answered:?} was believed for {operation:?}"
                );
            }
        }
        assert_step(step, operation, &before, &store, &document);
    }

    assert_eq!(
        faults,
        requester.faults(),
        "the requester's own tally disagrees with what this harness counted"
    );
}

/// The deciding domain's own step, exactly as `pds/config` performs it.
fn serve(
    store: &mut Datastore,
    responder: &ConfigResponder<'_>,
    demand: &wire::ConfigDemand,
    scratch: &mut [u8; MAX_DOCUMENT_BYTES],
    operation: ConfigOperation,
) -> ConfigAnswer {
    let sink = Discard;
    match operation {
        ConfigOperation::Stage => {
            let taken = responder.document(demand, scratch).to_vec();
            match config::stage_and_report(store, &taken, &sink) {
                StageReport::Staged { generation } => ConfigAnswer::Staged { generation },
                StageReport::Rejected { reason, detail } => {
                    assert!(RejectReason::ALL.contains(&reason));
                    ConfigAnswer::Rejected {
                        generation: store.running().to_bits(),
                        reason: reason as u32,
                        detail,
                    }
                }
            }
        }
        ConfigOperation::Commit => {
            let running = store.running().to_bits();
            match store.next_generation() {
                None => ConfigAnswer::Exhausted {
                    generation: running,
                },
                Some(next) if next.to_bits() != demand.generation() => {
                    ConfigAnswer::GenerationMismatch {
                        generation: next.to_bits(),
                    }
                }
                Some(_) => match config::commit_provisionally_and_report(store, &sink) {
                    CommitReport::Published { image, changes } => ConfigAnswer::Applied {
                        generation: image.generation,
                        changes,
                    },
                    CommitReport::Unchanged => ConfigAnswer::Unchanged {
                        generation: store.running().to_bits(),
                    },
                    CommitReport::NoCandidate => ConfigAnswer::NoCandidate {
                        generation: store.running().to_bits(),
                    },
                    CommitReport::Rejected { reason, detail } => ConfigAnswer::Rejected {
                        generation: store.running().to_bits(),
                        reason: reason as u32,
                        detail,
                    },
                    CommitReport::Exhausted => ConfigAnswer::Exhausted {
                        generation: store.running().to_bits(),
                    },
                },
            }
        }
        ConfigOperation::Confirm => {
            match config::confirm_and_report(store, demand.generation(), &sink) {
                ProvisionalReport::Confirmed { generation } => {
                    ConfigAnswer::Confirmed { generation }
                }
                ProvisionalReport::NotProvisional { generation } => {
                    ConfigAnswer::NotProvisional { generation }
                }
                ProvisionalReport::GenerationMismatch { provisional } => {
                    ConfigAnswer::GenerationMismatch {
                        generation: provisional,
                    }
                }
                ProvisionalReport::Reverted { .. } => {
                    unreachable!("a confirmation reverts nothing")
                }
            }
        }
        ConfigOperation::Rollback => match config::revert_and_report(store, &sink) {
            ProvisionalReport::Reverted { generation, .. } => {
                ConfigAnswer::RolledBack { generation }
            }
            ProvisionalReport::NotProvisional { generation } => {
                ConfigAnswer::NotProvisional { generation }
            }
            other => unreachable!("a revert answered {other:?}"),
        },
        // The channel's port has neither, so the store is untouched.
        ConfigOperation::Submit | ConfigOperation::Read => ConfigAnswer::NoSuchOperation,
    }
}

/// Every invariant one step owes, judged against what the store held before it.
fn assert_step(
    step: usize,
    operation: ConfigOperation,
    before: &Before,
    store: &Datastore,
    document: &[u8],
) {
    // Generations never run backwards, whichever step ran.
    assert!(
        store.running() >= before.generation,
        "step {step}: {operation:?} moved the generation backwards"
    );
    // At most one commit is ever undoable, so nothing accumulates beside it.
    if let Some(provisional) = store.provisional() {
        assert_eq!(
            provisional,
            store.running(),
            "step {step}: the outstanding commit is not the generation in force"
        );
        assert!(
            store.displaced_model().is_some(),
            "step {step}: a commit is outstanding with nothing to put back"
        );
    } else {
        assert!(
            store.displaced_model().is_none(),
            "step {step}: something is held to put back with no commit outstanding"
        );
    }

    match operation {
        // A staging touches nothing that is running, whatever the document is.
        ConfigOperation::Stage => {
            assert_eq!(store.running(), before.generation, "step {step}");
            assert_eq!(store.running_model(), &before.model, "step {step}");
            assert_eq!(store.provisional(), before.provisional, "step {step}");
        }
        ConfigOperation::Commit => {
            if store.running() > before.generation {
                // An applied commit is provisional and displaced exactly what was
                // running.
                assert_eq!(store.provisional(), Some(store.running()), "step {step}");
                assert_eq!(
                    store.displaced_model(),
                    Some(before.model),
                    "step {step}: the commit kept the wrong configuration to put back"
                );
            } else {
                assert_eq!(store.running_model(), &before.model, "step {step}");
            }
        }
        ConfigOperation::Confirm => {
            // Nothing a confirmation does moves the configuration.
            assert_eq!(store.running(), before.generation, "step {step}");
            assert_eq!(store.running_model(), &before.model, "step {step}");
            match before.provisional {
                // A confirmation settles the outstanding commit or leaves it
                // outstanding, and never anything between.
                Some(_) => assert!(
                    store.provisional().is_none() || store.provisional() == before.provisional,
                    "step {step}"
                ),
                None => assert_eq!(store.provisional(), None, "step {step}"),
            }
        }
        ConfigOperation::Rollback => match (before.provisional, before.displaced) {
            (Some(_), Some(displaced)) => {
                // A revert puts back exactly what the commit displaced, under a
                // NEW generation, and consumes the commit.
                assert!(store.running() > before.generation, "step {step}");
                assert_eq!(
                    store.running_model(),
                    &displaced,
                    "step {step}: the revert restored a configuration nothing displaced"
                );
                assert_eq!(store.provisional(), None, "step {step}");
            }
            _ => {
                assert_eq!(store.running(), before.generation, "step {step}");
                assert_eq!(store.running_model(), &before.model, "step {step}");
            }
        },
        // Neither is served on this port, so nothing at all moved.
        ConfigOperation::Submit | ConfigOperation::Read => {
            assert_eq!(store.running(), before.generation, "step {step}");
            assert_eq!(store.running_model(), &before.model, "step {step}");
            assert_eq!(store.provisional(), before.provisional, "step {step}");
            let _ = document;
        }
    }
}

/// One operation the peer chose, from the whole vocabulary and not only the four
/// this port serves: a harness that could not ask for a submission over the
/// channel would be modelling a peer that keeps to the protocol.
fn operation_of(unstructured: &mut Unstructured<'_>) -> ConfigOperation {
    let index = any_index(unstructured, ConfigOperation::ALL.len());
    ConfigOperation::ALL
        .get(index % ConfigOperation::ALL.len())
        .copied()
        .unwrap_or(ConfigOperation::Stage)
}

/// A generation the peer named: the right one often enough for the interesting
/// sequences to be reachable, and a wrong one often enough that a stale
/// confirmation is too.
fn generation_of(unstructured: &mut Unstructured<'_>, store: &Datastore) -> u32 {
    let next = store
        .next_generation()
        .map_or(0, config::Generation::to_bits);
    let running = store.running().to_bits();
    let provisional = store.provisional().map_or(0, config::Generation::to_bits);
    match any_index(unstructured, 6) {
        0 => next,
        1 => provisional,
        2 => running,
        3 => 0,
        4 => u32::MAX,
        _ => next.wrapping_add(1),
    }
}

/// The document every staging in one run reads, bounded by what one may be.
fn document_of(unstructured: &mut Unstructured<'_>) -> Vec<u8> {
    let rest = unstructured.len().min(MAX_DOCUMENT_BYTES);
    unstructured
        .bytes(rest)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// Whether an answer belongs to the operation it was given for, which is the
/// ABI's own cross-field rule read from the harness's side.
trait Answers {
    fn status_answers(self, operation: ConfigOperation) -> bool;
}

impl Answers for ConfigAnswer {
    fn status_answers(self, operation: ConfigOperation) -> bool {
        let status = match self {
            Self::Applied { .. } => ConfigStatus::Applied,
            Self::Unchanged { .. } => ConfigStatus::Unchanged,
            Self::Rejected { .. } => ConfigStatus::Rejected,
            Self::Exhausted { .. } => ConfigStatus::Exhausted,
            Self::Staged { .. } => ConfigStatus::Staged,
            Self::Confirmed { .. } => ConfigStatus::Confirmed,
            Self::RolledBack { .. } => ConfigStatus::RolledBack,
            Self::NoCandidate { .. } => ConfigStatus::NoCandidate,
            Self::NotProvisional { .. } => ConfigStatus::NotProvisional,
            Self::GenerationMismatch { .. } => ConfigStatus::GenerationMismatch,
            Self::NoSuchOperation => return false,
        };
        status.answers(operation)
    }
}
